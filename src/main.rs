use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use hostip::cert::{self, CertStore};
use hostip::config::{FileConfig, Mode, PortSpec, validate_specs};
use hostip::publicip;
use hostip::server::{self, Server};

#[derive(Parser)]
#[command(version, about = "Publish local apps on your public IP over HTTPS")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Publish local ports, e.g. `hostip expose 3000 8080 udp:50000-60000`.
    Expose(ExposeArgs),
    /// Show this machine's public and LAN IP addresses.
    Ip {
        /// HTTPS endpoints that return the caller's IP as plain text.
        #[arg(long = "source")]
        sources: Vec<String>,
    },
    /// Show the stored certificate.
    Cert {
        #[arg(long)]
        cert_dir: Option<PathBuf>,
    },
}

#[derive(Args)]
struct ExposeArgs {
    /// Ports as `[mode:]local[:public]`; mode is auto (default), https, tls, tcp or udp.
    /// Examples: 3000, 3000:443, tls:5000, udp:3478, udp:50000-60000.
    ports: Vec<String>,
    /// TOML config file with `[[port]]` entries and settings.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Address to listen on.
    #[arg(long)]
    bind: Option<IpAddr>,
    /// Use this public IP instead of detecting it.
    #[arg(long)]
    public_ip: Option<IpAddr>,
    /// Where certificates are stored.
    #[arg(long)]
    cert_dir: Option<PathBuf>,
    /// Extra names or IPs to include in the certificate.
    #[arg(long = "san")]
    sans: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("hostip=info")),
        )
        .init();

    match Cli::parse().command {
        Command::Expose(args) => expose(args).await,
        Command::Ip { sources } => {
            let sources = if sources.is_empty() {
                default_sources()
            } else {
                sources
            };
            println!("public IP: {}", publicip::detect(&sources).await?);
            if let Some(lan) = publicip::lan_ip() {
                println!("LAN IP:    {lan}");
            }
            Ok(())
        }
        Command::Cert { cert_dir } => {
            let dir = cert_dir.unwrap_or_else(default_cert_dir);
            match cert::stored_info(&dir) {
                Some(info) => println!("{info}"),
                None => println!(
                    "no certificate in {} yet; `hostip expose` creates one",
                    dir.display()
                ),
            }
            Ok(())
        }
    }
}

async fn expose(args: ExposeArgs) -> Result<()> {
    let file = match &args.config {
        Some(path) => FileConfig::load(path)?,
        None => FileConfig::default(),
    };
    let mut specs = file.port_specs()?;
    for p in &args.ports {
        specs.push(PortSpec::parse_cli(p)?);
    }
    if specs.is_empty() {
        bail!(
            "nothing to expose: pass ports (e.g. `hostip expose 3000`) or a config file with [[port]] entries"
        );
    }
    validate_specs(&specs)?;

    let public_ip = match args.public_ip.or(file.network.public_ip) {
        Some(ip) => Some(ip),
        None => {
            let sources = if file.network.public_ip_sources.is_empty() {
                default_sources()
            } else {
                file.network.public_ip_sources.clone()
            };
            match publicip::detect(&sources).await {
                Ok(ip) => Some(ip),
                Err(e) => {
                    warn!("{e:#}");
                    warn!("continuing without a public IP; pass --public-ip to set it");
                    None
                }
            }
        }
    };
    let lan_ip = publicip::lan_ip();
    if let Some(ip) = public_ip
        && publicip::is_non_public(ip)
    {
        warn!(%ip, "this public IP is a private/CGNAT address; visitors from the internet cannot reach it");
    }

    let mut sans: Vec<String> = ["localhost", "127.0.0.1", "::1"].map(String::from).to_vec();
    sans.extend(public_ip.iter().chain(lan_ip.iter()).map(IpAddr::to_string));
    sans.extend(file.tls.extra_sans.iter().cloned());
    sans.extend(args.sans.iter().cloned());

    let cert_dir = args
        .cert_dir
        .or(file.tls.dir.clone())
        .unwrap_or_else(default_cert_dir);
    let (key, info) = cert::load_or_generate(&cert_dir, &sans)?;
    info!(
        "{}{info}",
        if info.generated {
            "generated "
        } else {
            "using "
        }
    );
    let certs = CertStore::new(key);

    let bind = args
        .bind
        .or(file.server.bind)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let host = public_ip
        .or(lan_ip)
        .map_or_else(|| "localhost".to_owned(), |ip| ip.to_string());
    let server = Server::bind(&specs, bind, certs, &host).await?;
    let bound = server.local_addrs();
    server::log_ready(&bound);
    print_summary(&specs, &host, lan_ip);

    let shutdown = CancellationToken::new();
    tokio::spawn(wait_for_signal(shutdown.clone()));
    server.serve(shutdown).await;
    info!("stopped");
    Ok(())
}

fn print_summary(specs: &[PortSpec], host: &str, lan_ip: Option<IpAddr>) {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let pc = lan_ip.map_or_else(|| "this PC".to_owned(), |ip| ip.to_string());
    println!();
    println!("hostip is running. Visitors use:");
    for s in specs {
        let scheme = match s.mode {
            Mode::Auto | Mode::Https => "https",
            Mode::Tls => "tls",
            Mode::Tcp => "tcp",
            Mode::Udp => "udp",
        };
        println!(
            "  {scheme}://{host}:{:<11} -> 127.0.0.1:{} ({})",
            s.public.to_string(),
            s.local,
            s.mode
        );
    }
    println!();
    println!("Router port forwarding needed (automatic UPnP mapping is not implemented yet):");
    for s in specs {
        let (proto, target) = match s.listen {
            Some(listen) => ("TCP", listen.to_string()),
            None => ("UDP", s.local.to_string()),
        };
        println!("  {proto} {} -> {pc}:{target}", s.public);
    }
    println!();
    println!(
        "The certificate is self-signed, so browsers will warn until Let's Encrypt support lands."
    );
    println!("Press Ctrl+C to stop.");
}

async fn wait_for_signal(shutdown: CancellationToken) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    info!("shutting down");
    shutdown.cancel();
}

fn default_sources() -> Vec<String> {
    publicip::DEFAULT_SOURCES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn default_cert_dir() -> PathBuf {
    if cfg!(windows)
        && let Some(dir) = std::env::var_os("ProgramData")
    {
        return PathBuf::from(dir).join("hostip").join("certs");
    }
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".hostip").join("certs"),
        None => PathBuf::from(".hostip").join("certs"),
    }
}
