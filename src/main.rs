use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use hostip::acme::{self, AcmeManager, AcmeOptions, ChallengeKind, HttpChallenges};
use hostip::cert::{self, CertStore};
use hostip::config::{FileConfig, Mode, PortRange, PortSpec, parse_duration, validate_specs};
use hostip::portmap::{self, DiscoverOptions};
use hostip::publicip;
use hostip::server::{self, Server};

const DEFAULT_IP_CHECK_INTERVAL: Duration = Duration::from_secs(60);

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
    /// Extra names or IPs to include in the self-signed certificate.
    #[arg(long = "san")]
    sans: Vec<String>,
    /// Don't request a Let's Encrypt certificate; serve the self-signed one only.
    #[arg(long)]
    no_acme: bool,
    /// Use Let's Encrypt's staging CA (for testing; browsers don't trust it).
    #[arg(long)]
    acme_staging: bool,
    /// Custom ACME directory URL.
    #[arg(long)]
    acme_directory: Option<String>,
    /// Contact email for the ACME account (optional).
    #[arg(long)]
    acme_email: Option<String>,
    /// Local port for plain HTTP; the router maps public port 80 to it. 0 disables. [default: 80]
    #[arg(long)]
    http_listen: Option<u16>,
    /// Don't open router ports automatically (UPnP / PCP / NAT-PMP).
    #[arg(long)]
    no_upnp: bool,
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
            for (name, not_after) in acme::list_stored(&acme::default_dir(&dir)) {
                println!("Let's Encrypt certificate for {name}, valid until {not_after}");
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

    let sources = if file.network.public_ip_sources.is_empty() {
        default_sources()
    } else {
        file.network.public_ip_sources.clone()
    };
    let fixed_ip = args.public_ip.or(file.network.public_ip);
    let public_ip = match fixed_ip {
        Some(ip) => Some(ip),
        None => match publicip::detect(&sources).await {
            Ok(ip) => Some(ip),
            Err(e) => {
                warn!("{e:#}");
                warn!("continuing without a public IP; pass --public-ip to set it");
                None
            }
        },
    };
    let lan_ip = publicip::lan_ip();
    if let Some(ip) = public_ip
        && publicip::is_non_public(ip)
    {
        warn!(%ip, "this public IP is a private/CGNAT address; visitors from the internet cannot reach it");
    }

    // Self-signed certificate: served until Let's Encrypt has issued one, and as the fallback.
    let mut base_sans: Vec<String> = ["localhost", "127.0.0.1", "::1"].map(String::from).to_vec();
    base_sans.extend(lan_ip.iter().map(IpAddr::to_string));
    base_sans.extend(file.tls.extra_sans.iter().cloned());
    base_sans.extend(args.sans.iter().cloned());
    let cert_dir = args
        .cert_dir
        .clone()
        .or(file.tls.dir.clone())
        .unwrap_or_else(default_cert_dir);
    let self_signed = {
        let (cert_dir, base_sans) = (cert_dir.clone(), base_sans.clone());
        move |ip: Option<IpAddr>| {
            let mut sans = base_sans.clone();
            sans.extend(ip.map(|ip| ip.to_string()));
            cert::load_or_generate(&cert_dir, &sans)
        }
    };
    let (key, info) = self_signed(public_ip)?;
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
    let mut server = Server::bind(&specs, bind, certs.clone(), &host).await?;

    // Plain HTTP on public port 80: ACME HTTP-01 challenges and redirects to https.
    let https_443 = specs
        .iter()
        .any(|s| s.public.start == 443 && matches!(s.mode, Mode::Auto | Mode::Https));
    let challenges = Arc::new(HttpChallenges::default());
    let http_listen = args.http_listen.or(file.server.http_listen).unwrap_or(80);
    let http_bound = if http_listen == 0 {
        None
    } else {
        match server
            .bind_http(
                bind,
                http_listen,
                challenges.clone(),
                https_443.then_some(443),
            )
            .await
        {
            Ok(addr) => Some(addr.port()),
            Err(e) => {
                warn!("{e:#}; HTTP-01 validation and http->https redirects are off");
                None
            }
        }
    };

    let mut challenge_kinds = Vec::new();
    if https_443 {
        challenge_kinds.push(ChallengeKind::TlsAlpn01);
    }
    if http_bound.is_some() {
        challenge_kinds.push(ChallengeKind::Http01);
    }
    let acme_enabled = !args.no_acme && file.acme.enabled.unwrap_or(true);
    let acme_active = acme_enabled
        && !challenge_kinds.is_empty()
        && !public_ip.is_some_and(publicip::is_non_public);
    if acme_enabled && challenge_kinds.is_empty() {
        warn!(
            "Let's Encrypt needs public port 443 (publish an app on it, e.g. `hostip expose 3000:443`) \
             or the HTTP port 80; serving the self-signed certificate only"
        );
    }

    server::log_ready(&server.local_addrs());
    let upnp = !args.no_upnp && file.network.upnp.unwrap_or(true);
    print_summary(&specs, &host, lan_ip, http_bound, acme_active, upnp);

    let shutdown = CancellationToken::new();
    tokio::spawn(wait_for_signal(shutdown.clone()));

    // Public IP tracking (F7, F19): only when the IP was detected, not given.
    let (ip_tx, ip_rx) = watch::channel(public_ip);
    if fixed_ip.is_none() {
        let interval = match &file.network.ip_check_interval {
            Some(text) => parse_duration(text)?,
            None => DEFAULT_IP_CHECK_INTERVAL,
        };
        tokio::spawn(publicip::watch(sources, interval, ip_tx, shutdown.clone()));
    }

    if acme_active {
        let directory = args
            .acme_directory
            .clone()
            .or(file.acme.directory.clone())
            .unwrap_or_else(|| {
                AcmeOptions::directory_for(args.acme_staging || file.acme.staging).to_owned()
            });
        let renew_before = file
            .acme
            .renew_before
            .as_deref()
            .map(parse_duration)
            .transpose()?;
        let opts = AcmeOptions {
            directory,
            contact: args.acme_email.clone().or(file.acme.email.clone()),
            profile: Some(
                file.acme
                    .profile
                    .clone()
                    .unwrap_or_else(|| acme::DEFAULT_PROFILE.to_owned()),
            ),
            ca_root: file.acme.ca_root.clone(),
            dir: acme::default_dir(&cert_dir),
            challenges: challenge_kinds,
            renew_before,
        };
        info!(
            "requesting a Let's Encrypt certificate from {} via {}",
            opts.directory,
            opts.challenges
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" or ")
        );
        let manager = AcmeManager::new(opts, certs.clone(), challenges);
        let fallback = self_signed.clone();
        manager.set_fallback(Box::new(move |ip| Ok(fallback(Some(ip))?.0)));
        tokio::spawn(manager.run(ip_rx.clone(), shutdown.clone()));
    }
    tokio::spawn(report_ip_changes(
        ip_rx,
        specs.clone(),
        (!acme_active).then(|| {
            let certs = certs.clone();
            move |ip| match self_signed(Some(ip)) {
                Ok((key, _)) => certs.replace(key),
                Err(e) => warn!("cannot regenerate the self-signed certificate: {e:#}"),
            }
        }),
    ));

    // Router port mapping (F12, F26): opened now, renewed, removed on shutdown.
    let portmap_task = match lan_ip {
        Some(IpAddr::V4(lan)) if upnp => {
            let (mappings, too_large) = portmap::plan(&specs, http_bound);
            for spec in too_large {
                warn!(
                    "UDP {} is too large to map automatically; forward it manually",
                    spec.public
                );
            }
            Some(tokio::spawn(portmap::run(
                lan,
                mappings,
                DiscoverOptions::default(),
                shutdown.clone(),
            )))
        }
        _ => None,
    };

    server.serve(shutdown).await;
    if let Some(task) = portmap_task {
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }
    info!("stopped");
    Ok(())
}

/// Logs the new public URLs after an IP change and, without ACME, refreshes the
/// self-signed certificate so it names the new IP.
async fn report_ip_changes(
    mut ip: watch::Receiver<Option<IpAddr>>,
    specs: Vec<PortSpec>,
    refresh_self_signed: Option<impl Fn(IpAddr)>,
) {
    while ip.changed().await.is_ok() {
        let Some(addr) = *ip.borrow_and_update() else {
            continue;
        };
        if let Some(refresh) = &refresh_self_signed {
            refresh(addr);
        }
        let host = url_host(&addr.to_string());
        for s in specs.iter().filter(|s| s.mode != Mode::Udp) {
            warn!("links changed: visitors now use {}", public_url(s, &host));
        }
    }
}

fn scheme(mode: Mode) -> &'static str {
    match mode {
        Mode::Auto | Mode::Https => "https",
        Mode::Tls => "tls",
        Mode::Tcp => "tcp",
        Mode::Udp => "udp",
    }
}

/// `https://host` for port 443, otherwise `scheme://host:port`.
fn public_url(spec: &PortSpec, host: &str) -> String {
    let scheme = scheme(spec.mode);
    if spec.public == PortRange::single(443) && scheme == "https" {
        format!("https://{host}")
    } else {
        format!("{scheme}://{host}:{}", spec.public)
    }
}

fn url_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

fn print_summary(
    specs: &[PortSpec],
    host: &str,
    lan_ip: Option<IpAddr>,
    http_listen: Option<u16>,
    acme: bool,
    upnp: bool,
) {
    let host = url_host(host);
    let pc = lan_ip.map_or_else(|| "this PC".to_owned(), |ip| ip.to_string());
    println!();
    println!("hostip is running. Visitors use:");
    for s in specs {
        println!(
            "  {:<32} -> 127.0.0.1:{} ({})",
            public_url(s, &host),
            s.local,
            s.mode
        );
    }
    println!();
    if upnp {
        println!(
            "Router ports (opened automatically via UPnP / PCP / NAT-PMP if the router allows it,"
        );
        println!("otherwise forward them manually):");
    } else {
        println!("Router port forwarding needed:");
    }
    for s in specs {
        let (proto, target) = match s.listen {
            Some(listen) => ("TCP", listen.to_string()),
            None => ("UDP", s.local.to_string()),
        };
        println!("  {proto} {} -> {pc}:{target}", s.public);
    }
    if let Some(port) = http_listen {
        println!("  TCP 80 -> {pc}:{port}   (Let's Encrypt validation, http->https redirect)");
    }
    println!();
    if acme {
        println!(
            "Serving a self-signed certificate until Let's Encrypt issues the certificate for the IP."
        );
    } else {
        println!("The certificate is self-signed, so browsers will show a warning.");
    }
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
