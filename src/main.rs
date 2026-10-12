use std::io::IsTerminal;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use hostip::access::{self, AuthConfig, Guard};
use hostip::acme::{self, AcmeManager, AcmeOptions, ChallengeKind, HttpChallenges};
use hostip::cert::{self, CertStore};
use hostip::check::{self, CheckOptions, Observer};
use hostip::config::{
    FileConfig, Mode, PortRange, PortSpec, RelaySection, parse_duration, validate_specs,
};
use hostip::hooks::{self, CertExport, IpHooks};
use hostip::portmap::{self, DiscoverOptions};
use hostip::publicip;
use hostip::relay;
use hostip::server::{self, Server, ServerOptions};
use hostip::service;
use hostip::status;

const QUICK_USER: &str = "hostip";
const DEFAULT_IP_CHECK_INTERVAL: Duration = Duration::from_secs(60);
const CONFIG_POLL: Duration = Duration::from_secs(2);

#[derive(Parser)]
#[command(version, about = "Publish local apps on your public IP over HTTPS")]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Log format: `text`, or `json` (one object per line on stderr, for log collectors).
    #[arg(
        long,
        global = true,
        env = "HOSTIP_LOG_FORMAT",
        value_enum,
        default_value_t = LogFormat::Text
    )]
    log_format: LogFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Publish local ports, e.g. `hostip expose 3000 8080 udp:50000-60000`.
    Expose(Box<ExposeArgs>),
    /// Show this machine's public and LAN IP addresses.
    Ip {
        /// HTTPS endpoints that return the caller's IP as plain text.
        #[arg(long = "source")]
        sources: Vec<String>,
    },
    /// Show whether hostip is running, its public links and its certificate.
    /// Exits with 1 when hostip is not running.
    Status {
        /// Where the running hostip keeps its data (default: next to the certificates).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Print the raw status as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check from outside whether visitors can reach the published ports
    /// (TCP and UDP), using a `hostip relay` as the observer. Exits with 1 when
    /// a checked port is unreachable.
    Check(Box<CheckArgs>),
    /// Hash a password for `password_hash` in the config file (reads it from stdin).
    HashPassword,
    /// Run a relay on a machine with a public IP, for homes where no port can be opened.
    Relay(RelayArgs),
    /// Run hostip in the background (Windows service or systemd unit).
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Show the stored certificate.
    Cert {
        #[arg(long)]
        cert_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Install and start the background service for this config file
    /// (Windows: run from an Administrator prompt; also opens the Windows Firewall ports).
    Install {
        #[arg(short, long)]
        config: PathBuf,
        /// Windows: run as LocalSystem instead of the low-privilege LocalService
        /// (needed when hooks must restart other services).
        #[arg(long)]
        system: bool,
    },
    /// Stop and remove the background service and its firewall rules.
    Uninstall,
    /// Entry point used by the Windows Service Control Manager.
    #[command(hide = true)]
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
}

#[derive(Args)]
struct CheckArgs {
    /// Ports as for `expose`, e.g. `3000:443 udp:50000-50100`.
    ports: Vec<String>,
    /// The config file used with `expose` (its ports and [relay] are used).
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Relay (host:port) that checks from outside.
    #[arg(long, requires_all = ["relay_token", "relay_fingerprint"])]
    relay: Option<String>,
    /// The relay's token.
    #[arg(long, env = "HOSTIP_RELAY_TOKEN", hide_env_values = true)]
    relay_token: Option<String>,
    /// The relay's certificate fingerprint (printed by `hostip relay`).
    #[arg(long)]
    relay_fingerprint: Option<String>,
    /// Don't map free ports on the router for the check.
    #[arg(long)]
    no_upnp: bool,
}

#[derive(Args)]
struct RelayArgs {
    /// Control address the home side connects to (TCP and UDP).
    #[arg(long, default_value = "0.0.0.0:7000")]
    listen: std::net::SocketAddr,
    /// Shared secret; generated and saved on first start if not given.
    #[arg(long, env = "HOSTIP_RELAY_TOKEN", hide_env_values = true)]
    token: Option<String>,
    /// Ports the home side may publish, e.g. `80,443,50000-50100`.
    #[arg(long, value_delimiter = ',', default_value = "1-65535")]
    allow_ports: Vec<PortRange>,
    /// This relay's public IP (detected if not given).
    #[arg(long)]
    public_ip: Option<IpAddr>,
    /// Where the relay keeps its certificate and token.
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

#[derive(Args, Default, Clone)]
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
    /// Require this login (`user:password`) on every HTTP port without its own `auth`.
    #[arg(long)]
    auth: Option<String>,
    /// Quick mode (`hostip 3000`): don't require the generated login.
    #[arg(long, conflicts_with = "auth")]
    no_auth: bool,
    /// Set by quick mode: generate a login unless --auth or --no-auth is given.
    #[arg(long, hide = true)]
    quick: bool,
    /// Only let these networks connect (CIDR, repeatable), e.g. `--allow 203.0.113.0/24`.
    #[arg(long = "allow")]
    allow: Vec<ipnet::IpNet>,
    /// Maximum simultaneous connections per port.
    #[arg(long)]
    max_connections: Option<usize>,
    /// Limit each visitor connection's download speed, e.g. `8mbit` (protects upload bandwidth).
    #[arg(long, value_parser = hostip::io::parse_rate)]
    max_client_rate: Option<u64>,
    /// Log every HTTP request.
    #[arg(long)]
    access_log: bool,
    /// Keep the current public IP in this file.
    #[arg(long)]
    ip_file: Option<PathBuf>,
    /// Run this command at start and whenever the public IP changes
    /// (gets HOSTIP_PUBLIC_IP and HOSTIP_PREVIOUS_IP).
    #[arg(long)]
    on_ip_change: Option<String>,
    /// Copy the served certificate chain to this file (needs --export-key).
    #[arg(long, requires = "export_key")]
    export_cert: Option<PathBuf>,
    /// Copy the certificate's private key to this file.
    #[arg(long, requires = "export_cert")]
    export_key: Option<PathBuf>,
    /// Run this command after each certificate export (gets HOSTIP_CERT_FILE, HOSTIP_KEY_FILE).
    #[arg(long)]
    on_cert_renew: Option<String>,
    /// Serve this certificate chain (PEM) instead of a generated one (needs --key).
    #[arg(long, requires = "key")]
    cert: Option<PathBuf>,
    /// Private key (PEM) for --cert.
    #[arg(long, requires = "cert")]
    key: Option<PathBuf>,
    /// Publish through this `hostip relay` (host:port) instead of opening router ports.
    #[arg(long, requires_all = ["relay_token", "relay_fingerprint"])]
    relay: Option<String>,
    /// The relay's token.
    #[arg(long, env = "HOSTIP_RELAY_TOKEN", hide_env_values = true)]
    relay_token: Option<String>,
    /// The relay's certificate fingerprint (printed by `hostip relay`).
    #[arg(long)]
    relay_fingerprint: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse_from(quick_mode_args(std::env::args_os().collect()));
    if let Command::Service(ServiceCommand::Run { config }) = cli.command {
        return run_service(config, cli.log_format);
    }
    init_logging(cli.log_format, None);
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(run(cli.command))
}

/// Quick mode (F14): `hostip 3000 8080` means `hostip expose 3000 8080` with a
/// generated login. A subcommand name never parses as a port spec.
fn quick_mode_args(mut args: Vec<std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    let is_port = args
        .get(1)
        .and_then(|a| a.to_str())
        .is_some_and(|a| !a.starts_with('-') && PortSpec::parse_cli(a).is_ok());
    if is_port {
        args.insert(1, "expose".into());
        args.insert(2, "--quick".into());
    }
    args
}

/// A random password for quick mode: 16 URL-safe characters (96 bits).
fn generate_password() -> Result<String> {
    use base64::Engine;
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 12];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("no secure randomness"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Logs to the console, or to `file` (the Windows service log). JSON goes to
/// stderr on the console so it never mixes with the summary printed on stdout.
fn init_logging(format: LogFormat, file: Option<std::fs::File>) {
    let builder = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("hostip=info")),
    );
    match (format, file) {
        (LogFormat::Json, Some(file)) => builder
            .json()
            .with_writer(std::sync::Mutex::new(file))
            .init(),
        (LogFormat::Json, None) => builder.json().with_writer(std::io::stderr).init(),
        (LogFormat::Text, Some(file)) => builder
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .init(),
        (LogFormat::Text, None) => builder.init(),
    }
}

async fn run(command: Command) -> Result<()> {
    match command {
        Command::Expose(mut args) => {
            // Generated once, so config reloads keep the same login.
            if args.quick && args.auth.is_none() && !args.no_auth {
                let password = generate_password()?;
                println!();
                println!("Quick mode: visitors log in with");
                println!("  user:     {QUICK_USER}");
                println!("  password: {password}");
                println!(
                    "(shown only now; `--auth user:password` sets your own, `--no-auth` makes the links open)"
                );
                args.auth = Some(format!("{QUICK_USER}:{password}"));
            }
            let shutdown = CancellationToken::new();
            tokio::spawn(wait_for_signal(shutdown.clone()));
            expose_with_reload(*args, shutdown).await
        }
        Command::Status { data_dir, json } => {
            let file = status::path(&data_dir.unwrap_or_else(default_data_dir));
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            match status::read(&file) {
                Ok(current) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&current)?);
                    } else {
                        print!("{}", status::render(&current, now));
                    }
                    if !current.is_running(now) {
                        std::process::exit(1);
                    }
                }
                Err(_) => {
                    println!("hostip is not running (no {}).", file.display());
                    println!("For a service or another user, pass --data-dir.");
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        Command::Check(args) => check_command(*args).await,
        Command::HashPassword => {
            let mut password = String::new();
            std::io::stdin().read_line(&mut password)?;
            let password = password.trim_end_matches(['\r', '\n']);
            if password.is_empty() {
                bail!("type the password on stdin, e.g. `echo -n secret | hostip hash-password`");
            }
            println!("{}", access::hash_password(password)?);
            Ok(())
        }
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
        Command::Relay(args) => {
            let shutdown = CancellationToken::new();
            tokio::spawn(wait_for_signal(shutdown.clone()));
            relay_command(args, shutdown).await
        }
        Command::Service(ServiceCommand::Install { config, system }) => {
            install_service(&config, system)
        }
        Command::Service(ServiceCommand::Uninstall) => uninstall_service(),
        Command::Service(ServiceCommand::Run { .. }) => unreachable!("handled in main"),
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

async fn check_command(args: CheckArgs) -> Result<()> {
    let (file, specs) = load_specs(&ExposeArgs {
        ports: args.ports.clone(),
        config: args.config.clone(),
        ..ExposeArgs::default()
    })?;
    let observer = match (&args.relay, &file.relay) {
        (Some(address), _) => Some(Observer::new(
            address,
            args.relay_token.as_deref().unwrap_or_default(),
            args.relay_fingerprint.as_deref().unwrap_or_default(),
        )?),
        (None, Some(r)) => Some(Observer::new(&r.address, &r.token, &r.fingerprint)?),
        (None, None) => None,
    };
    let http_listen = file.server.http_listen.unwrap_or(80);
    let opts = CheckOptions {
        specs,
        http_listen: (http_listen != 0).then_some(http_listen),
        observer,
        upnp: !args.no_upnp && file.network.upnp.unwrap_or(true),
        lan_ip: publicip::lan_ip(),
    };
    println!("Checking reachability...");
    let report = check::run(&opts).await;
    print!("{}", report.render());
    if !report.all_reachable() {
        std::process::exit(1);
    }
    Ok(())
}

async fn relay_command(args: RelayArgs, shutdown: CancellationToken) -> Result<()> {
    let dir = args.data_dir.unwrap_or_else(|| {
        default_cert_dir()
            .parent()
            .map_or_else(|| PathBuf::from("relay"), |p| p.join("relay"))
    });
    std::fs::create_dir_all(&dir)?;
    let token = match args.token {
        Some(token) => token,
        None => {
            let path = dir.join("token");
            match std::fs::read_to_string(&path) {
                Ok(saved) => saved.trim().to_owned(),
                Err(_) => {
                    let token = relay::generate_token();
                    cert::write_private(&path, token.as_bytes())?;
                    token
                }
            }
        }
    };
    if token.len() < 16 {
        warn!("the relay token is short; use at least 16 random characters");
    }
    let public_ip = match args.public_ip {
        Some(ip) => Some(ip),
        None => publicip::detect(&default_sources()).await.ok(),
    };
    let (tls, fingerprint) = relay::relay_tls(&dir)?;
    let host = public_ip.map_or_else(
        || "<this-server-ip>".to_owned(),
        |ip| url_host(&ip.to_string()),
    );
    println!();
    println!("hostip relay is ready on {}.", args.listen);
    println!("On the home PC run, for example:");
    println!(
        "  hostip expose 3000:443 --relay {host}:{} --relay-token {token} --relay-fingerprint {fingerprint}",
        args.listen.port()
    );
    println!(
        "Open TCP+UDP {} and the published ports in this server's firewall.",
        args.listen.port()
    );
    println!();
    let options = relay::RelayOptions {
        listen: args.listen,
        token,
        public_ip,
        allowed_ports: args.allow_ports,
    };
    relay::run_relay(options, tls, shutdown).await
}

/// Checks the config and returns its absolute path plus the firewall rules it needs.
fn prepare_service(config: &std::path::Path) -> Result<(PathBuf, Vec<service::FirewallRule>)> {
    let config = std::fs::canonicalize(config)
        .map_err(|e| anyhow::anyhow!("cannot find {}: {e}", config.display()))?;
    let args = ExposeArgs {
        config: Some(config.clone()),
        ..ExposeArgs::default()
    };
    let (file, specs) = load_specs(&args)?;
    let http_listen = Some(file.server.http_listen.unwrap_or(80)).filter(|p| *p != 0);
    Ok((config, service::firewall_rules(&specs, http_listen)))
}

#[cfg(windows)]
fn install_service(config: &std::path::Path, system: bool) -> Result<()> {
    let (config, rules) = prepare_service(config)?;
    service::windows::install(&config, &rules, system)?;
    println!(
        "Installed and started the hostip service for {}.",
        config.display()
    );
    for rule in &rules {
        println!(
            "Windows Firewall: allowed inbound {} {}",
            rule.proto, rule.ports
        );
    }
    println!("Log: {}", service::windows::log_path().display());
    Ok(())
}

#[cfg(windows)]
fn uninstall_service() -> Result<()> {
    service::windows::uninstall()?;
    println!("Removed the hostip service and its firewall rules.");
    Ok(())
}

#[cfg(windows)]
fn run_service(config: PathBuf, log_format: LogFormat) -> Result<()> {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(service::windows::log_path())?;
    init_logging(log_format, Some(log));
    service::windows::run(config, |config, shutdown| {
        let args = ExposeArgs {
            config: Some(config),
            ..ExposeArgs::default()
        };
        tokio::runtime::Runtime::new()?.block_on(expose_with_reload(args, shutdown))
    })
}

#[cfg(not(windows))]
fn install_service(config: &std::path::Path, _system: bool) -> Result<()> {
    let (config, _) = prepare_service(config)?;
    let unit = service::systemd_unit(&std::env::current_exe()?, &config);
    let path = std::path::Path::new("/etc/systemd/system/hostip.service");
    if cfg!(target_os = "linux") && std::fs::write(path, &unit).is_ok() {
        let status = std::process::Command::new("systemctl")
            .args(["daemon-reload"])
            .status()
            .and_then(|_| {
                std::process::Command::new("systemctl")
                    .args(["enable", "--now", "hostip"])
                    .status()
            })?;
        if !status.success() {
            bail!("systemctl enable --now hostip failed");
        }
        println!("Installed and started {}.", path.display());
        println!("Logs: journalctl -u hostip -f");
        println!("Open the ports in your firewall (e.g. ufw) if it blocks inbound traffic.");
    } else {
        println!(
            "Save this as {} and run `systemctl enable --now hostip` as root:\n",
            path.display()
        );
        print!("{unit}");
    }
    Ok(())
}

#[cfg(not(windows))]
fn uninstall_service() -> Result<()> {
    let _ = std::process::Command::new("systemctl")
        .args(["disable", "--now", "hostip"])
        .status();
    let path = std::path::Path::new("/etc/systemd/system/hostip.service");
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    println!("Removed the hostip systemd unit.");
    Ok(())
}

#[cfg(not(windows))]
fn run_service(_config: PathBuf, _log_format: LogFormat) -> Result<()> {
    bail!("`hostip service run` is only used by Windows; on Linux the unit runs `hostip expose`")
}

/// Runs `expose`, restarting it whenever the config file changes to a valid config (F15).
async fn expose_with_reload(args: ExposeArgs, shutdown: CancellationToken) -> Result<()> {
    let Some(path) = args.config.clone() else {
        return expose(args, shutdown).await;
    };
    let modified = |p: &std::path::Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    loop {
        let mut seen = modified(&path);
        let run = shutdown.child_token();
        let task = expose(args.clone(), run.clone());
        tokio::pin!(task);
        loop {
            tokio::select! {
                result = &mut task => return result,
                _ = tokio::time::sleep(CONFIG_POLL) => {}
            }
            let now = modified(&path);
            if now == seen {
                continue;
            }
            seen = now;
            match load_specs(&args) {
                Ok(_) => break,
                Err(e) => warn!("config changed but is invalid, keeping the current one: {e:#}"),
            }
        }
        info!("config changed; restarting with the new settings (open connections are closed)");
        run.cancel();
        task.await?;
    }
}

/// The config file plus the port specs from it and the command line, validated.
fn load_specs(args: &ExposeArgs) -> Result<(FileConfig, Vec<PortSpec>)> {
    let file = match &args.config {
        Some(path) => FileConfig::load(path)?,
        None => FileConfig::default(),
    };
    let mut specs = file.port_specs()?;
    for p in &args.ports {
        specs.push(PortSpec::parse_cli(p)?);
    }
    let cli_auth = args
        .auth
        .as_deref()
        .map(AuthConfig::parse_cli)
        .transpose()?;
    for spec in specs.iter_mut().filter(|s| s.mode != Mode::Udp) {
        if spec.access.auth.is_none() && matches!(spec.mode, Mode::Auto | Mode::Https) {
            spec.access.auth = cli_auth.clone();
        }
        if spec.access.allow.is_empty() {
            spec.access.allow = args.allow.clone();
        }
        spec.access.max_connections = spec.access.max_connections.or(args.max_connections);
        spec.max_client_rate = spec.max_client_rate.or(args.max_client_rate);
    }
    if specs.is_empty() {
        bail!(
            "nothing to expose: pass ports (e.g. `hostip expose 3000`) or a config file with [[port]] entries"
        );
    }
    validate_specs(&specs)?;
    Ok((file, specs))
}

async fn expose(args: ExposeArgs, shutdown: CancellationToken) -> Result<()> {
    let (file, specs) = load_specs(&args)?;

    let sources = if file.network.public_ip_sources.is_empty() {
        default_sources()
    } else {
        file.network.public_ip_sources.clone()
    };
    let relay = match (&args.relay, &file.relay) {
        (Some(address), _) => Some(RelaySection {
            address: address.clone(),
            token: args.relay_token.clone().unwrap_or_default(),
            fingerprint: args.relay_fingerprint.clone().unwrap_or_default(),
        }),
        (None, Some(section)) => Some(section.clone()),
        (None, None) => None,
    };
    // Through a relay, visitors use the relay's address.
    let relay_ip = match &relay {
        Some(r) => Some(relay::resolve(&r.address).await?.ip()),
        None => None,
    };
    let fixed_ip = args.public_ip.or(file.network.public_ip).or(relay_ip);
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
    let own_cert = match (&args.cert, &args.key) {
        (Some(cert), Some(key)) => Some((cert.clone(), key.clone())),
        _ => file.tls.cert.clone().zip(file.tls.key.clone()),
    };
    if file.tls.cert.is_some() != file.tls.key.is_some() {
        bail!("[tls] needs both `cert` and `key`");
    }
    let certs = match &own_cert {
        Some((cert_path, key_path)) => {
            let pem = cert::PemPair {
                chain: std::fs::read_to_string(cert_path)?,
                key: std::fs::read_to_string(key_path)?,
            };
            let key = cert::certified_key_from_pem(&pem.chain, &pem.key)
                .with_context(|| format!("invalid certificate {}", cert_path.display()))?;
            info!("serving the certificate from {}", cert_path.display());
            let certs = CertStore::new(key.clone());
            certs.replace_with_pem(key, pem);
            certs
        }
        None => {
            let (key, info) = self_signed(public_ip)?;
            info!(
                "{}{info}",
                if info.generated {
                    "generated "
                } else {
                    "using "
                }
            );
            let certs = CertStore::new(key.clone());
            if let Ok(pem) = info.read_pem() {
                certs.replace_with_pem(key, pem);
            }
            certs
        }
    };

    let bind = args
        .bind
        .or(file.server.bind)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let host = public_ip
        .or(lan_ip)
        .map_or_else(|| "localhost".to_owned(), |ip| ip.to_string());
    let guard = Guard::new(file.limits.clone());
    let options = ServerOptions {
        guard: guard.clone(),
        access_log: args.access_log || file.server.access_log,
    };
    let mut server = Server::bind_with(&specs, bind, certs.clone(), &host, options).await?;

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
                // Through a relay, port 80 arrives over the tunnel; the local port is irrelevant.
                if relay.is_some() { 0 } else { http_listen },
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
    let acme_enabled = own_cert.is_none() && !args.no_acme && file.acme.enabled.unwrap_or(true);
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
    let upnp = relay.is_none() && !args.no_upnp && file.network.upnp.unwrap_or(true);
    print_summary(
        &specs,
        &host,
        lan_ip,
        http_bound,
        acme_active,
        upnp,
        relay.as_ref().map(|r| r.address.as_str()),
    );

    // Public IP tracking (F7, F19): only when the IP was detected, not given.
    let (ip_tx, ip_rx) = watch::channel(public_ip);
    if fixed_ip.is_none() {
        let interval = match &file.network.ip_check_interval {
            Some(text) => parse_duration(text)?,
            None => DEFAULT_IP_CHECK_INTERVAL,
        };
        tokio::spawn(publicip::watch(sources, interval, ip_tx, shutdown.clone()));
    }

    let mut acme_outcomes = None;
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
        acme_outcomes = Some(manager.outcomes());
        tokio::spawn(manager.run(ip_rx.clone(), shutdown.clone()));
    }
    if let Some((cert_path, key_path)) = own_cert {
        tokio::spawn(cert::watch_files(
            certs.clone(),
            cert_path,
            key_path,
            shutdown.clone(),
        ));
    }
    let ip_hooks = IpHooks {
        ip_file: args.ip_file.clone().or(file.network.ip_file.clone()),
        on_change: args
            .on_ip_change
            .clone()
            .or(file.network.on_ip_change.clone()),
    };
    if ip_hooks.ip_file.is_some() || ip_hooks.on_change.is_some() {
        tokio::spawn(hooks::watch_ip(ip_rx.clone(), ip_hooks));
    }
    let export = match (&args.export_cert, &args.export_key) {
        (Some(cert), Some(key)) => Some(CertExport {
            cert: cert.clone(),
            key: key.clone(),
            on_renew: args.on_cert_renew.clone(),
        }),
        _ => file.tls.export.clone().map(|e| CertExport {
            cert: e.cert,
            key: e.key,
            on_renew: args.on_cert_renew.clone().or(e.on_renew),
        }),
    };
    if let Some(export) = export {
        tokio::spawn(hooks::export_certs(certs.clone(), export));
    }
    {
        let specs = specs.clone();
        let mode = match &relay {
            Some(r) => format!("relay {}", r.address),
            None => "direct".to_owned(),
        };
        let urls = move |ip: Option<IpAddr>| {
            let host = url_host(&ip.map_or_else(|| "localhost".to_owned(), |ip| ip.to_string()));
            specs
                .iter()
                .filter(|s| s.mode != Mode::Udp)
                .map(|s| public_url(s, &host))
                .collect()
        };
        let guard = guard.clone();
        tokio::spawn(status::write_periodically(
            status::path(&default_data_dir()),
            status::Sources {
                mode,
                urls: Box::new(urls),
                certs: certs.clone(),
                ip: ip_rx.clone(),
                acme: acme_outcomes,
                open_connections: Box::new(move || guard.open_connections()),
            },
            shutdown.clone(),
        ));
    }
    tokio::spawn(report_ip_changes(
        ip_rx,
        specs.clone(),
        (!acme_active && args.cert.is_none() && file.tls.cert.is_none()).then(|| {
            let certs = certs.clone();
            move |ip| match self_signed(Some(ip))
                .and_then(|(key, info)| Ok((key, info.read_pem()?)))
            {
                Ok((key, pem)) => certs.replace_with_pem(key, pem),
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

    if let Some(r) = relay {
        let mut tcp_ports: Vec<u16> = specs
            .iter()
            .filter(|s| s.mode != Mode::Udp)
            .map(|s| s.public.start)
            .collect();
        if http_bound.is_some() {
            tcp_ports.push(80);
        }
        let options = relay::ClientOptions {
            relay: r.address,
            token: r.token,
            fingerprint: r.fingerprint,
            tcp_ports,
            udp: specs
                .iter()
                .filter(|s| s.mode == Mode::Udp)
                .map(|s| (s.public, s.local.start))
                .collect(),
        };
        tokio::spawn(relay::run_client(
            options,
            server.injector(shutdown.clone()),
            shutdown.clone(),
        ));
    }

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
    relay: Option<&str>,
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
    if std::io::stdout().is_terminal()
        && let Some(url) = specs
            .iter()
            .find(|s| matches!(s.mode, Mode::Auto | Mode::Https))
            .map(|s| public_url(s, &host))
        && let Ok(code) = qrcode::QrCode::new(&url)
    {
        // Inverted colours read well on dark terminals and still scan on light ones.
        let qr = code
            .render::<qrcode::render::unicode::Dense1x2>()
            .dark_color(qrcode::render::unicode::Dense1x2::Light)
            .light_color(qrcode::render::unicode::Dense1x2::Dark)
            .build();
        println!();
        println!("Scan to open {url}:");
        println!("{qr}");
    }
    println!();
    if let Some(relay) = relay {
        println!("No router setup needed: visitors arrive through the relay at {relay}.");
    } else {
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
    }
    let open_http: Vec<String> = specs
        .iter()
        .filter(|s| matches!(s.mode, Mode::Auto | Mode::Https) && s.access.auth.is_none())
        .map(|s| s.public.to_string())
        .collect();
    if !open_http.is_empty() {
        println!();
        println!(
            "Anyone with the link can open port(s) {}; add `--auth user:password` to require a login.",
            open_http.join(", ")
        );
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

/// Where hostip keeps its state (the certificate directory's parent).
fn default_data_dir() -> PathBuf {
    default_cert_dir()
        .parent()
        .map_or_else(|| PathBuf::from(".hostip"), PathBuf::from)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<std::ffi::OsString> {
        list.iter().map(Into::into).collect()
    }

    #[test]
    fn quick_mode_rewrites_bare_ports() {
        assert_eq!(
            quick_mode_args(args(&["hostip", "3000", "udp:3478"])),
            args(&["hostip", "expose", "--quick", "3000", "udp:3478"])
        );
        assert_eq!(
            quick_mode_args(args(&["hostip", "3000:443", "--no-auth"])),
            args(&["hostip", "expose", "--quick", "3000:443", "--no-auth"])
        );
        for unchanged in [
            &["hostip", "expose", "3000"][..],
            &["hostip", "status"],
            &["hostip", "--help"],
            &["hostip"],
        ] {
            assert_eq!(quick_mode_args(args(unchanged)), args(unchanged));
        }
    }

    #[test]
    fn quick_mode_parses_and_sets_a_login() {
        let cli = Cli::try_parse_from(quick_mode_args(args(&["hostip", "3000"]))).unwrap();
        let Command::Expose(expose) = cli.command else {
            panic!("expected expose");
        };
        assert!(expose.quick && !expose.no_auth && expose.auth.is_none());
        assert!(
            Cli::try_parse_from(args(&[
                "hostip",
                "expose",
                "3000",
                "--no-auth",
                "--auth",
                "a:b"
            ]))
            .is_err(),
            "--no-auth and --auth conflict"
        );
    }

    #[test]
    fn generated_passwords_are_long_and_differ() {
        let (a, b) = (generate_password().unwrap(), generate_password().unwrap());
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
        assert!(AuthConfig::parse_cli(&format!("{QUICK_USER}:{a}")).is_ok());
    }
}
