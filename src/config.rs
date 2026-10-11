//! Port specifications and the optional TOML configuration file.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// How a published port is handled (see docs/REQUIREMENTS.md §5.2a).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Terminate TLS, then proxy HTTP if the client speaks HTTP, otherwise pipe raw bytes.
    Auto,
    /// Terminate TLS and always reverse-proxy HTTP.
    Https,
    /// Terminate TLS and pipe raw bytes.
    Tls,
    /// Raw TCP pipe without TLS.
    Tcp,
    /// UDP: mapped on the router only, traffic goes directly to the app.
    Udp,
}

impl Mode {
    pub fn terminates_tls(self) -> bool {
        matches!(self, Mode::Auto | Mode::Https | Mode::Tls)
    }
}

impl FromStr for Mode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "auto" => Mode::Auto,
            "https" => Mode::Https,
            "tls" => Mode::Tls,
            "tcp" => Mode::Tcp,
            "udp" => Mode::Udp,
            other => bail!("unknown mode `{other}` (expected auto, https, tls, tcp or udp)"),
        })
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Auto => "auto",
            Mode::Https => "https",
            Mode::Tls => "tls",
            Mode::Tcp => "tcp",
            Mode::Udp => "udp",
        })
    }
}

/// An inclusive port range; a single port has `start == end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    pub fn is_single(&self) -> bool {
        self.start == self.end
    }

    pub fn count(&self) -> u32 {
        u32::from(self.end - self.start) + 1
    }
}

impl FromStr for PortRange {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parse = |p: &str| -> Result<u16> {
            let port: u16 = p
                .trim()
                .parse()
                .with_context(|| format!("invalid port `{p}`"))?;
            if port == 0 {
                bail!("port 0 is not allowed");
            }
            Ok(port)
        };
        let range = match s.split_once('-') {
            Some((a, b)) => Self {
                start: parse(a)?,
                end: parse(b)?,
            },
            None => Self::single(parse(s)?),
        };
        if range.start > range.end {
            bail!("invalid port range `{s}`: start is greater than end");
        }
        Ok(range)
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_single() {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// Offset used to pick a listen port when the public port equals the local port,
/// because the app itself already occupies the local port on this machine.
pub const LISTEN_PORT_OFFSET: u16 = 10_000;

/// One published port (or UDP port range).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    pub mode: Mode,
    /// Port(s) the app listens on, on this machine.
    pub local: PortRange,
    /// Port(s) visitors connect to on the public IP.
    pub public: PortRange,
    /// Port hostip listens on (TCP modes only). The router forwards `public` -> `listen`.
    pub listen: Option<u16>,
    /// Close raw (non-HTTP) connections after this long without traffic.
    pub idle_timeout: Option<Duration>,
}

impl PortSpec {
    /// Parses the CLI form `[mode:]local[:public]`, e.g. `3000`, `3000:443`,
    /// `tls:5000`, `udp:3478`, `udp:50000-60000`.
    pub fn parse_cli(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        let (mode, rest) = match parts.first().map(|p| p.parse::<Mode>()) {
            Some(Ok(mode)) => (mode, &parts[1..]),
            _ => (Mode::Auto, &parts[..]),
        };
        let (local, public) = match rest {
            [local] => (local.parse()?, None),
            [local, public] => (local.parse()?, Some(public.parse()?)),
            _ => bail!("invalid port spec `{s}` (expected [mode:]local[:public])"),
        };
        Self::new(mode, local, public, None, None)
            .with_context(|| format!("invalid port spec `{s}`"))
    }

    pub fn new(
        mode: Mode,
        local: PortRange,
        public: Option<PortRange>,
        listen: Option<u16>,
        idle_timeout: Option<Duration>,
    ) -> Result<Self> {
        let public = public.unwrap_or(local);
        if public.count() != local.count() {
            bail!("public range {public} and local range {local} differ in size");
        }
        if mode != Mode::Udp {
            if !local.is_single() || !public.is_single() {
                bail!("port ranges are only supported for udp");
            }
        } else if listen.is_some() {
            bail!("`listen` does not apply to udp ports");
        }
        let mut spec = Self {
            mode,
            local,
            public,
            listen,
            idle_timeout,
        };
        if mode != Mode::Udp && spec.listen.is_none() {
            spec.listen = Some(spec.default_listen_port()?);
        }
        Ok(spec)
    }

    /// hostip cannot listen on the app's own port, so when the public port mirrors the
    /// local port we listen on `local + 10000` and the router maps public -> listen.
    fn default_listen_port(&self) -> Result<u16> {
        if self.public.start != self.local.start {
            return Ok(self.public.start);
        }
        self.local
            .start
            .checked_add(LISTEN_PORT_OFFSET)
            .with_context(|| {
                format!(
                    "cannot derive a listen port for local port {}; set `listen` explicitly",
                    self.local.start
                )
            })
    }

    pub fn listen_port(&self) -> Option<u16> {
        self.listen
    }
}

/// Parses durations like `30s`, `10m`, `2h`, `4d` or a plain number of seconds.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num
        .parse()
        .with_context(|| format!("invalid duration `{s}`"))?;
    let secs = match unit.trim() {
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        other => bail!("invalid duration unit `{other}` in `{s}` (use s, m, h or d)"),
    };
    Ok(Duration::from_secs(secs))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub tls: TlsSection,
    #[serde(default)]
    pub network: NetworkSection,
    #[serde(default)]
    pub acme: AcmeSection,
    #[serde(default, rename = "port")]
    pub ports: Vec<PortEntry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// Address to bind listeners on (default `0.0.0.0`).
    pub bind: Option<IpAddr>,
    /// Local port for the plain-HTTP listener the router maps public port 80 to
    /// (ACME HTTP-01 and redirects). Default 80; 0 disables it.
    pub http_listen: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    pub dir: Option<PathBuf>,
    #[serde(default)]
    pub extra_sans: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSection {
    /// Skip detection and use this public IP.
    pub public_ip: Option<IpAddr>,
    #[serde(default)]
    pub public_ip_sources: Vec<String>,
    /// How often to re-check the public IP, e.g. `60s`.
    pub ip_check_interval: Option<String>,
    /// Open router ports automatically via UPnP / PCP / NAT-PMP (default true).
    pub upnp: Option<bool>,
}

/// Let's Encrypt settings for the bare-IP certificate.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeSection {
    /// Default true.
    pub enabled: Option<bool>,
    #[serde(default)]
    pub staging: bool,
    /// Custom ACME directory URL (overrides `staging`).
    pub directory: Option<String>,
    pub email: Option<String>,
    /// Default `shortlived` (required by Let's Encrypt for IP certificates).
    pub profile: Option<String>,
    /// Extra root CA for the ACME server's own HTTPS (test CAs only).
    pub ca_root: Option<PathBuf>,
    /// Renew this long before expiry, e.g. `2d`; default one third of the lifetime.
    pub renew_before: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortEntry {
    pub local: PortValue,
    pub public: Option<PortValue>,
    pub listen: Option<u16>,
    pub mode: Option<Mode>,
    pub idle_timeout: Option<String>,
}

/// A port written either as a TOML integer (`3000`) or string (`"50000-60000"`).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PortValue {
    Number(u16),
    Text(String),
}

impl PortValue {
    fn to_range(&self) -> Result<PortRange> {
        match self {
            PortValue::Number(n) => PortRange::from_str(&n.to_string()),
            PortValue::Text(s) => s.parse(),
        }
    }
}

impl PortEntry {
    pub fn to_spec(&self) -> Result<PortSpec> {
        let idle = self
            .idle_timeout
            .as_deref()
            .map(parse_duration)
            .transpose()?;
        let public = self.public.as_ref().map(PortValue::to_range).transpose()?;
        PortSpec::new(
            self.mode.unwrap_or(Mode::Auto),
            self.local.to_range()?,
            public,
            self.listen,
            idle,
        )
    }
}

impl FileConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid config file {}", path.display()))
    }

    pub fn port_specs(&self) -> Result<Vec<PortSpec>> {
        self.ports
            .iter()
            .enumerate()
            .map(|(i, p)| {
                p.to_spec()
                    .with_context(|| format!("[[port]] entry #{}", i + 1))
            })
            .collect()
    }
}

/// Rejects specs that would make two listeners (or two router mappings) collide.
pub fn validate_specs(specs: &[PortSpec]) -> Result<()> {
    for (i, a) in specs.iter().enumerate() {
        for b in &specs[i + 1..] {
            let tcp = |s: &PortSpec| s.mode != Mode::Udp;
            if tcp(a) != tcp(b) {
                continue;
            }
            let overlap = |x: PortRange, y: PortRange| x.start <= y.end && y.start <= x.end;
            if overlap(a.public, b.public) {
                bail!("public ports {} and {} overlap", a.public, b.public);
            }
            if let (Some(la), Some(lb)) = (a.listen, b.listen)
                && la == lb
            {
                bail!("two ports would both listen on {la}");
            }
        }
        if let Some(listen) = a.listen
            && a.mode != Mode::Udp
            && listen == a.local.start
        {
            bail!("listen port {listen} is the app's own port; choose a different `listen`");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cli_specs() {
        let s = PortSpec::parse_cli("3000").unwrap();
        assert_eq!(
            (s.mode, s.local, s.public, s.listen),
            (
                Mode::Auto,
                PortRange::single(3000),
                PortRange::single(3000),
                Some(13000)
            )
        );

        let s = PortSpec::parse_cli("3000:443").unwrap();
        assert_eq!((s.public.start, s.listen), (443, Some(443)));

        let s = PortSpec::parse_cli("tls:5000").unwrap();
        assert_eq!(s.mode, Mode::Tls);

        let s = PortSpec::parse_cli("udp:50000-60000").unwrap();
        assert_eq!(
            (s.mode, s.local.count(), s.listen),
            (Mode::Udp, 10_001, None)
        );
    }

    #[test]
    fn rejects_bad_specs() {
        for bad in [
            "0",
            "abc",
            "3000:3001:3002",
            "50000-40000",
            "50000-60000",
            "udp:1-5:1-6",
            "60000",
        ] {
            assert!(
                PortSpec::parse_cli(bad).is_err(),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert!(parse_duration("5w").is_err());
    }

    #[test]
    fn parses_config_file() {
        let cfg: FileConfig = toml::from_str(
            r#"
            [network]
            public_ip = "203.0.113.7"
            ip_check_interval = "60s"

            [acme]
            staging = true
            email = "me@example.com"

            [[port]]
            local = 3000
            idle_timeout = "30m"

            [[port]]
            local = 7880
            public = 7443

            [[port]]
            local = "50000-50100"
            mode = "udp"
            "#,
        )
        .unwrap();
        let specs = cfg.port_specs().unwrap();
        assert_eq!(specs.len(), 3);
        assert_eq!(specs[0].idle_timeout, Some(Duration::from_secs(1800)));
        assert_eq!(specs[1].listen, Some(7443));
        assert_eq!(specs[2].local.count(), 101);
        validate_specs(&specs).unwrap();
    }

    #[test]
    fn detects_collisions() {
        let specs = vec![
            PortSpec::parse_cli("3000:443").unwrap(),
            PortSpec::parse_cli("4000:443").unwrap(),
        ];
        assert!(validate_specs(&specs).is_err());
        let specs = vec![
            PortSpec::parse_cli("udp:3478").unwrap(),
            PortSpec::parse_cli("3478:8443").unwrap(),
        ];
        validate_specs(&specs).unwrap();
    }
}
