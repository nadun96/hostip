//! Reachability self-test (F13, F29): can visitors on the internet reach the
//! published ports?
//!
//! A `hostip relay` acts as the outside observer: it connects back to this
//! network's public address on every TCP port and sends a datagram to every UDP
//! port. Ports nothing listens on yet (hostip or the app is not running) get a
//! temporary listener here, and a temporary router mapping when UPnP is on, so the
//! check tests the path through the router either way. The router's own internet
//! address shows double NAT / CGNAT.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

use crate::config::{Mode, PortSpec};
use crate::portmap::{DiscoverOptions, Mapping, PortMapper, Proto};
use crate::publicip;
use crate::relay::{self, TcpReach};

/// UDP ranges can be large; this many ports are checked at most.
pub const MAX_UDP_PORTS: usize = 64;
/// Datagrams can arrive a little after the relay has answered.
const UDP_GRACE: Duration = Duration::from_secs(1);

/// The relay that probes from outside.
#[derive(Debug, Clone)]
pub struct Observer {
    pub address: String,
    pub token: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct CheckOptions {
    pub specs: Vec<PortSpec>,
    /// Local port of the plain-HTTP listener (public 80), if any.
    pub http_listen: Option<u16>,
    pub observer: Option<Observer>,
    /// Map free ports on the router for the duration of the check.
    pub upnp: bool,
    pub lan_ip: Option<IpAddr>,
}

/// Who answers on a local port during the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listener {
    /// The port was free; the check listened on it.
    Temporary,
    /// Already in use, normally by a running hostip (TCP) or the app (UDP).
    InUse,
    /// Could not listen (e.g. ports below 1024 need privileges).
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpReach {
    Received,
    NotReceived,
    /// The app holds the port, so the probe datagrams cannot be seen.
    NotTested,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResult {
    pub public: u16,
    pub local: u16,
    pub label: &'static str,
    pub listener: Listener,
    pub reach: Option<TcpReach>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpResult {
    pub public: u16,
    pub local: u16,
    pub reach: Option<UdpReach>,
}

#[derive(Debug, Default)]
pub struct Report {
    /// The relay used as the outside observer.
    pub observer: Option<String>,
    /// This network's public address as the relay saw it.
    pub observed_ip: Option<IpAddr>,
    pub observer_error: Option<String>,
    /// How ports were mapped on the router, or why not.
    pub router: Option<String>,
    /// The router's own internet address.
    pub router_wan: Option<IpAddr>,
    pub tcp: Vec<TcpResult>,
    pub udp: Vec<UdpResult>,
    /// UDP ports left out because of [`MAX_UDP_PORTS`].
    pub udp_skipped: usize,
}

/// Runs the check: temporary listeners, temporary router mappings, the outside probe.
pub async fn run(opts: &CheckOptions) -> Report {
    let mut report = Report {
        observer: opts.observer.as_ref().map(|o| o.address.clone()),
        ..Report::default()
    };
    let mut held: Vec<JoinHandle<()>> = Vec::new();
    let mut mappings = Vec::new();
    let received: Arc<Mutex<HashSet<u16>>> = Arc::default();
    let nonce = random_u64();

    let tcp_ports = opts
        .specs
        .iter()
        .filter(|s| s.mode != Mode::Udp)
        .filter_map(|s| Some((s.public.start, s.listen?, "")))
        .chain(opts.http_listen.map(|l| (80, l, " (http)")));
    for (public, local, label) in tcp_ports {
        let listener = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, local)).await {
            Ok(l) => {
                held.push(tokio::spawn(async move {
                    // Accept and drop: the connection itself is the answer.
                    while let Ok((stream, _)) = l.accept().await {
                        drop(stream);
                    }
                }));
                mappings.push(Mapping {
                    proto: Proto::Tcp,
                    external: public,
                    internal: local,
                });
                Listener::Temporary
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Listener::InUse,
            Err(e) => Listener::Unavailable(e.to_string()),
        };
        report.tcp.push(TcpResult {
            public,
            local,
            label,
            listener,
            reach: None,
        });
    }

    let udp_ports: Vec<(u16, u16)> = opts
        .specs
        .iter()
        .filter(|s| s.mode == Mode::Udp)
        .flat_map(|s| {
            (0..=s.public.end - s.public.start)
                .map(move |i| (s.public.start + i, s.local.start + i))
        })
        .collect();
    report.udp_skipped = udp_ports.len().saturating_sub(MAX_UDP_PORTS);
    for &(public, local) in udp_ports.iter().take(MAX_UDP_PORTS) {
        let reach = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, local)).await {
            Ok(socket) => {
                let received = received.clone();
                held.push(tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    while let Ok((n, _)) = socket.recv_from(&mut buf).await {
                        if buf[..n] == relay::probe_datagram(nonce, public)[..] {
                            received.lock().unwrap().insert(public);
                        }
                    }
                }));
                mappings.push(Mapping {
                    proto: Proto::Udp,
                    external: public,
                    internal: local,
                });
                None
            }
            Err(_) => Some(UdpReach::NotTested),
        };
        report.udp.push(UdpResult {
            public,
            local,
            reach,
        });
    }

    let mut mapper = None;
    if let Some(IpAddr::V4(lan)) = opts.lan_ip {
        match PortMapper::discover(lan, &DiscoverOptions::default()).await {
            Ok(mut m) => {
                report.router_wan = m.external_ip().await;
                if opts.upnp && !mappings.is_empty() {
                    let mapped = m.map_all(&mappings).await;
                    report.router = Some(format!(
                        "{}: mapped {} free port(s) for the check{}",
                        m.method(),
                        mapped.mapped.len(),
                        mapped
                            .failed
                            .first()
                            .map(|(map, e)| format!("; {map} failed: {e}"))
                            .unwrap_or_default()
                    ));
                } else {
                    report.router = Some(format!("{} found", m.method()));
                }
                mapper = Some(m);
            }
            Err(e) => report.router = Some(format!("no UPnP / PCP / NAT-PMP router: {e:#}")),
        }
    }

    if let Some(observer) = &opts.observer {
        let probed_udp: Vec<u16> = report
            .udp
            .iter()
            .filter(|u| u.reach.is_none())
            .map(|u| u.public)
            .collect();
        match relay::request_probe(
            &observer.address,
            &observer.token,
            &observer.fingerprint,
            report.tcp.iter().map(|t| t.public).collect(),
            probed_udp,
            nonce,
        )
        .await
        {
            Ok((observed, tcp)) => {
                report.observed_ip = Some(observed);
                for (port, reach) in tcp {
                    for t in report.tcp.iter_mut().filter(|t| t.public == port) {
                        t.reach = Some(reach);
                    }
                }
                tokio::time::sleep(UDP_GRACE).await;
                let received = received.lock().unwrap();
                for u in report.udp.iter_mut().filter(|u| u.reach.is_none()) {
                    u.reach = Some(if received.contains(&u.public) {
                        UdpReach::Received
                    } else {
                        UdpReach::NotReceived
                    });
                }
            }
            Err(e) => report.observer_error = Some(format!("{e:#}")),
        }
    }

    if let Some(mut m) = mapper
        && opts.upnp
        && !mappings.is_empty()
    {
        m.remove_all().await;
    }
    // Wait for the listeners to close, so the ports are free when this returns.
    held.iter().for_each(JoinHandle::abort);
    for task in held {
        let _ = task.await;
    }
    report
}

fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    // Only distinguishes this check's datagrams; a fixed value would still work.
    let _ = SystemRandom::new().fill(&mut bytes);
    u64::from_le_bytes(bytes)
}

impl Report {
    /// True when every port the outside probe could test was reachable.
    pub fn all_reachable(&self) -> bool {
        self.observed_ip.is_some()
            && self.tcp.iter().all(|t| t.reach == Some(TcpReach::Open))
            && self
                .udp
                .iter()
                .all(|u| matches!(u.reach, Some(UdpReach::Received | UdpReach::NotTested)))
    }

    /// Double NAT / CGNAT: the router is not the device holding the public address.
    pub fn behind_cgnat(&self) -> Option<String> {
        let wan = self.router_wan?;
        if publicip::is_non_public(wan) {
            return Some(format!(
                "the router's internet address {wan} is private or CGNAT: another NAT \
                 (often the ISP's) sits in front of it"
            ));
        }
        match self.observed_ip {
            Some(seen) if seen != wan => Some(format!(
                "the router's internet address is {wan}, but the internet sees {seen}: \
                 another NAT or a VPN sits in the path"
            )),
            _ => None,
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        match (&self.observer, self.observed_ip, &self.observer_error) {
            (Some(relay), Some(ip), _) => {
                let _ = writeln!(out, "Seen from outside (relay {relay}): public IP {ip}");
            }
            (Some(relay), None, Some(e)) => {
                let _ = writeln!(out, "Outside check through relay {relay} failed: {e}");
            }
            _ => {
                let _ = writeln!(
                    out,
                    "No outside check: pass a relay (--relay, --relay-token, --relay-fingerprint \
                     or [relay] in the config) to test reachability from the internet."
                );
            }
        }
        if let Some(router) = &self.router {
            let _ = writeln!(out, "Router: {router}");
        }
        if let Some(wan) = self.router_wan {
            let _ = writeln!(out, "Router's internet address: {wan}");
        }
        out.push('\n');
        for t in &self.tcp {
            let port = format!("TCP {}{} -> port {}", t.public, t.label, t.local);
            let (verdict, note) = match t.reach {
                Some(TcpReach::Open) => ("reachable", String::new()),
                Some(TcpReach::Refused) => {
                    ("REFUSED", " nothing answered behind the router".into())
                }
                Some(TcpReach::Timeout) => ("NO ANSWER", " blocked on the way".into()),
                None => ("not checked", String::new()),
            };
            let listener = match &t.listener {
                Listener::Temporary => " (checked with a temporary listener)".to_owned(),
                Listener::InUse => String::new(),
                Listener::Unavailable(e) => format!(" (cannot listen here: {e})"),
            };
            let _ = writeln!(out, "  {port:<30} {verdict}{note}{listener}");
        }
        for u in &self.udp {
            let port = format!("UDP {} -> port {}", u.public, u.local);
            let verdict = match u.reach {
                Some(UdpReach::Received) => "reachable",
                Some(UdpReach::NotReceived) => "NOT RECEIVED",
                Some(UdpReach::NotTested) => "not tested: in use by the app (stop it to test)",
                None => "not checked",
            };
            let _ = writeln!(out, "  {port:<30} {verdict}");
        }
        if self.udp_skipped > 0 {
            let _ = writeln!(
                out,
                "  ... {} more UDP ports not checked (first {MAX_UDP_PORTS} only)",
                self.udp_skipped
            );
        }

        let mut hints = Vec::new();
        if let Some(cgnat) = self.behind_cgnat() {
            hints.push(format!(
                "{cgnat}. Opening ports on this router cannot help; use relay mode \
                 (`hostip expose --relay ...`) or ask the ISP for a public IP."
            ));
        }
        if self.tcp.iter().any(|t| t.reach == Some(TcpReach::Timeout))
            || self
                .udp
                .iter()
                .any(|u| u.reach == Some(UdpReach::NotReceived))
        {
            hints.push(
                "No answer means the router does not forward the port (turn on UPnP or forward \
                 it manually to this PC), this PC's firewall blocks it, or the ISP does. \
                 If no port works at all, use relay mode."
                    .into(),
            );
        }
        if self.tcp.iter().any(|t| t.reach == Some(TcpReach::Refused)) {
            hints.push(
                "Refused means the router forwards the port to a device where nothing \
                 listens: check that the forwarding points at this PC and the right port."
                    .into(),
            );
        }
        if !hints.is_empty() {
            out.push('\n');
            for hint in hints {
                let _ = writeln!(out, "- {hint}");
            }
        }
        out
    }
}

impl Observer {
    pub fn new(address: &str, token: &str, fingerprint: &str) -> Result<Self> {
        if token.is_empty() || fingerprint.is_empty() {
            return Err(anyhow!("the relay needs both a token and a fingerprint"));
        }
        Ok(Self {
            address: address.to_owned(),
            token: token.to_owned(),
            fingerprint: fingerprint.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Report {
        Report {
            observer: Some("relay.example:7000".into()),
            observed_ip: Some("198.51.100.4".parse().unwrap()),
            router_wan: Some("198.51.100.4".parse().unwrap()),
            tcp: vec![TcpResult {
                public: 443,
                local: 443,
                label: "",
                listener: Listener::InUse,
                reach: Some(TcpReach::Open),
            }],
            udp: vec![UdpResult {
                public: 3478,
                local: 3478,
                reach: Some(UdpReach::NotTested),
            }],
            ..Report::default()
        }
    }

    #[test]
    fn all_good() {
        let r = report();
        assert!(r.all_reachable());
        assert!(r.behind_cgnat().is_none());
        let text = r.render();
        assert!(text.contains("public IP 198.51.100.4"), "{text}");
        assert!(text.contains("TCP 443 -> port 443"), "{text}");
        assert!(!text.contains("- "), "no hints expected: {text}");
    }

    #[test]
    fn detects_cgnat() {
        let mut r = report();
        r.router_wan = Some("100.64.1.2".parse().unwrap());
        assert!(r.behind_cgnat().unwrap().contains("CGNAT"));
        let mut r = report();
        r.router_wan = Some("203.0.113.9".parse().unwrap());
        assert!(r.behind_cgnat().unwrap().contains("another NAT"));
    }

    #[test]
    fn explains_failures() {
        let mut r = report();
        r.tcp[0].reach = Some(TcpReach::Timeout);
        r.udp[0].reach = Some(UdpReach::NotReceived);
        assert!(!r.all_reachable());
        let text = r.render();
        assert!(text.contains("NO ANSWER"), "{text}");
        assert!(text.contains("NOT RECEIVED"), "{text}");
        assert!(text.contains("No answer means"), "{text}");
    }

    #[test]
    fn without_observer_nothing_counts_as_reachable() {
        let mut r = report();
        r.observed_ip = None;
        r.observer = None;
        assert!(!r.all_reachable());
        assert!(r.render().contains("No outside check"));
    }
}
