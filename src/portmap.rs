//! Automatic router port mapping (F12, F26, F35): UPnP-IGD first, then PCP / NAT-PMP.
//!
//! Mappings are leased, renewed periodically (which also restores them after a
//! router reboot) and removed again on shutdown.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use crab_nat::{InternetProtocol, PortMappingOptions};
use igd_next::aio::Gateway;
use igd_next::aio::tokio::Tokio;
use igd_next::{AddPortError, PortMappingProtocol, SearchOptions};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::{Mode, PortSpec};

/// Requested lease; mappings are renewed at half of it.
const LEASE_SECS: u32 = 3600;
const RENEW_INTERVAL: Duration = Duration::from_secs(LEASE_SECS as u64 / 2);
/// Routers commonly cap UPnP mappings at a few dozen to a few hundred entries.
pub const MAX_MAPPINGS: usize = 128;
const DESCRIPTION: &str = "hostip";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        })
    }
}

/// One router mapping: public `external` port -> this PC's `internal` port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    pub proto: Proto,
    pub external: u16,
    pub internal: u16,
}

impl fmt::Display for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} -> {}", self.proto, self.external, self.internal)
    }
}

/// The mappings needed for `specs` (plus public 80 -> `http_listen`). UDP ranges that
/// would exceed [`MAX_MAPPINGS`] are returned separately for manual forwarding.
pub fn plan(specs: &[PortSpec], http_listen: Option<u16>) -> (Vec<Mapping>, Vec<PortSpec>) {
    let mut mappings = Vec::new();
    let mut too_large = Vec::new();
    for spec in specs.iter().filter(|s| s.mode != Mode::Udp) {
        if let Some(listen) = spec.listen {
            mappings.push(Mapping {
                proto: Proto::Tcp,
                external: spec.public.start,
                internal: listen,
            });
        }
    }
    if let Some(port) = http_listen {
        mappings.push(Mapping {
            proto: Proto::Tcp,
            external: 80,
            internal: port,
        });
    }
    for spec in specs.iter().filter(|s| s.mode == Mode::Udp) {
        if mappings.len() + spec.local.count() as usize > MAX_MAPPINGS {
            too_large.push(spec.clone());
            continue;
        }
        for offset in 0..=(spec.local.end - spec.local.start) {
            mappings.push(Mapping {
                proto: Proto::Udp,
                external: spec.public.start + offset,
                internal: spec.local.start + offset,
            });
        }
    }
    (mappings, too_large)
}

#[derive(Debug, Clone)]
pub struct DiscoverOptions {
    /// Where to send the SSDP search; default is the UPnP multicast group.
    pub ssdp_target: Option<SocketAddr>,
    pub search_timeout: Duration,
    /// Fall back to PCP / NAT-PMP at the default gateway when UPnP is not found.
    pub try_pcp: bool,
    /// Gateways trusted even though they are not the SSDP responder (e.g. loopback in tests).
    pub allowed_gateway_ips: Vec<IpAddr>,
}

impl Default for DiscoverOptions {
    fn default() -> Self {
        Self {
            ssdp_target: None,
            search_timeout: Duration::from_secs(3),
            try_pcp: true,
            allowed_gateway_ips: Vec::new(),
        }
    }
}

enum Backend {
    Upnp {
        gateway: Gateway<Tokio>,
        /// 0 = permanent (some routers support nothing else).
        lease: u32,
    },
    Pcp {
        gateway: Ipv4Addr,
        handles: Vec<crab_nat::PortMapping>,
    },
}

/// Outcome of [`PortMapper::map_all`].
#[derive(Debug, Default)]
pub struct MapReport {
    pub mapped: Vec<Mapping>,
    pub failed: Vec<(Mapping, String)>,
}

pub struct PortMapper {
    lan_ip: Ipv4Addr,
    backend: Backend,
    active: Vec<Mapping>,
}

impl PortMapper {
    /// Finds the router: UPnP-IGD via SSDP, otherwise PCP / NAT-PMP at the default gateway.
    pub async fn discover(lan_ip: Ipv4Addr, opts: &DiscoverOptions) -> Result<Self> {
        let mut search = SearchOptions::default();
        search.timeout = Some(opts.search_timeout);
        search.single_search_timeout = Some(opts.search_timeout);
        search.allowed_gateway_ips = opts.allowed_gateway_ips.clone();
        if let Some(target) = opts.ssdp_target {
            search.broadcast_address = target;
        }
        let upnp_error = match igd_next::aio::tokio::search_gateway(search).await {
            Ok(gateway) => {
                return Ok(Self {
                    lan_ip,
                    backend: Backend::Upnp {
                        gateway,
                        lease: LEASE_SECS,
                    },
                    active: Vec::new(),
                });
            }
            Err(e) => e,
        };
        if !opts.try_pcp {
            return Err(anyhow!("no UPnP router found ({upnp_error})"));
        }
        let gateway = default_gateway().with_context(|| {
            format!("no UPnP router found ({upnp_error}) and no default gateway for PCP/NAT-PMP")
        })?;
        Ok(Self {
            lan_ip,
            backend: Backend::Pcp {
                gateway,
                handles: Vec::new(),
            },
            active: Vec::new(),
        })
    }

    pub fn method(&self) -> &'static str {
        match self.backend {
            Backend::Upnp { .. } => "UPnP",
            Backend::Pcp { .. } => "PCP/NAT-PMP",
        }
    }

    /// The router's WAN address, if it reports one (UPnP only).
    pub async fn external_ip(&self) -> Option<IpAddr> {
        match &self.backend {
            Backend::Upnp { gateway, .. } => gateway.get_external_ip().await.ok(),
            Backend::Pcp { .. } => None,
        }
    }

    pub async fn map_all(&mut self, mappings: &[Mapping]) -> MapReport {
        let mut report = MapReport::default();
        for &m in mappings {
            match self.map_one(m).await {
                Ok(()) => {
                    self.active.push(m);
                    report.mapped.push(m);
                }
                Err(e) => report.failed.push((m, e)),
            }
        }
        report
    }

    async fn map_one(&mut self, m: Mapping) -> Result<(), String> {
        let lan_ip = self.lan_ip;
        match &mut self.backend {
            Backend::Upnp { gateway, lease } => {
                let local = SocketAddr::V4(SocketAddrV4::new(lan_ip, m.internal));
                let mut result = gateway
                    .add_port(upnp_proto(m.proto), m.external, local, *lease, DESCRIPTION)
                    .await;
                if matches!(result, Err(AddPortError::OnlyPermanentLeasesSupported)) {
                    *lease = 0;
                    result = gateway
                        .add_port(upnp_proto(m.proto), m.external, local, 0, DESCRIPTION)
                        .await;
                }
                result.map_err(|e| describe_upnp_error(&e, m))
            }
            Backend::Pcp { gateway, handles } => {
                let (Some(internal), Some(external)) =
                    (NonZeroU16::new(m.internal), NonZeroU16::new(m.external))
                else {
                    return Err("port 0".into());
                };
                let options = PortMappingOptions {
                    external_port: Some(external),
                    lifetime_seconds: Some(LEASE_SECS),
                    timeout_config: None,
                };
                let handle = crab_nat::PortMapping::new(
                    (*gateway).into(),
                    lan_ip.into(),
                    pcp_proto(m.proto),
                    internal,
                    options,
                )
                .await
                .map_err(|e| describe_pcp_error(&e, *gateway))?;
                if handle.external_port() != external {
                    let granted = handle.external_port();
                    let _ = handle.try_drop().await;
                    return Err(format!(
                        "router offered external port {granted} instead of {external}"
                    ));
                }
                handles.push(handle);
                Ok(())
            }
        }
    }

    /// Refreshes every active mapping (also restores them after a router reboot).
    pub async fn renew(&mut self) {
        let lan_ip = self.lan_ip;
        match &mut self.backend {
            Backend::Upnp { gateway, lease } => {
                for m in &self.active {
                    let local = SocketAddr::V4(SocketAddrV4::new(lan_ip, m.internal));
                    if let Err(e) = gateway
                        .add_port(upnp_proto(m.proto), m.external, local, *lease, DESCRIPTION)
                        .await
                    {
                        warn!(
                            "renewing port mapping {m} failed: {}",
                            describe_upnp_error(&e, *m)
                        );
                    }
                }
            }
            Backend::Pcp { handles, .. } => {
                for handle in handles.iter_mut() {
                    if let Err(e) = handle.renew().await {
                        warn!(
                            "renewing port mapping for port {} failed: {e:?}",
                            handle.external_port()
                        );
                    }
                }
            }
        }
    }

    /// Removes every mapping this process created.
    pub async fn remove_all(&mut self) {
        match &mut self.backend {
            Backend::Upnp { gateway, .. } => {
                for m in self.active.drain(..) {
                    if let Err(e) = gateway.remove_port(upnp_proto(m.proto), m.external).await {
                        debug!("removing port mapping {m} failed: {e}");
                    }
                }
            }
            Backend::Pcp { handles, .. } => {
                self.active.clear();
                for handle in handles.drain(..) {
                    if let Err((e, _)) = handle.try_drop().await {
                        debug!("removing port mapping failed: {e:?}");
                    }
                }
            }
        }
    }
}

/// Maps the ports, keeps them renewed until `shutdown`, then removes them.
pub async fn run(
    lan_ip: Ipv4Addr,
    mappings: Vec<Mapping>,
    opts: DiscoverOptions,
    shutdown: CancellationToken,
) {
    if mappings.is_empty() {
        return;
    }
    let mut mapper = match PortMapper::discover(lan_ip, &opts).await {
        Ok(mapper) => mapper,
        Err(e) => {
            warn!(
                "automatic port mapping unavailable: {e:#}; forward the ports listed above manually"
            );
            return;
        }
    };
    let method = mapper.method();
    if let Some(wan) = mapper.external_ip().await
        && crate::publicip::is_non_public(wan)
    {
        warn!(
            "the router's internet address {wan} is private or CGNAT (double NAT): \
             mapping ports on this router alone will not make this PC reachable"
        );
    }
    let report = mapper.map_all(&mappings).await;
    for m in &report.mapped {
        info!("{method}: mapped {m}");
    }
    let same_error = report
        .failed
        .first()
        .filter(|(_, first)| report.failed.iter().all(|(_, e)| e == first));
    match same_error {
        Some((_, e)) if report.mapped.is_empty() => {
            warn!("automatic port mapping failed: {e}; forward the ports listed above manually");
        }
        _ => {
            for (m, e) in &report.failed {
                warn!("{method}: could not map {m}: {e}; forward it manually");
            }
        }
    }
    if report.mapped.is_empty() {
        return;
    }
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(RENEW_INTERVAL) => mapper.renew().await,
        }
    }
    mapper.remove_all().await;
    info!("{method}: removed port mappings");
}

fn upnp_proto(proto: Proto) -> PortMappingProtocol {
    match proto {
        Proto::Tcp => PortMappingProtocol::TCP,
        Proto::Udp => PortMappingProtocol::UDP,
    }
}

fn pcp_proto(proto: Proto) -> InternetProtocol {
    match proto {
        Proto::Tcp => InternetProtocol::Tcp,
        Proto::Udp => InternetProtocol::Udp,
    }
}

fn describe_upnp_error(e: &AddPortError, m: Mapping) -> String {
    match e {
        AddPortError::PortInUse => "the router already maps this port to another device".into(),
        AddPortError::SamePortValuesRequired => format!(
            "the router only maps a port to the same port number; set `listen = {}` for it \
             (the app then needs a different local port)",
            m.external
        ),
        AddPortError::ActionNotAuthorized => "the router refused (UPnP may be read-only)".into(),
        other => other.to_string(),
    }
}

fn describe_pcp_error(e: &crab_nat::MappingFailure, gateway: Ipv4Addr) -> String {
    let text = format!("{e:?}");
    if text.contains("Socket") || text.contains("Timeout") || text.contains("NoResponse") {
        format!("the router at {gateway} does not answer PCP/NAT-PMP")
    } else {
        text
    }
}

fn default_gateway() -> Result<Ipv4Addr> {
    let gateway = netdev::get_default_gateway().map_err(|e| anyhow!(e))?;
    gateway
        .ipv4
        .first()
        .copied()
        .context("default gateway has no IPv4 address")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_tcp_http_and_udp_mappings() {
        let specs = [
            PortSpec::parse_cli("3000:443").unwrap(),
            PortSpec::parse_cli("8080").unwrap(),
            PortSpec::parse_cli("udp:3478").unwrap(),
            PortSpec::parse_cli("udp:50000-50002").unwrap(),
        ];
        let (mappings, too_large) = plan(&specs, Some(80));
        let shown: Vec<String> = mappings.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown,
            [
                "TCP 443 -> 443",
                "TCP 8080 -> 18080",
                "TCP 80 -> 80",
                "UDP 3478 -> 3478",
                "UDP 50000 -> 50000",
                "UDP 50001 -> 50001",
                "UDP 50002 -> 50002",
            ]
        );
        assert!(too_large.is_empty());
    }

    #[test]
    fn leaves_huge_udp_ranges_for_manual_forwarding() {
        let specs = [PortSpec::parse_cli("udp:50000-60000").unwrap()];
        let (mappings, too_large) = plan(&specs, None);
        assert!(mappings.is_empty());
        assert_eq!(too_large.len(), 1);
    }
}
