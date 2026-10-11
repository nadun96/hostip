//! Public and LAN IP address discovery.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

pub const DEFAULT_SOURCES: &[&str] = &[
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
];

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Asks each source in turn for this machine's public IP and returns the first answer.
pub async fn detect(sources: &[String]) -> Result<IpAddr> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    let mut errors = Vec::new();
    for source in sources {
        match tokio::time::timeout(LOOKUP_TIMEOUT, query(&client, source)).await {
            Ok(Ok(ip)) => return Ok(ip),
            Ok(Err(e)) => errors.push(format!("{source}: {e:#}")),
            Err(_) => errors.push(format!("{source}: timed out")),
        }
    }
    bail!("could not detect the public IP:\n  {}", errors.join("\n  "))
}

async fn query<C>(client: &Client<C, Empty<Bytes>>, source: &str) -> Result<IpAddr>
where
    C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
{
    let resp = client.get(source.parse()?).await?;
    if !resp.status().is_success() {
        bail!("HTTP {}", resp.status());
    }
    let body = Limited::new(resp.into_body(), 256)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .to_bytes();
    let text = std::str::from_utf8(&body)?.trim();
    text.parse()
        .with_context(|| format!("not an IP address: `{text}`"))
}

/// Re-checks the public IP every `interval` and publishes changes (F7, F19).
pub async fn watch(
    sources: Vec<String>,
    interval: Duration,
    tx: watch::Sender<Option<IpAddr>>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(interval) => {}
        }
        match detect(&sources).await {
            Ok(ip) => {
                tx.send_if_modified(|current| {
                    if *current == Some(ip) {
                        return false;
                    }
                    info!(
                        "public IP changed: {} -> {ip}",
                        current.map_or("none".into(), |c| c.to_string())
                    );
                    *current = Some(ip);
                    true
                });
            }
            // Transient: keep the last known IP.
            Err(e) => debug!("public IP check failed: {e:#}"),
        }
    }
}

/// The address this machine uses on the LAN (no packets are sent).
pub fn lan_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

/// True for addresses that cannot be reached from the internet (RFC 1918, CGNAT, loopback, ...).
pub fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_addresses() {
        for ip in [
            "10.0.0.1",
            "192.168.1.5",
            "100.64.1.1",
            "127.0.0.1",
            "fd00::1",
        ] {
            assert!(is_non_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["203.0.113.7", "100.128.0.1", "2001:db8::1"] {
            assert!(!is_non_public(ip.parse().unwrap()), "{ip}");
        }
    }
}
