//! A small status file written while hostip runs, read by `hostip status` (F14).
//! Useful above all for the background service, which has no console.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::acme;
use crate::cert::CertStore;

const WRITE_INTERVAL: Duration = Duration::from_secs(30);
/// A status file older than this means hostip is not running.
pub const STALE_AFTER: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Status {
    pub pid: u32,
    pub updated: i64,
    pub public_ip: Option<IpAddr>,
    /// `direct` or `relay <address>`.
    pub mode: String,
    pub urls: Vec<String>,
    pub certificate: Option<CertificateStatus>,
    /// Latest Let's Encrypt attempt, when ACME is on.
    #[serde(default)]
    pub acme: Option<AcmeStatus>,
    /// Visitor connections open right now.
    #[serde(default)]
    pub open_connections: usize,
}

/// Outcome of the latest Let's Encrypt attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AcmeStatus {
    pub at: i64,
    /// `None` on success.
    pub error: Option<String>,
    /// Next renewal or retry.
    pub next: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CertificateStatus {
    pub subject: String,
    pub issuer: String,
    pub not_after: i64,
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join("status.json")
}

fn certificate_status(certs: &CertStore) -> Option<CertificateStatus> {
    let key = certs.current();
    let (_, cert) = x509_parser::parse_x509_certificate(key.cert.first()?).ok()?;
    let names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .map(|n| match n {
                    x509_parser::extensions::GeneralName::IPAddress(bytes) => match bytes.len() {
                        4 => <[u8; 4]>::try_from(*bytes)
                            .map(|b| IpAddr::from(b).to_string())
                            .unwrap_or_default(),
                        16 => <[u8; 16]>::try_from(*bytes)
                            .map(|b| IpAddr::from(b).to_string())
                            .unwrap_or_default(),
                        _ => String::new(),
                    },
                    x509_parser::extensions::GeneralName::DNSName(name) => (*name).to_owned(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    Some(CertificateStatus {
        subject: names,
        issuer: cert.issuer().to_string(),
        not_after: cert.validity().not_after.timestamp(),
    })
}

/// What the status file reports, and where it comes from.
pub struct Sources {
    /// `direct` or `relay <address>`.
    pub mode: String,
    pub urls: Box<dyn Fn(Option<IpAddr>) -> Vec<String> + Send>,
    pub certs: Arc<CertStore>,
    pub ip: watch::Receiver<Option<IpAddr>>,
    pub acme: Option<watch::Receiver<Option<acme::Outcome>>>,
    pub open_connections: Box<dyn Fn() -> usize + Send>,
}

/// Rewrites the status file every 30 seconds and whenever the IP, the certificate
/// or the Let's Encrypt state changes; removes it on shutdown.
pub async fn write_periodically(file: PathBuf, mut src: Sources, shutdown: CancellationToken) {
    let mut cert_changes = src.certs.subscribe();
    let mut acme_rx = src.acme.take();
    loop {
        let public_ip = *src.ip.borrow_and_update();
        let acme = acme_rx.as_mut().and_then(|rx| {
            rx.borrow_and_update().as_ref().map(|o| AcmeStatus {
                at: o.at.unix_timestamp(),
                error: o.error.clone(),
                next: o.next.unix_timestamp(),
            })
        });
        let status = Status {
            pid: std::process::id(),
            updated: OffsetDateTime::now_utc().unix_timestamp(),
            public_ip,
            mode: src.mode.clone(),
            urls: (src.urls)(public_ip),
            certificate: certificate_status(&src.certs),
            acme,
            open_connections: (src.open_connections)(),
        };
        if let Ok(json) = serde_json::to_vec_pretty(&status) {
            if let Some(dir) = file.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let tmp = file.with_extension("tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, &file);
            }
        }
        // A closed channel never changes again; it must not wake the loop.
        let ip_changed = async {
            if src.ip.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        let acme_changed = async {
            let open = match acme_rx.as_mut() {
                Some(rx) => rx.changed().await.is_ok(),
                None => false,
            };
            if !open {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            _ = shutdown.cancelled() => {
                let _ = std::fs::remove_file(&file);
                return;
            }
            _ = tokio::time::sleep(WRITE_INTERVAL) => {}
            _ = ip_changed => {}
            _ = cert_changes.changed() => {}
            _ = acme_changed => {}
        }
    }
}

pub fn read(file: &Path) -> Result<Status> {
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("hostip is not running (no {})", file.display()))?;
    Ok(serde_json::from_str(&text)?)
}

impl Status {
    pub fn is_running(&self, now: i64) -> bool {
        now - self.updated <= STALE_AFTER.as_secs() as i64
    }
}

/// Human-readable report; `now` is passed in for testability.
pub fn render(status: &Status, now: i64) -> String {
    let age = now - status.updated;
    let mut out = String::new();
    if !status.is_running(now) {
        out.push_str(&format!(
            "hostip is NOT running (last seen {} min ago, pid {})\n",
            age / 60,
            status.pid
        ));
    } else {
        out.push_str(&format!(
            "hostip is running (pid {}, {})\n",
            status.pid, status.mode
        ));
    }
    out.push_str(&format!(
        "Public IP:   {}\n",
        status
            .public_ip
            .map_or("unknown".into(), |ip| ip.to_string())
    ));
    for url in &status.urls {
        out.push_str(&format!("Visitors:    {url}\n"));
    }
    if let Some(cert) = &status.certificate {
        let days = (cert.not_after - now) as f64 / 86_400.0;
        let expiry = OffsetDateTime::from_unix_timestamp(cert.not_after)
            .map(|t| t.to_string())
            .unwrap_or_default();
        out.push_str(&format!(
            "Certificate: {} (issued by {}), expires {expiry} ({days:.1} days)\n",
            cert.subject, cert.issuer
        ));
    }
    if let Some(acme) = &status.acme {
        let at = datetime(acme.at);
        let next = if acme.next > now {
            format!(
                "{} (in {:.1} days)",
                datetime(acme.next),
                days(acme.next - now)
            )
        } else {
            "due now".to_owned()
        };
        match &acme.error {
            None => out.push_str(&format!(
                "Renewal:     last check {at} succeeded; next {next}\n"
            )),
            Some(e) => out.push_str(&format!("Renewal:     FAILED {at}: {e}; retry {next}\n")),
        }
    }
    if status.is_running(now) {
        out.push_str(&format!("Connections: {} open\n", status.open_connections));
    }
    out
}

fn datetime(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .map(|t| t.to_string())
        .unwrap_or_default()
}

fn days(secs: i64) -> f64 {
    secs as f64 / 86_400.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(updated: i64) -> Status {
        Status {
            pid: 42,
            updated,
            public_ip: Some("203.0.113.7".parse().unwrap()),
            mode: "direct".into(),
            urls: vec!["https://203.0.113.7".into()],
            certificate: Some(CertificateStatus {
                subject: "203.0.113.7".into(),
                issuer: "CN=E8, O=Let's Encrypt".into(),
                not_after: updated + 4 * 86_400,
            }),
            acme: Some(AcmeStatus {
                at: updated - 60,
                error: None,
                next: updated + 2 * 86_400,
            }),
            open_connections: 7,
        }
    }

    #[test]
    fn renders_running_and_stale_status() {
        let now = 1_800_000_000;
        let running = render(&sample(now - 10), now);
        assert!(
            running.starts_with("hostip is running (pid 42, direct)"),
            "{running}"
        );
        assert!(running.contains("https://203.0.113.7"));
        assert!(running.contains("4.0 days"), "{running}");
        assert!(running.contains("succeeded; next"), "{running}");
        assert!(running.contains("Connections: 7 open"), "{running}");
        let stale = render(&sample(now - 600), now);
        assert!(stale.starts_with("hostip is NOT running"), "{stale}");
        assert!(!stale.contains("Connections"), "{stale}");
    }

    #[test]
    fn renders_a_failed_renewal() {
        let now = 1_800_000_000;
        let mut s = sample(now - 10);
        s.acme = Some(AcmeStatus {
            at: now - 60,
            error: Some("connection refused".into()),
            next: now + 600,
        });
        let text = render(&s, now);
        assert!(text.contains("FAILED"), "{text}");
        assert!(text.contains("connection refused; retry"), "{text}");
    }

    #[test]
    fn reads_files_from_older_versions() {
        // Written before `acme` and `open_connections` existed.
        let old = r#"{"pid":1,"updated":5,"public_ip":null,"mode":"direct","urls":[],"certificate":null}"#;
        let s: Status = serde_json::from_str(old).unwrap();
        assert_eq!(s.acme, None);
        assert_eq!(s.open_connections, 0);
    }

    #[tokio::test]
    async fn writes_and_removes_the_status_file() {
        let dir = tempfile::tempdir().unwrap();
        let (key, _) = crate::cert::load_or_generate(dir.path(), &["203.0.113.7".into()]).unwrap();
        let file = path(dir.path());
        let (_tx, rx) = watch::channel(Some("203.0.113.7".parse().unwrap()));
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(write_periodically(
            file.clone(),
            Sources {
                mode: "direct".into(),
                urls: Box::new(|ip| vec![format!("https://{}", ip.unwrap())]),
                certs: CertStore::new(key),
                ip: rx,
                acme: None,
                open_connections: Box::new(|| 3),
            },
            shutdown.clone(),
        ));
        for _ in 0..50 {
            if file.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let status = read(&file).unwrap();
        assert_eq!(status.urls, ["https://203.0.113.7"]);
        assert_eq!(status.certificate.unwrap().subject, "203.0.113.7");
        assert_eq!(status.open_connections, 3);
        shutdown.cancel();
        task.await.unwrap();
        assert!(!file.exists());
    }
}
