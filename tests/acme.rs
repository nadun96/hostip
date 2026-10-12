//! Issues real certificates for 127.0.0.1 from Pebble, Let's Encrypt's test CA.
//!
//! Skipped unless Pebble is installed:
//!   go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
//! Set `PEBBLE_BIN` / `PEBBLE_DIR` if it is not in `~/go/bin` and the Go module cache.

use std::net::{IpAddr, Ipv4Addr, TcpListener as StdListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use hostip::acme::{AcmeManager, AcmeOptions, ChallengeKind, HttpChallenges};
use hostip::cert::{self, CertStore};
use hostip::config::{Mode, PortRange, PortSpec};
use hostip::server::Server;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// Locates the Pebble binary and its source directory (for its test certificates).
fn find_pebble() -> Option<(PathBuf, PathBuf)> {
    let bin = std::env::var_os("PEBBLE_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join("go/bin/pebble"));
    let dir = match std::env::var_os("PEBBLE_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => std::fs::read_dir(home().join("go/pkg/mod/github.com/letsencrypt"))
            .ok()?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("pebble"))
            })
            .max()?,
    };
    (bin.exists() && dir.join("test/certs/pebble.minica.pem").exists()).then_some((bin, dir))
}

fn free_port() -> u16 {
    StdListener::bind((LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Pebble {
    child: Child,
    directory: String,
    ca_root: PathBuf,
    http_port: u16,
    tls_port: u16,
    _dir: tempfile::TempDir,
}

impl Drop for Pebble {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn start_pebble() -> Option<Pebble> {
    let Some((bin, src)) = find_pebble() else {
        eprintln!("skipping: Pebble not installed");
        return None;
    };
    let (api, mgmt, http_port, tls_port) = (free_port(), free_port(), free_port(), free_port());
    let dir = tempfile::tempdir().unwrap();
    let certs = src.join("test/certs/localhost");
    let config = serde_json::json!({
        "pebble": {
            "listenAddress": format!("127.0.0.1:{api}"),
            "managementListenAddress": format!("127.0.0.1:{mgmt}"),
            "certificate": certs.join("cert.pem"),
            "privateKey": certs.join("key.pem"),
            "httpPort": http_port,
            "tlsPort": tls_port,
            "ocspResponderURL": "",
            "externalAccountBindingRequired": false,
            "retryAfter": { "authz": 1, "order": 1 },
            "keyAlgorithm": "ecdsa",
            "profiles": {
                "default": { "description": "default", "validityPeriod": 7_776_000 },
                "shortlived": { "description": "short-lived", "validityPeriod": 518_400 }
            }
        }
    });
    let config_path = dir.path().join("pebble.json");
    std::fs::write(&config_path, config.to_string()).unwrap();
    let child = Command::new(bin)
        .arg("-config")
        .arg(&config_path)
        .env("PEBBLE_VA_NOSLEEP", "1")
        .env("PEBBLE_WFE_NONCEREJECT", "0")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if tokio::net::TcpStream::connect((LOCALHOST, api))
            .await
            .is_ok()
        {
            return Some(Pebble {
                child,
                directory: format!("https://127.0.0.1:{api}/dir"),
                ca_root: src.join("test/certs/pebble.minica.pem"),
                http_port,
                tls_port,
                _dir: dir,
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
    panic!("Pebble did not start");
}

struct Setup {
    manager: Arc<AcmeManager>,
    certs: Arc<CertStore>,
    shutdown: CancellationToken,
    _dir: tempfile::TempDir,
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Starts hostip the way a home PC would run it: public 443 (TLS) and 80 (HTTP) forwarded to it.
async fn start_hostip(pebble: &Pebble, kind: ChallengeKind) -> Setup {
    start_hostip_with(pebble, vec![kind], true).await
}

async fn start_hostip_with(pebble: &Pebble, kinds: Vec<ChallengeKind>, http_ok: bool) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let (key, _) = cert::load_or_generate(dir.path(), &["127.0.0.1".into()]).unwrap();
    let certs = CertStore::new(key);
    let challenges = Arc::new(HttpChallenges::default());

    let spec = PortSpec::new(
        Mode::Auto,
        PortRange::single(free_port()),
        Some(PortRange::single(443)),
        Some(pebble.tls_port),
        None,
    )
    .unwrap();
    let mut server = Server::bind(&[spec], LOCALHOST, certs.clone(), "127.0.0.1")
        .await
        .unwrap();
    server
        // Without `http_ok`, port 80 answers from somewhere else, as if the ISP blocked it.
        .bind_http(
            LOCALHOST,
            if http_ok { pebble.http_port } else { 0 },
            challenges.clone(),
            Some(443),
        )
        .await
        .unwrap();
    let shutdown = CancellationToken::new();
    tokio::spawn(server.serve(shutdown.clone()));

    let opts = AcmeOptions {
        directory: pebble.directory.clone(),
        contact: None,
        profile: Some("shortlived".into()),
        ca_root: Some(pebble.ca_root.clone()),
        dir: dir.path().join("acme"),
        challenges: kinds,
        renew_before: None,
    };
    Setup {
        manager: AcmeManager::new(opts, certs.clone(), challenges),
        certs,
        shutdown,
        _dir: dir,
    }
}

fn issuer_of(key: &rustls::sign::CertifiedKey) -> String {
    let (_, parsed) = x509_parser::parse_x509_certificate(&key.cert[0]).unwrap();
    parsed.issuer().to_string()
}

#[tokio::test]
async fn issues_ip_certificate_via_tls_alpn_01() {
    let Some(pebble) = start_pebble().await else {
        return;
    };
    let setup = start_hostip(&pebble, ChallengeKind::TlsAlpn01).await;
    let issued = setup
        .manager
        .issue(Ipv4Addr::LOCALHOST.into())
        .await
        .unwrap();
    assert!(
        issuer_of(&issued.key).contains("Pebble"),
        "{}",
        issuer_of(&issued.key)
    );
    // The short-lived profile was used (Pebble: 6 days, notAfter is inclusive).
    let hours = (issued.not_after - issued.not_before).whole_hours();
    assert!((143..=144).contains(&hours), "lifetime {hours}h");
    assert!(
        setup
            .manager
            .load_stored(Ipv4Addr::LOCALHOST.into())
            .is_some()
    );
}

#[tokio::test]
async fn issues_ip_certificate_via_http_01() {
    let Some(pebble) = start_pebble().await else {
        return;
    };
    let setup = start_hostip(&pebble, ChallengeKind::Http01).await;
    let issued = setup
        .manager
        .issue(Ipv4Addr::LOCALHOST.into())
        .await
        .unwrap();
    assert!(issuer_of(&issued.key).contains("Pebble"));
}

#[tokio::test]
async fn manager_swaps_in_issued_certificate() {
    let Some(pebble) = start_pebble().await else {
        return;
    };
    let setup = start_hostip(&pebble, ChallengeKind::TlsAlpn01).await;
    let self_signed = setup.certs.current();
    let (_tx, rx) = watch::channel(Some(IpAddr::from(Ipv4Addr::LOCALHOST)));
    tokio::spawn(setup.manager.clone().run(rx, setup.shutdown.clone()));

    for _ in 0..300 {
        if !Arc::ptr_eq(&setup.certs.current(), &self_signed) {
            assert!(issuer_of(&setup.certs.current()).contains("Pebble"));
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("certificate was not swapped in");
}

#[tokio::test]
async fn retries_with_the_other_challenge_type() {
    let Some(pebble) = start_pebble().await else {
        return;
    };
    // HTTP-01 is preferred here but port 80 is unreachable; the retry uses TLS-ALPN-01.
    let setup = start_hostip_with(
        &pebble,
        vec![ChallengeKind::Http01, ChallengeKind::TlsAlpn01],
        false,
    )
    .await;
    let ip = Ipv4Addr::LOCALHOST.into();
    assert!(setup.manager.issue(ip).await.is_err());
    let issued = setup.manager.issue(ip).await.unwrap();
    assert!(issuer_of(&issued.key).contains("Pebble"));
}
