//! Relay mode end to end: visitor -> relay -> tunnel -> home hostip -> local app.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use hostip::cert::{self, CertStore};
use hostip::config::{Mode, PortRange, PortSpec};
use hostip::relay::{self, ClientOptions, RelayOptions};
use hostip::server::Server;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn free_tcp() -> u16 {
    std::net::TcpListener::bind((LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp() -> u16 {
    std::net::UdpSocket::bind((LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start_app() -> u16 {
    let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(|req: Request<Incoming>| async move {
                    let xff = req.headers().get("x-forwarded-for").cloned();
                    Ok::<_, Infallible>(Response::new(Full::<Bytes>::from(format!(
                        "via relay, xff={}",
                        xff.as_ref().and_then(|v| v.to_str().ok()).unwrap_or("-")
                    ))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    port
}

async fn start_udp_echo() -> u16 {
    let socket = UdpSocket::bind((LOCALHOST, 0)).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = socket.recv_from(&mut buf).await.unwrap();
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = socket.send_to(&reply, from).await;
        }
    });
    port
}

struct Setup {
    public_tcp: u16,
    public_udp: u16,
    roots: rustls::RootCertStore,
    shutdown: CancellationToken,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

async fn start(token_for_home: &str, fingerprint_override: Option<String>) -> Setup {
    let shutdown = CancellationToken::new();
    let (relay_dir, home_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());

    // The relay, on a "public" machine.
    let control = free_tcp();
    let (tls, fingerprint) = relay::relay_tls(relay_dir.path()).unwrap();
    let opts = RelayOptions {
        listen: SocketAddr::new(LOCALHOST, control),
        token: "relay-secret".into(),
        public_ip: Some(LOCALHOST),
        allowed_ports: vec![PortRange {
            start: 1024,
            end: 65535,
        }],
    };
    tokio::spawn(relay::run_relay(opts, tls, shutdown.clone()));

    // Home: hostip in front of a web app and a UDP app, connected out to the relay.
    let (app, udp_app) = (start_app().await, start_udp_echo().await);
    let (public_tcp, public_udp) = (free_tcp(), free_udp());
    let (key, info) = cert::load_or_generate(home_dir.path(), &["127.0.0.1".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(&info.cert_path).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let spec = PortSpec::new(
        Mode::Auto,
        PortRange::single(app),
        Some(PortRange::single(public_tcp)),
        Some(free_tcp()),
        None,
    )
    .unwrap();
    let server = Server::bind(&[spec], LOCALHOST, CertStore::new(key), "127.0.0.1")
        .await
        .unwrap();
    let injector = server.injector(shutdown.clone());
    tokio::spawn(server.serve(shutdown.clone()));
    let client = ClientOptions {
        relay: format!("127.0.0.1:{control}"),
        token: token_for_home.into(),
        fingerprint: fingerprint_override.unwrap_or(fingerprint),
        tcp_ports: vec![public_tcp],
        udp: vec![(PortRange::single(public_udp), udp_app)],
    };
    tokio::spawn(relay::run_client(client, injector, shutdown.clone()));

    Setup {
        public_tcp,
        public_udp,
        roots,
        shutdown,
        _dirs: (relay_dir, home_dir),
    }
}

/// HTTPS GET through the relay's public port, retried while the tunnel comes up.
async fn get_via_relay(setup: &Setup, tries: usize) -> Option<String> {
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(setup.roots.clone())
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    for _ in 0..tries {
        let attempt = async {
            let tcp = TcpStream::connect((LOCALHOST, setup.public_tcp))
                .await
                .ok()?;
            let name = ServerName::IpAddress(Ipv4Addr::LOCALHOST.into());
            let tls = connector.connect(name, tcp).await.ok()?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .ok()?;
            tokio::spawn(conn);
            let req = Request::get("/")
                .header("host", "x")
                .body(Full::<Bytes>::default())
                .ok()?;
            let resp = sender.send_request(req).await.ok()?;
            let body = resp.into_body().collect().await.ok()?.to_bytes();
            Some(String::from_utf8_lossy(&body).into_owned())
        };
        if let Ok(Some(body)) = tokio::time::timeout(Duration::from_secs(2), attempt).await {
            return Some(body);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

#[tokio::test]
async fn serves_https_and_udp_through_the_relay() {
    let setup = start("relay-secret", None).await;
    let body = get_via_relay(&setup, 50)
        .await
        .expect("no response through the relay");
    assert_eq!(body, "via relay, xff=127.0.0.1");

    let visitor = UdpSocket::bind((LOCALHOST, 0)).await.unwrap();
    let mut buf = [0u8; 64];
    let mut echoed = None;
    for _ in 0..50 {
        visitor
            .send_to(b"media", (LOCALHOST, setup.public_udp))
            .await
            .unwrap();
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(200), visitor.recv_from(&mut buf)).await
        {
            echoed = Some(buf[..n].to_vec());
            break;
        }
    }
    assert_eq!(echoed.as_deref(), Some(&b"echo:media"[..]));
}

#[tokio::test]
async fn refuses_a_wrong_token() {
    let setup = start("wrong", None).await;
    assert!(get_via_relay(&setup, 10).await.is_none());
}

#[tokio::test]
async fn refuses_a_relay_with_another_certificate() {
    let setup = start("relay-secret", Some("00".repeat(32))).await;
    assert!(get_via_relay(&setup, 10).await.is_none());
}
