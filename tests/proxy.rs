//! End-to-end tests: TLS client -> hostip -> local upstream app.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use hostip::access::{AccessConfig, AuthConfig, Guard, Limits};
use hostip::cert::{self, CertStore};
use hostip::config::{Mode, PortRange, PortSpec};
use hostip::server::{Server, ServerOptions};

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A small HTTP app standing in for the user's real app.
async fn start_http_upstream() -> u16 {
    let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| upstream_handler(req, port));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    port
}

async fn upstream_handler(
    mut req: Request<Incoming>,
    port: u16,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_owned()
    };
    let resp = match req.uri().path() {
        "/echo" => Response::new(Full::from(format!(
            "path={} host={} xff={} proto={}",
            req.uri().path_and_query().unwrap(),
            header("host"),
            header("x-forwarded-for"),
            header("x-forwarded-proto"),
        ))),
        "/headers" => Response::new(Full::from(format!(
            "authorization={} cookie={}",
            header("authorization"),
            header("cookie"),
        ))),
        "/redirect" => Response::builder()
            .status(StatusCode::FOUND)
            .header("location", format!("http://localhost:{port}/target"))
            .body(Full::default())
            .unwrap(),
        "/upload" => {
            let body = req.into_body().collect().await.unwrap().to_bytes();
            Response::new(Full::from(format!("received {} bytes", body.len())))
        }
        "/ws" => {
            let upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                let mut io = TokioIo::new(upgrade.await.unwrap());
                let mut buf = [0u8; 64];
                let n = io.read(&mut buf).await.unwrap();
                io.write_all(&buf[..n]).await.unwrap();
            });
            Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header("connection", "upgrade")
                .header("upgrade", "echo")
                .body(Full::default())
                .unwrap()
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::default())
            .unwrap(),
    };
    Ok(resp)
}

/// A non-HTTP app: echoes whatever it receives.
async fn start_echo_upstream() -> u16 {
    let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

struct Hostip {
    addr: SocketAddr,
    roots: rustls::RootCertStore,
    shutdown: CancellationToken,
    _dir: tempfile::TempDir,
}

impl Drop for Hostip {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

async fn start_hostip(mode: Mode, upstream_port: u16) -> Hostip {
    start_hostip_with(
        mode,
        upstream_port,
        AccessConfig::default(),
        Limits::default(),
    )
    .await
}

async fn start_hostip_with(
    mode: Mode,
    upstream_port: u16,
    access: AccessConfig,
    limits: Limits,
) -> Hostip {
    let dir = tempfile::tempdir().unwrap();
    let (key, info) =
        cert::load_or_generate(dir.path(), &["localhost".into(), "127.0.0.1".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(&info.cert_path).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }

    let mut spec =
        PortSpec::new(mode, PortRange::single(upstream_port), None, Some(0), None).unwrap();
    spec.access = access;
    let options = ServerOptions {
        guard: Guard::new(limits),
        access_log: false,
    };
    let server = Server::bind_with(
        &[spec],
        LOCALHOST,
        CertStore::new(key),
        "127.0.0.1",
        options,
    )
    .await
    .unwrap();
    let addr = server.local_addrs()[0].1;
    let shutdown = CancellationToken::new();
    tokio::spawn(server.serve(shutdown.clone()));
    Hostip {
        addr,
        roots,
        shutdown,
        _dir: dir,
    }
}

impl Hostip {
    async fn tls(&self, alpn: &[&[u8]]) -> TlsStream<TcpStream> {
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(self.roots.clone())
        .with_no_client_auth();
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        let tcp = TcpStream::connect(self.addr).await.unwrap();
        let name = ServerName::IpAddress(Ipv4Addr::LOCALHOST.into());
        TlsConnector::from(Arc::new(cfg))
            .connect(name, tcp)
            .await
            .unwrap()
    }

    async fn http1(&self) -> hyper::client::conn::http1::SendRequest<Full<Bytes>> {
        let tls = self.tls(&[b"http/1.1"]).await;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(conn.with_upgrades());
        sender
    }
}

async fn body_text(resp: Response<Incoming>) -> String {
    String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn get(host: &str, path: &str) -> Request<Full<Bytes>> {
    Request::get(path)
        .header("host", host)
        .body(Full::default())
        .unwrap()
}

#[tokio::test]
async fn proxies_http1_with_forwarded_headers() {
    let up = start_http_upstream().await;
    let hostip = start_hostip(Mode::Auto, up).await;
    let mut client = hostip.http1().await;

    let mut req = get("203.0.113.7:3000", "/echo?x=1");
    req.headers_mut()
        .insert("x-forwarded-for", "6.6.6.6".parse().unwrap());
    let resp = client.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_text(resp).await,
        "path=/echo?x=1 host=203.0.113.7:3000 xff=127.0.0.1 proto=https"
    );
}

#[tokio::test]
async fn proxies_http2() {
    let up = start_http_upstream().await;
    let hostip = start_hostip(Mode::Auto, up).await;
    let tls = hostip.tls(&[b"h2"]).await;
    let (mut client, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);

    let req = Request::get("https://203.0.113.7:3000/echo")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.send_request(req).await.unwrap();
    assert_eq!(
        body_text(resp).await,
        "path=/echo host=203.0.113.7:3000 xff=127.0.0.1 proto=https"
    );
}

#[tokio::test]
async fn streams_request_bodies() {
    let up = start_http_upstream().await;
    let hostip = start_hostip(Mode::Https, up).await;
    let mut client = hostip.http1().await;
    let req = Request::post("/upload")
        .header("host", "x")
        .body(Full::from(vec![7u8; 5 * 1024 * 1024]))
        .unwrap();
    let resp = client.send_request(req).await.unwrap();
    assert_eq!(
        body_text(resp).await,
        format!("received {} bytes", 5 * 1024 * 1024)
    );
}

#[tokio::test]
async fn rewrites_localhost_redirects() {
    let up = start_http_upstream().await;
    let hostip = start_hostip(Mode::Auto, up).await;
    let mut client = hostip.http1().await;
    let resp = client
        .send_request(get("203.0.113.7:3000", "/redirect"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        resp.headers()["location"],
        "https://203.0.113.7:3000/target"
    );
}

#[tokio::test]
async fn passes_protocol_upgrades_through() {
    let up = start_http_upstream().await;
    let hostip = start_hostip(Mode::Auto, up).await;
    let mut client = hostip.http1().await;
    let req = Request::get("/ws")
        .header("host", "x")
        .header("connection", "upgrade")
        .header("upgrade", "echo")
        .body(Full::default())
        .unwrap();
    let resp = client.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    let mut io = TokioIo::new(hyper::upgrade::on(resp).await.unwrap());
    io.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    io.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn auto_mode_pipes_non_http_protocols() {
    let up = start_echo_upstream().await;
    let hostip = start_hostip(Mode::Auto, up).await;
    let mut tls = hostip.tls(&[]).await;
    tls.write_all(b"\x00\x01custom-protocol").await.unwrap();
    let mut buf = [0u8; 17];
    tls.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"\x00\x01custom-protocol");
}

#[tokio::test]
async fn tls_mode_pipes_raw_bytes() {
    let up = start_echo_upstream().await;
    let hostip = start_hostip(Mode::Tls, up).await;
    let mut tls = hostip.tls(&[]).await;
    tls.write_all(b"GET looks like http but is piped")
        .await
        .unwrap();
    let mut buf = [0u8; 32];
    tls.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"GET looks like http but is piped");
}

#[tokio::test]
async fn tcp_mode_pipes_without_tls() {
    let up = start_echo_upstream().await;
    let hostip = start_hostip(Mode::Tcp, up).await;
    let mut tcp = TcpStream::connect(hostip.addr).await.unwrap();
    tcp.write_all(b"plain").await.unwrap();
    let mut buf = [0u8; 5];
    tcp.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"plain");
}

#[tokio::test]
async fn redirects_plain_http_to_https() {
    let up = start_http_upstream().await;
    let hostip = start_hostip(Mode::Auto, up).await;
    let mut tcp = TcpStream::connect(hostip.addr).await.unwrap();
    tcp.write_all(b"GET /page HTTP/1.1\r\nHost: 203.0.113.7:3000\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    tcp.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 308"), "{out}");
    assert!(
        out.contains("Location: https://203.0.113.7:3000/page\r\n"),
        "{out}"
    );
}

#[tokio::test]
async fn reports_bad_gateway_when_app_is_down() {
    let unused = TcpListener::bind((LOCALHOST, 0))
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let hostip = start_hostip(Mode::Auto, unused).await;
    let mut client = hostip.http1().await;
    let resp = client.send_request(get("x", "/")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(body_text(resp).await, "hostip: upstream unavailable\n");
}

fn with_auth() -> AccessConfig {
    AccessConfig {
        auth: Some(AuthConfig::parse_cli("alice:s3cret").unwrap()),
        ..AccessConfig::default()
    }
}

fn basic(user_pass: &str) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(user_pass)
    )
}

#[tokio::test]
async fn login_protects_the_app_and_sets_a_session_cookie() {
    let up = start_http_upstream().await;
    let hostip = start_hostip_with(Mode::Auto, up, with_auth(), Limits::default()).await;
    let mut client = hostip.http1().await;

    let resp = client.send_request(get("x", "/echo")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(
        resp.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .starts_with("Basic")
    );

    let mut req = get("x", "/echo");
    req.headers_mut()
        .insert("authorization", basic("alice:s3cret").parse().unwrap());
    let resp = client.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = resp.headers()["set-cookie"].to_str().unwrap().to_owned();
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("Secure"),
        "{cookie}"
    );
    let session = cookie.split(';').next().unwrap().to_owned();

    // The cookie alone works, and the app never sees hostip's credentials.
    let mut req = get("x", "/headers");
    req.headers_mut()
        .insert("cookie", format!("{session}; theme=dark").parse().unwrap());
    req.headers_mut()
        .insert("authorization", "Bearer app-token".parse().unwrap());
    let resp = client.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_text(resp).await,
        "authorization=Bearer app-token cookie=theme=dark"
    );
}

#[tokio::test]
async fn blocks_repeated_failed_logins() {
    let up = start_http_upstream().await;
    let limits = Limits {
        auth_failures_before_block: 3,
        ..Limits::default()
    };
    let hostip = start_hostip_with(Mode::Https, up, with_auth(), limits).await;
    let mut client = hostip.http1().await;
    for _ in 0..3 {
        let mut req = get("x", "/echo");
        req.headers_mut()
            .insert("authorization", basic("alice:guess").parse().unwrap());
        let resp = client.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    // Even the right password is refused while blocked.
    let mut req = get("x", "/echo");
    req.headers_mut()
        .insert("authorization", basic("alice:s3cret").parse().unwrap());
    let resp = client.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn login_ports_refuse_raw_tcp() {
    let up = start_echo_upstream().await;
    let hostip = start_hostip_with(Mode::Auto, up, with_auth(), Limits::default()).await;
    let mut tls = hostip.tls(&[]).await;
    tls.write_all(b"\x00raw").await.unwrap();
    let mut buf = Vec::new();
    // The connection is closed without anything reaching the app.
    let n = tls.read_to_end(&mut buf).await.unwrap_or(0);
    assert_eq!(n, 0);
}

#[tokio::test]
async fn deny_list_drops_connections() {
    let up = start_http_upstream().await;
    let access = AccessConfig {
        deny: vec!["127.0.0.0/8".parse().unwrap()],
        ..AccessConfig::default()
    };
    let hostip = start_hostip_with(Mode::Auto, up, access, Limits::default()).await;
    let mut tcp = TcpStream::connect(hostip.addr).await.unwrap();
    let mut buf = [0u8; 1];
    assert_eq!(tcp.read(&mut buf).await.unwrap_or(0), 0);
}

#[tokio::test]
async fn caps_simultaneous_connections_per_port() {
    let up = start_echo_upstream().await;
    let access = AccessConfig {
        max_connections: Some(1),
        ..AccessConfig::default()
    };
    let hostip = start_hostip_with(Mode::Tcp, up, access, Limits::default()).await;
    let mut first = TcpStream::connect(hostip.addr).await.unwrap();
    first.write_all(b"a").await.unwrap();
    let mut buf = [0u8; 1];
    first.read_exact(&mut buf).await.unwrap();

    let mut second = TcpStream::connect(hostip.addr).await.unwrap();
    assert_eq!(
        second.read(&mut buf).await.unwrap_or(0),
        0,
        "second is closed"
    );

    drop(first);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let mut third = TcpStream::connect(hostip.addr).await.unwrap();
    third.write_all(b"c").await.unwrap();
    third.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"c");
}
