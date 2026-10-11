//! TCP listeners: TLS termination, protocol sniffing and dispatch (F1, F16, F30, F31).

use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use crate::access::{AccessRules, Guard, Limits};
use crate::acme::HttpChallenges;
use crate::cert::{ACME_TLS_ALPN, CertStore};
use crate::config::{Mode, PortSpec};
use crate::io::{Activity, Prefixed};
use crate::proxy::{Hold, HttpProxy};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for a client's first bytes before assuming a server-speaks-first protocol.
const SNIFF_TIMEOUT: Duration = Duration::from_secs(3);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_RAW_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Request-line prefixes that identify HTTP/1.x and the HTTP/2 connection preface.
const HTTP_TOKENS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
    b"PRI * HTTP/2.0",
];

/// Settings shared by all listeners.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    pub guard: Arc<Guard>,
    /// Log every HTTP request at info level.
    pub access_log: bool,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            guard: Guard::new(Limits::default()),
            access_log: false,
        }
    }
}

struct PortCtx {
    spec: PortSpec,
    upstream: SocketAddr,
    rules: AccessRules,
    guard: Arc<Guard>,
    http: Arc<HttpProxy>,
    tls_http: TlsAcceptor,
    tls_raw: TlsAcceptor,
}

struct HttpPortCtx {
    challenges: Arc<HttpChallenges>,
    /// Public HTTPS port that plain-HTTP visitors are redirected to.
    https_port: Option<u16>,
}

/// Any byte stream a connection can arrive on (a TCP socket, or a relay tunnel).
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

pub struct Server {
    listeners: Vec<(Arc<PortCtx>, TcpListener)>,
    http_port: Option<(Arc<HttpPortCtx>, TcpListener)>,
    tracker: TaskTracker,
}

/// Feeds connections that did not arrive on a local listener (relay mode) into the
/// same handling as the listener for that public port.
#[derive(Clone)]
pub struct Injector {
    ports: Arc<std::collections::HashMap<u16, Arc<PortCtx>>>,
    http: Option<Arc<HttpPortCtx>>,
    tracker: TaskTracker,
    shutdown: CancellationToken,
}

impl Injector {
    /// Handles `stream` as if it had been accepted on public port `port` from `peer`.
    /// Returns false when nothing is published on that port or the connection is refused.
    pub fn inject<S: Io>(&self, port: u16, stream: S, peer: SocketAddr) -> bool {
        if port == 80
            && let Some(http) = &self.http
        {
            self.tracker.spawn(serve_http_port(http.clone(), stream));
            return true;
        }
        let Some(ctx) = self.ports.get(&port) else {
            return false;
        };
        let Some(hold) = admit(ctx, peer) else {
            return false;
        };
        self.tracker.spawn(handle_connection(
            ctx.clone(),
            stream,
            peer,
            self.shutdown.clone(),
            hold,
        ));
        true
    }
}

impl Server {
    /// Binds a listener for every TCP port spec. UDP specs are handled by the router mapping only.
    pub async fn bind(
        specs: &[PortSpec],
        bind: IpAddr,
        certs: Arc<CertStore>,
        public_host: &str,
    ) -> Result<Self> {
        Self::bind_with(specs, bind, certs, public_host, ServerOptions::default()).await
    }

    pub async fn bind_with(
        specs: &[PortSpec],
        bind: IpAddr,
        certs: Arc<CertStore>,
        public_host: &str,
        options: ServerOptions,
    ) -> Result<Self> {
        let tls_http = TlsAcceptor::from(tls_config(certs.clone(), true)?);
        let tls_raw = TlsAcceptor::from(tls_config(certs, false)?);
        let mut listeners = Vec::new();
        for spec in specs.iter().filter(|s| s.mode != Mode::Udp) {
            let listen = spec
                .listen_port()
                .context("tcp port spec without listen port")?;
            let listener = TcpListener::bind((bind, listen)).await.with_context(|| {
                format!("cannot listen on {bind}:{listen} (is the port already in use?)")
            })?;
            let upstream = SocketAddr::from((Ipv4Addr::LOCALHOST, spec.local.start));
            let public_host = if public_host.contains(':') {
                format!("[{public_host}]")
            } else {
                public_host.to_owned()
            };
            let rules = AccessRules::new(&spec.access)
                .with_context(|| format!("port {}: invalid access settings", spec.public))?;
            let http = HttpProxy::new(
                upstream,
                format!("{public_host}:{}", spec.public.start),
                rules.auth.clone(),
                options.guard.clone(),
                options.access_log,
            );
            let ctx = PortCtx {
                spec: spec.clone(),
                upstream,
                rules,
                guard: options.guard.clone(),
                http,
                tls_http: tls_http.clone(),
                tls_raw: tls_raw.clone(),
            };
            listeners.push((Arc::new(ctx), listener));
        }
        Ok(Self {
            listeners,
            http_port: None,
            tracker: TaskTracker::new(),
        })
    }

    /// Adds the plain-HTTP listener (public port 80): answers ACME HTTP-01 challenges and
    /// redirects everything else to `https://` on `https_port`.
    pub async fn bind_http(
        &mut self,
        bind: IpAddr,
        port: u16,
        challenges: Arc<HttpChallenges>,
        https_port: Option<u16>,
    ) -> Result<SocketAddr> {
        let listener = TcpListener::bind((bind, port))
            .await
            .with_context(|| format!("cannot listen on {bind}:{port} for HTTP"))?;
        let addr = listener.local_addr()?;
        let ctx = HttpPortCtx {
            challenges,
            https_port,
        };
        self.http_port = Some((Arc::new(ctx), listener));
        Ok(addr)
    }

    /// The actual bound address of each listener, in spec order.
    pub fn local_addrs(&self) -> Vec<(PortSpec, SocketAddr)> {
        self.listeners
            .iter()
            .filter_map(|(ctx, l)| Some((ctx.spec.clone(), l.local_addr().ok()?)))
            .collect()
    }

    /// A handle for injecting relayed connections; they share this server's shutdown.
    pub fn injector(&self, shutdown: CancellationToken) -> Injector {
        Injector {
            ports: Arc::new(
                self.listeners
                    .iter()
                    .map(|(ctx, _)| (ctx.spec.public.start, ctx.clone()))
                    .collect(),
            ),
            http: self.http_port.as_ref().map(|(ctx, _)| ctx.clone()),
            tracker: self.tracker.clone(),
            shutdown,
        }
    }

    /// Serves until `shutdown` is cancelled, then drains connections for a short grace period.
    pub async fn serve(self, shutdown: CancellationToken) {
        let tracker = self.tracker;
        for (ctx, listener) in self.listeners {
            tracker.spawn(accept_loop(
                ctx,
                listener,
                tracker.clone(),
                shutdown.clone(),
            ));
        }
        if let Some((ctx, listener)) = self.http_port {
            tracker.spawn(http_port_loop(
                ctx,
                listener,
                tracker.clone(),
                shutdown.clone(),
            ));
        }
        shutdown.cancelled().await;
        tracker.close();
        if timeout(SHUTDOWN_GRACE, tracker.wait()).await.is_err() {
            warn!("some connections did not finish within {SHUTDOWN_GRACE:?}; closing them");
        }
    }
}

fn tls_config(certs: Arc<CertStore>, http_alpn: bool) -> Result<Arc<ServerConfig>> {
    let mut cfg =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(certs);
    if http_alpn {
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), ACME_TLS_ALPN.to_vec()];
    }
    Ok(Arc::new(cfg))
}

async fn accept_loop(
    ctx: Arc<PortCtx>,
    listener: TcpListener,
    tracker: TaskTracker,
    shutdown: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, peer)) => {
                let Some(hold) = admit(&ctx, peer) else {
                    continue;
                };
                let _ = stream.set_nodelay(true);
                tracker.spawn(handle_connection(
                    ctx.clone(),
                    stream,
                    peer,
                    shutdown.clone(),
                    hold,
                ));
            }
            Err(e) => {
                // Usually resource exhaustion (too many open files); back off briefly.
                warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Applies the port's allow/deny list and connection cap, and the per-IP limits.
/// The returned permits free their slots when the connection ends.
fn admit(ctx: &PortCtx, peer: SocketAddr) -> Option<Hold> {
    let ip = peer.ip().to_canonical();
    let port = ctx.spec.public.start;
    if !ctx.rules.ip_allowed(ip) {
        debug!(%ip, port, "rejected: not allowed by allow/deny list");
        return None;
    }
    let Some(port_permit) = ctx.rules.take_slot() else {
        info!(%ip, port, "rejected: port connection limit reached");
        return None;
    };
    match ctx.guard.admit(ip) {
        Ok(ip_permit) => Some(Arc::new((ip_permit, port_permit))),
        Err(reason) => {
            debug!(%ip, port, ?reason, "rejected by per-IP limits");
            None
        }
    }
}

async fn handle_connection<S: Io>(
    ctx: Arc<PortCtx>,
    stream: S,
    peer: SocketAddr,
    shutdown: CancellationToken,
    hold: Hold,
) {
    let port = ctx.spec.public.start;
    let result = match ctx.spec.mode {
        Mode::Tcp => pipe(&ctx, stream, Bytes::new(), &shutdown).await,
        Mode::Udp => Ok(()),
        Mode::Auto | Mode::Https | Mode::Tls => {
            handle_tls(&ctx, stream, peer, &shutdown, &hold).await
        }
    };
    if let Err(e) = result {
        debug!(%peer, port, error = %e, "connection ended with error");
    }
}

async fn handle_tls<S: Io>(
    ctx: &PortCtx,
    mut stream: S,
    peer: SocketAddr,
    shutdown: &CancellationToken,
    hold: &Hold,
) -> io::Result<()> {
    let mut first = [0u8; 1];
    match timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut first)).await {
        Ok(Ok(_)) => {}
        _ => return Ok(()),
    }
    let stream = Prefixed::new(Bytes::copy_from_slice(&first), stream);
    // 0x16 = TLS handshake record. Anything else on an HTTP port is most likely plain HTTP.
    if first[0] != 0x16 {
        if ctx.spec.mode != Mode::Tls && first[0].is_ascii_uppercase() {
            return redirect_plain_http(stream).await;
        }
        return Ok(());
    }

    let acceptor = if ctx.spec.mode == Mode::Tls {
        &ctx.tls_raw
    } else {
        &ctx.tls_http
    };
    let mut tls = match timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            debug!(%peer, error = %e, "TLS handshake failed");
            return Ok(());
        }
        Err(_) => return Ok(()),
    };

    let alpn = tls.get_ref().1.alpn_protocol();
    if alpn == Some(ACME_TLS_ALPN) {
        // TLS-ALPN-01 validation: the handshake itself is the answer (RFC 8737).
        return Ok(());
    }

    match ctx.spec.mode {
        Mode::Tls => pipe(ctx, tls, Bytes::new(), shutdown).await,
        Mode::Https => serve_http(ctx, tls, peer, shutdown, hold.clone()).await,
        _ if alpn == Some(b"h2") => serve_http(ctx, tls, peer, shutdown, hold.clone()).await,
        _ => {
            let (prefix, is_http) = sniff(&mut tls).await?;
            if is_http {
                serve_http(
                    ctx,
                    Prefixed::new(prefix, tls),
                    peer,
                    shutdown,
                    hold.clone(),
                )
                .await
            } else if ctx.rules.auth.is_some() {
                // A login cannot be enforced on raw TCP, so it is refused.
                debug!(%peer, "rejected non-HTTP connection on a port that requires login");
                Ok(())
            } else {
                pipe(ctx, tls, prefix, shutdown).await
            }
        }
    }
}

/// Reads the client's first bytes and decides whether it speaks HTTP.
async fn sniff<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<(Bytes, bool)> {
    let deadline = Instant::now() + SNIFF_TIMEOUT;
    let mut buf = BytesMut::with_capacity(4096);
    loop {
        if let Some(is_http) = classify(&buf) {
            return Ok((buf.freeze(), is_http));
        }
        match timeout_at(deadline, stream.read_buf(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => return Ok((buf.freeze(), false)),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e),
        }
    }
}

/// `Some(true)` = HTTP, `Some(false)` = not HTTP, `None` = need more bytes.
fn classify(buf: &[u8]) -> Option<bool> {
    if buf.is_empty() {
        return None;
    }
    let mut undecided = false;
    for token in HTTP_TOKENS {
        if buf.len() >= token.len() {
            if buf.starts_with(token) {
                return Some(true);
            }
        } else if token.starts_with(buf) {
            undecided = true;
        }
    }
    (!undecided).then_some(false)
}

async fn serve_http<S>(
    ctx: &PortCtx,
    io: S,
    peer: SocketAddr,
    shutdown: &CancellationToken,
    hold: Hold,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let http = ctx.http.clone();
    let service = service_fn(move |req| http.clone().handle(req, peer, hold.clone()));
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    let conn = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    tokio::pin!(conn);
    let result = tokio::select! {
        result = conn.as_mut() => result,
        _ = shutdown.cancelled() => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    };
    result.map_err(io::Error::other)
}

/// Pipes raw bytes between the client and the app, closing after `idle_timeout` without reads.
async fn pipe<S>(
    ctx: &PortCtx,
    client: S,
    prefix: Bytes,
    shutdown: &CancellationToken,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut upstream = TcpStream::connect(ctx.upstream).await?;
    upstream.set_nodelay(true)?;
    upstream.write_all(&prefix).await?;

    let idle = ctx.spec.idle_timeout.unwrap_or(DEFAULT_RAW_IDLE_TIMEOUT);
    let counter = Arc::new(AtomicU64::new(0));
    let mut client = Activity::new(client, counter.clone());
    let mut upstream = Activity::new(upstream, counter.clone());
    let copy = tokio::io::copy_bidirectional(&mut client, &mut upstream);
    tokio::pin!(copy);

    let mut last_seen = counter.load(Ordering::Relaxed);
    loop {
        tokio::select! {
            result = &mut copy => return result.map(|_| ()),
            _ = shutdown.cancelled() => return Ok(()),
            _ = tokio::time::sleep(idle) => {
                let now = counter.load(Ordering::Relaxed);
                if now == last_seen {
                    debug!(port = ctx.spec.public.start, "closing idle connection");
                    return Ok(());
                }
                last_seen = now;
            }
        }
    }
}

async fn http_port_loop(
    ctx: Arc<HttpPortCtx>,
    listener: TcpListener,
    tracker: TaskTracker,
    shutdown: CancellationToken,
) {
    loop {
        let stream = tokio::select! {
            _ = shutdown.cancelled() => return,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        tracker.spawn(serve_http_port(ctx.clone(), stream));
    }
}

async fn serve_http_port<S: Io>(ctx: Arc<HttpPortCtx>, stream: S) {
    let service = service_fn(move |req| http_port_response(req, ctx.clone()));
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(TokioIo::new(stream), service);
    if let Err(e) = conn.await {
        debug!(error = %e, "HTTP port connection ended with error");
    }
}

async fn http_port_response(
    req: Request<Incoming>,
    ctx: Arc<HttpPortCtx>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let text = |status: StatusCode, body: String| {
        let mut resp = Response::new(Full::from(body));
        *resp.status_mut() = status;
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        resp
    };
    if let Some(token) = req
        .uri()
        .path()
        .strip_prefix("/.well-known/acme-challenge/")
    {
        return Ok(match ctx.challenges.get(token) {
            Some(key_authorization) => text(StatusCode::OK, key_authorization),
            None => text(StatusCode::NOT_FOUND, "unknown challenge\n".into()),
        });
    }
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(strip_port);
    let target = match (ctx.https_port, host) {
        (Some(443), Some(host)) => format!("https://{host}"),
        (Some(port), Some(host)) => format!("https://{host}:{port}"),
        _ => {
            return Ok(text(
                StatusCode::NOT_FOUND,
                "hostip: nothing is published over HTTPS on port 443\n".into(),
            ));
        }
    };
    let path = req.uri().path_and_query().map_or("/", |p| p.as_str());
    let mut resp = text(StatusCode::PERMANENT_REDIRECT, String::new());
    if let Ok(location) = HeaderValue::from_str(&format!("{target}{path}")) {
        resp.headers_mut().insert(header::LOCATION, location);
    }
    Ok(resp)
}

/// `host:port` -> `host`, keeping IPv6 brackets.
fn strip_port(authority: &str) -> &str {
    if authority.starts_with('[') {
        authority
            .find(']')
            .map_or(authority, |end| &authority[..=end])
    } else {
        authority.split(':').next().unwrap_or(authority)
    }
}

/// Answers a plain-HTTP request on a TLS port with a redirect to `https://`.
async fn redirect_plain_http<S: Io>(mut stream: S) -> io::Result<()> {
    let mut buf = BytesMut::with_capacity(1024);
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 8192 {
        match timeout_at(deadline, stream.read_buf(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {}
            _ => return Ok(()),
        }
    }
    let response = match plain_http_redirect_target(&buf) {
        Some(location) => format!(
            "HTTP/1.1 308 Permanent Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        None => {
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
        }
    };
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

fn plain_http_redirect_target(head: &[u8]) -> Option<String> {
    let head = std::str::from_utf8(head).ok()?;
    let mut lines = head.split("\r\n");
    let path = lines.next()?.split(' ').nth(1)?;
    let host = lines
        .take_while(|l| !l.is_empty())
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
        })?
        .1
        .trim();
    let valid = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic());
    (path.starts_with('/') && valid(path) && valid(host)).then(|| format!("https://{host}{path}"))
}

pub fn log_ready(specs: &[(PortSpec, SocketAddr)]) {
    for (spec, addr) in specs {
        info!(mode = %spec.mode, listen = %addr, local = spec.local.start, "listening");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_protocols() {
        assert_eq!(classify(b""), None);
        assert_eq!(classify(b"GE"), None);
        assert_eq!(classify(b"GET / HTTP/1.1\r\n"), Some(true));
        assert_eq!(classify(b"PRI * HTTP/2.0\r\n"), Some(true));
        assert_eq!(classify(b"P"), None);
        assert_eq!(classify(b"\x00\x01binary"), Some(false));
        assert_eq!(classify(b"GETX"), Some(false));
    }

    #[test]
    fn strips_ports_from_hosts() {
        assert_eq!(strip_port("203.0.113.7:80"), "203.0.113.7");
        assert_eq!(strip_port("203.0.113.7"), "203.0.113.7");
        assert_eq!(strip_port("[2001:db8::1]:80"), "[2001:db8::1]");
    }

    #[test]
    fn builds_plain_http_redirects() {
        assert_eq!(
            plain_http_redirect_target(b"GET /a?b=1 HTTP/1.1\r\nHost: 203.0.113.7:3000\r\n\r\n")
                .as_deref(),
            Some("https://203.0.113.7:3000/a?b=1")
        );
        assert_eq!(plain_http_redirect_target(b"GET /a HTTP/1.1\r\n\r\n"), None);
        assert_eq!(
            plain_http_redirect_target(b"GET http://evil/ HTTP/1.1\r\nHost: x\r\n\r\n"),
            None
        );
    }
}
