//! Relay mode (F36): works behind any NAT/CGNAT, with no router access.
//!
//! `hostip relay` runs on a machine with a public IP. The home `hostip` dials *out*
//! to it over TLS (the relay's self-signed certificate is pinned by fingerprint and
//! a shared token authenticates the home side). The relay then listens on the
//! published ports:
//!
//! * TCP: for every visitor the relay asks home to open a fresh tunnel connection
//!   and splices the two. TLS for visitors still terminates at home, so the relay
//!   never sees plaintext; the visitor's address travels with the request.
//! * UDP (e.g. WebRTC media): datagrams are exchanged with home over a UDP channel
//!   keyed per connection; home gives every remote peer its own local socket so the
//!   app sees a stable 5-tuple per peer.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::access::{Guard, Limits};
use crate::config::PortRange;
use crate::server::Injector;

const SERVER_NAME: &str = "hostip-relay";
const MAX_MESSAGE: u32 = 64 * 1024;
const PING_INTERVAL: Duration = Duration::from_secs(20);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
const ATTACH_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_REGISTER_INTERVAL: Duration = Duration::from_secs(15);
const UDP_SESSION_IDLE: Duration = Duration::from_secs(120);
const MAX_UDP_SESSIONS: usize = 10_000;
/// Visitors waiting for home to attach a tunnel.
const MAX_PENDING: usize = 4096;
const UDP_MAGIC: u8 = 0x48;
const UDP_REGISTER: u8 = 1;
const UDP_DATA: u8 = 2;
const UDP_HEADER: usize = 16;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Msg {
    Hello {
        token: String,
        tcp_ports: Vec<u16>,
        udp_ports: Vec<(u16, u16)>,
    },
    Welcome {
        public_ip: Option<IpAddr>,
        udp_key: u64,
    },
    Refused {
        reason: String,
    },
    Open {
        id: u64,
        port: u16,
        client: SocketAddr,
    },
    Attach {
        id: u64,
        token: String,
    },
    Ping,
    Pong,
}

async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, msg: &Msg) -> Result<()> {
    let body = serde_json::to_vec(msg)?;
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

/// Reads messages on a separate task: `read_msg` is not cancel-safe, so it must never
/// be raced inside `select!`. The channel closes when the stream ends or fails.
fn spawn_reader<R: AsyncRead + Unpin + Send + 'static>(mut reader: R) -> mpsc::Receiver<Msg> {
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(async move {
        while let Ok(msg) = read_msg(&mut reader).await {
            if tx.send(msg).await.is_err() {
                return;
            }
        }
    });
    rx
}

async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> Result<Msg> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len);
    if len > MAX_MESSAGE {
        bail!("relay message too large ({len} bytes)");
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

/// UDP frame: magic, kind, key (u64), session (u32), port (u16), then payload.
fn encode_frame(kind: u8, key: u64, session: u32, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(UDP_HEADER + payload.len());
    frame.push(UDP_MAGIC);
    frame.push(kind);
    frame.extend_from_slice(&key.to_be_bytes());
    frame.extend_from_slice(&session.to_be_bytes());
    frame.extend_from_slice(&port.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

struct Frame<'a> {
    kind: u8,
    key: u64,
    session: u32,
    port: u16,
    payload: &'a [u8],
}

fn decode_frame(buf: &[u8]) -> Option<Frame<'_>> {
    if buf.len() < UDP_HEADER || buf[0] != UDP_MAGIC {
        return None;
    }
    Some(Frame {
        kind: buf[1],
        key: u64::from_be_bytes(buf[2..10].try_into().ok()?),
        session: u32::from_be_bytes(buf[10..14].try_into().ok()?),
        port: u16::from_be_bytes(buf[14..16].try_into().ok()?),
        payload: &buf[UDP_HEADER..],
    })
}

/// Compares tokens without revealing timing information.
struct TokenCheck {
    key: hmac::Key,
    tag: hmac::Tag,
}

impl TokenCheck {
    fn new(token: &str) -> Result<Self> {
        let mut secret = [0u8; 32];
        SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| anyhow!("no secure randomness"))?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
        let tag = hmac::sign(&key, token.as_bytes());
        Ok(Self { key, tag })
    }

    fn matches(&self, token: &str) -> bool {
        hmac::verify(&self.key, token.as_bytes(), self.tag.as_ref()).is_ok()
    }
}

/// A random 32-character token for a new relay.
pub fn generate_token() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 24];
    let _ = SystemRandom::new().fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    let _ = SystemRandom::new().fill(&mut bytes);
    u64::from_be_bytes(bytes)
}

/// SHA-256 of a certificate, as lowercase hex.
pub fn fingerprint(cert: &CertificateDer<'_>) -> String {
    ring::digest::digest(&ring::digest::SHA256, cert)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn parse_fingerprint(text: &str) -> Result<[u8; 32]> {
    let hex: String = text
        .trim()
        .trim_start_matches("sha256:")
        .chars()
        .filter(|c| *c != ':')
        .collect();
    if hex.len() != 64 {
        bail!("the relay fingerprint must be 64 hex digits (SHA-256)");
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).context("invalid fingerprint")?;
    }
    Ok(out)
}

// ---------------------------------------------------------------- relay server

/// The relay's TLS settings from its (generated once, then reused) self-signed
/// certificate in `dir`, plus that certificate's fingerprint for pinning.
pub fn relay_tls(dir: &std::path::Path) -> Result<(Arc<rustls::ServerConfig>, String)> {
    let (key, _) = crate::cert::load_or_generate(dir, &[SERVER_NAME.to_owned()])?;
    let fingerprint = fingerprint(key.cert.first().context("empty relay certificate")?);
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_cert_resolver(crate::cert::CertStore::new(key));
    Ok((Arc::new(config), fingerprint))
}

#[derive(Debug, Clone)]
pub struct RelayOptions {
    pub listen: SocketAddr,
    pub token: String,
    /// Announced to the home side (for its certificate and URLs).
    pub public_ip: Option<IpAddr>,
    /// Ports the home side may publish.
    pub allowed_ports: Vec<PortRange>,
}

struct Home {
    control: mpsc::Sender<Msg>,
    udp_key: u64,
    udp_addr: Option<SocketAddr>,
    generation: u64,
}

#[derive(Default)]
struct UdpSessions {
    by_peer: HashMap<(u16, SocketAddr), u32>,
    by_id: HashMap<u32, (u16, SocketAddr, Instant)>,
    next: u32,
}

struct RelayState {
    opts: RelayOptions,
    token: TokenCheck,
    home: Mutex<Option<Home>>,
    generation: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<tokio_rustls::server::TlsStream<TcpStream>>>>,
    next_id: AtomicU64,
    sessions: Mutex<UdpSessions>,
    public_udp: Mutex<HashMap<u16, Arc<UdpSocket>>>,
    control_udp: Arc<UdpSocket>,
    /// Per-visitor-IP limits, so floods are stopped here instead of making home
    /// open a tunnel for every connection.
    guard: Arc<Guard>,
}

/// Runs the relay until `shutdown`. `tls` is the relay's own certificate.
pub async fn run_relay(
    opts: RelayOptions,
    tls: Arc<rustls::ServerConfig>,
    shutdown: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(opts.listen)
        .await
        .with_context(|| format!("cannot listen on {}", opts.listen))?;
    let control_udp = Arc::new(
        UdpSocket::bind(listener.local_addr()?)
            .await
            .context("cannot bind the relay UDP port")?,
    );
    let state = Arc::new(RelayState {
        token: TokenCheck::new(&opts.token)?,
        opts,
        home: Mutex::new(None),
        generation: AtomicU64::new(0),
        pending: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        sessions: Mutex::new(UdpSessions::default()),
        public_udp: Mutex::new(HashMap::new()),
        control_udp,
        guard: Guard::new(Limits::default()),
    });
    tokio::spawn(relay_udp_control(state.clone()));
    tokio::spawn(expire_udp_sessions(state.clone(), shutdown.clone()));
    let acceptor = TlsAcceptor::from(tls);
    info!("relay listening on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            accepted = listener.accept() => match accepted {
                Ok(v) => v,
                Err(e) => {
                    warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let (state, acceptor, shutdown) = (state.clone(), acceptor.clone(), shutdown.clone());
        tokio::spawn(async move {
            if let Err(e) = relay_accept(state, acceptor, stream, shutdown).await {
                debug!(%peer, "relay connection ended: {e:#}");
            }
        });
    }
}

async fn relay_accept(
    state: Arc<RelayState>,
    acceptor: TlsAcceptor,
    stream: TcpStream,
    shutdown: CancellationToken,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let peer = stream.peer_addr()?;
    let mut tls = tokio::time::timeout(ATTACH_TIMEOUT, acceptor.accept(stream)).await??;
    match tokio::time::timeout(ATTACH_TIMEOUT, read_msg(&mut tls)).await?? {
        Msg::Hello {
            token,
            tcp_ports,
            udp_ports,
        } => {
            if !state.token.matches(&token) {
                warn!(%peer, "relay: wrong token");
                write_msg(
                    &mut tls,
                    &Msg::Refused {
                        reason: "wrong token".into(),
                    },
                )
                .await?;
                return Ok(());
            }
            relay_control(state, tls, peer, tcp_ports, udp_ports, shutdown).await
        }
        Msg::Attach { id, token } => {
            if !state.token.matches(&token) {
                return Ok(());
            }
            if let Some(waiter) = state.pending.lock().unwrap().remove(&id) {
                let _ = waiter.send(tls);
            }
            Ok(())
        }
        other => bail!("unexpected first message {other:?}"),
    }
}

fn port_allowed(opts: &RelayOptions, port: u16) -> bool {
    opts.allowed_ports
        .iter()
        .any(|r| r.start <= port && port <= r.end)
}

async fn relay_control(
    state: Arc<RelayState>,
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    peer: SocketAddr,
    tcp_ports: Vec<u16>,
    udp_ports: Vec<(u16, u16)>,
    shutdown: CancellationToken,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(tls);
    let udp_ports: Vec<u16> = udp_ports
        .iter()
        .flat_map(|&(start, end)| start..=end)
        .collect();
    if let Some(port) = tcp_ports
        .iter()
        .chain(&udp_ports)
        .find(|p| !port_allowed(&state.opts, **p))
    {
        let reason = format!("port {port} is not allowed on this relay");
        write_msg(
            &mut writer,
            &Msg::Refused {
                reason: reason.clone(),
            },
        )
        .await?;
        bail!(reason);
    }

    let mut listeners: Vec<JoinHandle<()>> = Vec::new();
    for &port in &tcp_ports {
        let listener = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).await {
            Ok(l) => l,
            Err(e) => {
                let reason = format!("relay cannot listen on TCP {port}: {e}");
                write_msg(
                    &mut writer,
                    &Msg::Refused {
                        reason: reason.clone(),
                    },
                )
                .await?;
                listeners.iter().for_each(JoinHandle::abort);
                bail!(reason);
            }
        };
        listeners.push(tokio::spawn(relay_public_tcp(
            state.clone(),
            listener,
            port,
        )));
    }
    for &port in &udp_ports {
        let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                let reason = format!("relay cannot listen on UDP {port}: {e}");
                write_msg(
                    &mut writer,
                    &Msg::Refused {
                        reason: reason.clone(),
                    },
                )
                .await?;
                listeners.iter().for_each(JoinHandle::abort);
                bail!(reason);
            }
        };
        state
            .public_udp
            .lock()
            .unwrap()
            .insert(port, socket.clone());
        listeners.push(tokio::spawn(relay_public_udp(state.clone(), socket, port)));
    }

    let udp_key = random_u64();
    let (control_tx, mut control_rx) = mpsc::channel::<Msg>(256);
    let generation = state.generation.fetch_add(1, Ordering::Relaxed) + 1;
    *state.home.lock().unwrap() = Some(Home {
        control: control_tx,
        udp_key,
        udp_addr: None,
        generation,
    });
    write_msg(
        &mut writer,
        &Msg::Welcome {
            public_ip: state.opts.public_ip,
            udp_key,
        },
    )
    .await?;
    info!(%peer, ?tcp_ports, udp = udp_ports.len(), "home connected");

    let mut incoming = spawn_reader(reader);
    let result: Result<()> = async {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                msg = control_rx.recv() => match msg {
                    Some(msg) => write_msg(&mut writer, &msg).await?,
                    None => return Ok(()),
                },
                msg = tokio::time::timeout(CONTROL_TIMEOUT, incoming.recv()) => match msg? {
                    Some(Msg::Ping) => write_msg(&mut writer, &Msg::Pong).await?,
                    Some(Msg::Pong) => {}
                    Some(other) => bail!("unexpected control message {other:?}"),
                    None => return Ok(()),
                },
            }
        }
    }
    .await;

    // Tear down only if no newer home has replaced this one.
    let mut home = state.home.lock().unwrap();
    if home.as_ref().is_some_and(|h| h.generation == generation) {
        *home = None;
    }
    drop(home);
    for port in &udp_ports {
        state.public_udp.lock().unwrap().remove(port);
    }
    listeners.iter().for_each(JoinHandle::abort);
    info!(%peer, "home disconnected");
    result
}

async fn relay_public_tcp(state: Arc<RelayState>, listener: TcpListener, port: u16) {
    loop {
        let Ok((mut visitor, client)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let Ok(permit) = state.guard.admit(client.ip().to_canonical()) else {
            debug!(%client, "relay: visitor over the per-IP limits");
            continue;
        };
        if state.pending.lock().unwrap().len() >= MAX_PENDING {
            debug!(%client, "relay: too many visitors waiting for home");
            continue;
        }
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = visitor.set_nodelay(true);
            let control = state
                .home
                .lock()
                .unwrap()
                .as_ref()
                .map(|h| h.control.clone());
            let Some(control) = control else {
                return;
            };
            let id = state.next_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = oneshot::channel();
            state.pending.lock().unwrap().insert(id, tx);
            if control.send(Msg::Open { id, port, client }).await.is_err() {
                state.pending.lock().unwrap().remove(&id);
                return;
            }
            match tokio::time::timeout(ATTACH_TIMEOUT, rx).await {
                Ok(Ok(mut tunnel)) => {
                    if let Err(e) = tokio::io::copy_bidirectional(&mut visitor, &mut tunnel).await {
                        debug!(%client, "relayed connection ended: {e}");
                    }
                }
                _ => {
                    state.pending.lock().unwrap().remove(&id);
                    debug!(%client, port, "home did not attach in time");
                }
            }
        });
    }
}

async fn relay_public_udp(state: Arc<RelayState>, socket: Arc<UdpSocket>, port: u16) {
    let mut buf = vec![0u8; 65_536];
    loop {
        let Ok((n, client)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        let target = {
            let home = state.home.lock().unwrap();
            home.as_ref().and_then(|h| Some((h.udp_addr?, h.udp_key)))
        };
        let Some((home_addr, key)) = target else {
            continue;
        };
        let session = {
            let mut sessions = state.sessions.lock().unwrap();
            match sessions.by_peer.get(&(port, client)).copied() {
                Some(id) => {
                    if let Some(entry) = sessions.by_id.get_mut(&id) {
                        entry.2 = Instant::now();
                    }
                    id
                }
                None if sessions.by_id.len() >= MAX_UDP_SESSIONS => continue,
                None => {
                    sessions.next = sessions.next.wrapping_add(1).max(1);
                    let id = sessions.next;
                    sessions.by_peer.insert((port, client), id);
                    sessions.by_id.insert(id, (port, client, Instant::now()));
                    id
                }
            }
        };
        let frame = encode_frame(UDP_DATA, key, session, port, &buf[..n]);
        let _ = state.control_udp.send_to(&frame, home_addr).await;
    }
}

/// Datagrams from home: registrations (keeping its NAT mapping open) and replies.
async fn relay_udp_control(state: Arc<RelayState>) {
    let mut buf = vec![0u8; 65_536 + UDP_HEADER];
    loop {
        let Ok((n, from)) = state.control_udp.recv_from(&mut buf).await else {
            continue;
        };
        let Some(frame) = decode_frame(&buf[..n]) else {
            continue;
        };
        {
            let mut home = state.home.lock().unwrap();
            let Some(home) = home.as_mut().filter(|h| h.udp_key == frame.key) else {
                continue;
            };
            if frame.kind == UDP_REGISTER {
                home.udp_addr = Some(from);
                continue;
            }
        }
        if frame.kind != UDP_DATA {
            continue;
        }
        let target = state
            .sessions
            .lock()
            .unwrap()
            .by_id
            .get(&frame.session)
            .map(|&(port, client, _)| (port, client));
        let Some((port, client)) = target else {
            continue;
        };
        let socket = state.public_udp.lock().unwrap().get(&port).cloned();
        if let Some(socket) = socket {
            let _ = socket.send_to(frame.payload, client).await;
        }
    }
}

async fn expire_udp_sessions(state: Arc<RelayState>, shutdown: CancellationToken) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
        }
        let mut sessions = state.sessions.lock().unwrap();
        let now = Instant::now();
        let expired: Vec<u32> = sessions
            .by_id
            .iter()
            .filter(|(_, (_, _, seen))| now - *seen > UDP_SESSION_IDLE)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some((port, client, _)) = sessions.by_id.remove(&id) {
                sessions.by_peer.remove(&(port, client));
            }
        }
    }
}

// ---------------------------------------------------------------- home client

#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// `host:port` of the relay.
    pub relay: String,
    pub token: String,
    /// SHA-256 fingerprint of the relay's certificate (printed by `hostip relay`).
    pub fingerprint: String,
    pub tcp_ports: Vec<u16>,
    /// (public range on the relay, first local port on this PC).
    pub udp: Vec<(PortRange, u16)>,
}

#[derive(Debug)]
struct Pinned {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual = ring::digest::digest(&ring::digest::SHA256, end_entity);
        if actual.as_ref() == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "relay certificate does not match the pinned fingerprint".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct Client {
    opts: ClientOptions,
    connector: TlsConnector,
    relay_addr: SocketAddr,
}

impl Client {
    async fn dial(&self) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = tokio::time::timeout(ATTACH_TIMEOUT, TcpStream::connect(self.relay_addr))
            .await
            .context("connecting to the relay timed out")??;
        let _ = tcp.set_nodelay(true);
        let name = ServerName::try_from(SERVER_NAME)?;
        Ok(self.connector.connect(name, tcp).await?)
    }
}

/// Resolves `host:port`.
pub async fn resolve(relay: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(relay)
        .await
        .with_context(|| format!("cannot resolve relay address {relay}"))?
        .next()
        .with_context(|| format!("relay address {relay} did not resolve"))
}

/// Keeps a connection to the relay open (reconnecting with backoff) and feeds the
/// relayed visitors into `injector`.
pub async fn run_client(opts: ClientOptions, injector: Injector, shutdown: CancellationToken) {
    let fingerprint = match parse_fingerprint(&opts.fingerprint) {
        Ok(f) => f,
        Err(e) => {
            warn!("relay: {e:#}");
            return;
        }
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            fingerprint,
            provider,
        }))
        .with_no_client_auth();
    let mut delay = Duration::from_secs(1);
    loop {
        let relay_addr = match resolve(&opts.relay).await {
            Ok(a) => a,
            Err(e) => {
                warn!("relay: {e:#}");
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(delay) => {}
                }
                continue;
            }
        };
        let client = Arc::new(Client {
            opts: opts.clone(),
            connector: TlsConnector::from(Arc::new(config.clone())),
            relay_addr,
        });
        let started = Instant::now();
        match client_session(client, injector.clone(), shutdown.clone()).await {
            Ok(()) if shutdown.is_cancelled() => return,
            Ok(()) => warn!("relay connection closed; reconnecting"),
            Err(e) => warn!("relay connection failed: {e:#}; reconnecting"),
        }
        if started.elapsed() > Duration::from_secs(60) {
            delay = Duration::from_secs(1);
        }
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(delay) => {}
        }
        delay = (delay * 2).min(Duration::from_secs(60));
    }
}

async fn client_session(
    client: Arc<Client>,
    injector: Injector,
    shutdown: CancellationToken,
) -> Result<()> {
    let tls = client.dial().await?;
    let (mut reader, mut writer) = tokio::io::split(tls);
    write_msg(
        &mut writer,
        &Msg::Hello {
            token: client.opts.token.clone(),
            tcp_ports: client.opts.tcp_ports.clone(),
            udp_ports: client
                .opts
                .udp
                .iter()
                .map(|(r, _)| (r.start, r.end))
                .collect(),
        },
    )
    .await?;
    let udp_key = match tokio::time::timeout(ATTACH_TIMEOUT, read_msg(&mut reader)).await?? {
        Msg::Welcome { public_ip, udp_key } => {
            info!(
                "connected to relay {}{}",
                client.relay_addr,
                public_ip.map_or(String::new(), |ip| format!(" (public IP {ip})"))
            );
            udp_key
        }
        Msg::Refused { reason } => bail!("relay refused: {reason}"),
        other => bail!("unexpected relay message {other:?}"),
    };

    let mut incoming = spawn_reader(reader);
    let session_end = shutdown.child_token();
    let udp_task = (!client.opts.udp.is_empty())
        .then(|| tokio::spawn(client_udp(client.clone(), udp_key, session_end.clone())));

    let result: Result<()> = async {
        let mut ping = tokio::time::interval(PING_INTERVAL);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                _ = ping.tick() => write_msg(&mut writer, &Msg::Ping).await?,
                msg = tokio::time::timeout(CONTROL_TIMEOUT, incoming.recv()) => match msg? {
                    None => bail!("the relay closed the connection"),
                    Some(Msg::Open { id, port, client: visitor }) => {
                        let (client, injector) = (client.clone(), injector.clone());
                        tokio::spawn(async move {
                            if let Err(e) = attach(&client, &injector, id, port, visitor).await {
                                debug!(%visitor, "relay attach failed: {e:#}");
                            }
                        });
                    }
                    Some(Msg::Pong | Msg::Ping) => {}
                    Some(other) => bail!("unexpected relay message {other:?}"),
                },
            }
        }
    }
    .await;
    session_end.cancel();
    if let Some(task) = udp_task {
        let _ = task.await;
    }
    result
}

async fn attach(
    client: &Client,
    injector: &Injector,
    id: u64,
    port: u16,
    visitor: SocketAddr,
) -> Result<()> {
    let mut tunnel = client.dial().await?;
    write_msg(
        &mut tunnel,
        &Msg::Attach {
            id,
            token: client.opts.token.clone(),
        },
    )
    .await?;
    if !injector.inject(port, tunnel, visitor) {
        debug!(%visitor, port, "relayed connection refused");
    }
    Ok(())
}

/// Exchanges UDP with the relay; every relay session gets its own local socket.
async fn client_udp(client: Arc<Client>, key: u64, end: CancellationToken) {
    let tunnel = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!("relay UDP: {e}");
            return;
        }
    };
    let relay = client.relay_addr;
    let mut sessions: HashMap<u32, (Arc<UdpSocket>, Instant)> = HashMap::new();
    let mut register = tokio::time::interval(UDP_REGISTER_INTERVAL);
    let mut buf = vec![0u8; 65_536 + UDP_HEADER];
    loop {
        tokio::select! {
            _ = end.cancelled() => return,
            _ = register.tick() => {
                let _ = tunnel.send_to(&encode_frame(UDP_REGISTER, key, 0, 0, &[]), relay).await;
                let now = Instant::now();
                sessions.retain(|_, (_, seen)| now - *seen < UDP_SESSION_IDLE);
            }
            received = tunnel.recv_from(&mut buf) => {
                let Ok((n, from)) = received else { continue };
                if from != relay {
                    continue;
                }
                let Some(frame) = decode_frame(&buf[..n]) else { continue };
                if frame.key != key || frame.kind != UDP_DATA {
                    continue;
                }
                let Some(local) = local_udp_port(&client.opts.udp, frame.port) else { continue };
                let socket = match sessions.get_mut(&frame.session) {
                    Some((socket, seen)) => {
                        *seen = Instant::now();
                        socket.clone()
                    }
                    None => {
                        let Ok(socket) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await else { continue };
                        if socket.connect((Ipv4Addr::LOCALHOST, local)).await.is_err() {
                            continue;
                        }
                        let socket = Arc::new(socket);
                        tokio::spawn(udp_replies(
                            socket.clone(),
                            tunnel.clone(),
                            relay,
                            key,
                            frame.session,
                            frame.port,
                            end.clone(),
                        ));
                        sessions.insert(frame.session, (socket.clone(), Instant::now()));
                        socket
                    }
                };
                let _ = socket.send(frame.payload).await;
            }
        }
    }
}

/// Sends the app's replies for one relay session back to the relay.
async fn udp_replies(
    socket: Arc<UdpSocket>,
    tunnel: Arc<UdpSocket>,
    relay: SocketAddr,
    key: u64,
    session: u32,
    port: u16,
    end: CancellationToken,
) {
    let mut buf = vec![0u8; 65_536];
    loop {
        tokio::select! {
            _ = end.cancelled() => return,
            _ = tokio::time::sleep(UDP_SESSION_IDLE) => return,
            received = socket.recv(&mut buf) => {
                let Ok(n) = received else { return };
                let frame = encode_frame(UDP_DATA, key, session, port, &buf[..n]);
                let _ = tunnel.send_to(&frame, relay).await;
            }
        }
    }
}

fn local_udp_port(udp: &[(PortRange, u16)], public: u16) -> Option<u16> {
    udp.iter()
        .find(|(range, _)| range.start <= public && public <= range.end)
        .map(|(range, local)| local + (public - range.start))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let frame = encode_frame(UDP_DATA, 0xdead_beef, 7, 50_000, b"hello");
        let decoded = decode_frame(&frame).unwrap();
        assert_eq!(
            (
                decoded.kind,
                decoded.key,
                decoded.session,
                decoded.port,
                decoded.payload
            ),
            (UDP_DATA, 0xdead_beef, 7, 50_000, &b"hello"[..])
        );
        assert!(decode_frame(b"short").is_none());
    }

    #[test]
    fn maps_udp_ports() {
        let udp = [(
            PortRange {
                start: 50_000,
                end: 50_010,
            },
            40_000,
        )];
        assert_eq!(local_udp_port(&udp, 50_003), Some(40_003));
        assert_eq!(local_udp_port(&udp, 49_999), None);
    }

    #[test]
    fn parses_fingerprints() {
        let hex = "ab".repeat(32);
        assert_eq!(parse_fingerprint(&hex).unwrap(), [0xab; 32]);
        let colons: Vec<String> = (0..32).map(|_| "AB".to_string()).collect();
        assert_eq!(
            parse_fingerprint(&format!("sha256:{}", colons.join(":"))).unwrap(),
            [0xab; 32]
        );
        assert!(parse_fingerprint("abc").is_err());
    }

    #[test]
    fn checks_tokens() {
        let check = TokenCheck::new("s3cret").unwrap();
        assert!(check.matches("s3cret"));
        assert!(!check.matches("s3cre"));
    }

    #[tokio::test]
    async fn messages_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let msg = Msg::Open {
            id: 9,
            port: 443,
            client: "198.51.100.4:5555".parse().unwrap(),
        };
        write_msg(&mut a, &msg).await.unwrap();
        assert_eq!(read_msg(&mut b).await.unwrap(), msg);
    }
}
