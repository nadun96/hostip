//! End-to-end benchmarks against the non-functional targets in
//! docs/REQUIREMENTS.md §4, measured on the real `hostip` binary in front of a
//! local test app:
//!
//!     cargo bench --bench e2e
//!
//! Prints a table (also appended to `$GITHUB_STEP_SUMMARY` in GitHub Actions) and
//! exits with 1 when a target is missed. The load generator and the app run on the
//! same machine as hostip, so requests per second is a lower bound.

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Frame, Incoming};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const LOCALHOST: Ipv4Addr = Ipv4Addr::LOCALHOST;
/// Size of the streamed download.
const BIG: u64 = 1 << 30;
const CHUNK: usize = 64 * 1024;
const LOAD_CONNECTIONS: usize = 64;
const LOAD_TIME: Duration = Duration::from_secs(5);
const LATENCY_REQUESTS: usize = 2000;

// ------------------------------------------------------------------ test app

/// A body of `left` zero bytes, sent in 64 KiB chunks without allocating per chunk.
struct Zeros {
    left: u64,
    chunk: Bytes,
}

impl Body for Zeros {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.left == 0 {
            return Poll::Ready(None);
        }
        let n = self.left.min(CHUNK as u64) as usize;
        self.left -= n as u64;
        Poll::Ready(Some(Ok(Frame::data(self.chunk.slice(..n)))))
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.left)
    }
}

async fn start_app() -> u16 {
    let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let chunk = Bytes::from(vec![0u8; CHUNK]);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = stream.set_nodelay(true);
            let chunk = chunk.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let left = if req.uri().path() == "/big" { BIG } else { 2 };
                    let chunk = chunk.clone();
                    async move { Ok::<_, Infallible>(Response::new(Zeros { left, chunk })) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    port
}

// --------------------------------------------------------------- hostip itself

fn free_port() -> u16 {
    std::net::TcpListener::bind((LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Hostip {
    child: Child,
}

impl Drop for Hostip {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_hostip(dir: &std::path::Path, app: u16, public: u16) -> Hostip {
    let child = Command::new(env!("CARGO_BIN_EXE_hostip"))
        .args([
            "expose",
            &format!("{app}:{public}"),
            "--public-ip",
            "203.0.113.7",
            "--no-upnp",
            "--no-acme",
            "--http-listen",
            "0",
            "--cert-dir",
        ])
        .arg(dir.join("certs"))
        .env("HOME", dir)
        .env("RUST_LOG", "hostip=warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start hostip");
    Hostip { child }
}

/// Resident memory of a process in MiB (Linux only).
fn rss_mib(pid: u32) -> Option<f64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let kib: f64 = status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some(kib / 1024.0)
}

// --------------------------------------------------------------------- clients

#[derive(Clone)]
enum Target {
    Direct(u16),
    Hostip(u16, TlsConnector),
}

type Sender = hyper::client::conn::http1::SendRequest<Empty<Bytes>>;

async fn connect(target: &Target) -> std::io::Result<Sender> {
    let port = match target {
        Target::Direct(p) | Target::Hostip(p, _) => *p,
    };
    let tcp = TcpStream::connect((LOCALHOST, port)).await?;
    tcp.set_nodelay(true)?;
    let (sender, conn) = match target {
        Target::Direct(_) => {
            let (s, c) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
                .await
                .map_err(std::io::Error::other)?;
            tokio::spawn(c);
            return Ok(s);
        }
        Target::Hostip(_, tls) => {
            let name = ServerName::from(std::net::IpAddr::from(LOCALHOST));
            let stream = tls.connect(name, tcp).await?;
            hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .map_err(std::io::Error::other)?
        }
    };
    tokio::spawn(conn);
    Ok(sender)
}

/// Sends GET `path` and drains the body; returns the time to the response
/// headers and the total time.
async fn get(sender: &mut Sender, path: &str) -> (Duration, Duration, u64) {
    let start = Instant::now();
    sender.ready().await.unwrap();
    let req = Request::get(path)
        .header("host", "127.0.0.1")
        .body(Empty::new())
        .unwrap();
    let mut res = sender.send_request(req).await.unwrap();
    let ttfb = start.elapsed();
    let mut bytes = 0;
    while let Some(frame) = res.body_mut().frame().await {
        if let Ok(data) = frame.unwrap().into_data() {
            bytes += data.len() as u64;
        }
    }
    (ttfb, start.elapsed(), bytes)
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

/// Sequential requests on one warm connection: (median TTFB, p99 total).
async fn latency(target: &Target) -> (Duration, Duration) {
    let mut sender = connect(target).await.unwrap();
    for _ in 0..200 {
        get(&mut sender, "/").await;
    }
    let mut ttfb = Vec::with_capacity(LATENCY_REQUESTS);
    let mut total = Vec::with_capacity(LATENCY_REQUESTS);
    for _ in 0..LATENCY_REQUESTS {
        let (t, all, _) = get(&mut sender, "/").await;
        ttfb.push(t);
        total.push(all);
    }
    ttfb.sort();
    total.sort();
    (percentile(&ttfb, 0.5), percentile(&total, 0.99))
}

/// Requests per second over `LOAD_CONNECTIONS` keep-alive connections.
async fn throughput(target: &Target) -> f64 {
    let deadline = Instant::now() + LOAD_TIME;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..LOAD_CONNECTIONS {
        let target = target.clone();
        tasks.spawn(async move {
            let mut sender = connect(&target).await.unwrap();
            let mut n = 0u64;
            while Instant::now() < deadline {
                get(&mut sender, "/").await;
                n += 1;
            }
            n
        });
    }
    let total: u64 = tasks.join_all().await.into_iter().sum();
    total as f64 / LOAD_TIME.as_secs_f64()
}

// ------------------------------------------------------------------- the run

struct Row {
    metric: &'static str,
    result: String,
    target: &'static str,
    ok: Option<bool>,
}

#[tokio::main]
async fn main() {
    let dir = tempfile::tempdir().unwrap();
    let app = start_app().await;
    let public = free_port();

    // First start generates the key and certificate; startup is measured without it.
    {
        let _first = spawn_hostip(dir.path(), app, public);
        wait_for_port(public, Duration::from_secs(30)).await;
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(dir.path().join("certs/self-signed.pem")).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = TlsConnector::from(Arc::new(config));
    let via = Target::Hostip(public, tls.clone());
    let direct = Target::Direct(app);

    // Startup: process start until a TLS handshake succeeds.
    let started = Instant::now();
    let hostip = spawn_hostip(dir.path(), app, public);
    loop {
        if let Ok(tcp) = TcpStream::connect((LOCALHOST, public)).await
            && tls
                .connect(ServerName::from(std::net::IpAddr::from(LOCALHOST)), tcp)
                .await
                .is_ok()
        {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "hostip did not start"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let startup = started.elapsed();
    let pid = hostip.child.id();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let idle = rss_mib(pid);

    let (ttfb_direct, p99_direct) = latency(&direct).await;
    let (ttfb_via, p99_via) = latency(&via).await;
    let rps = throughput(&via).await;

    // Streaming: one 1 GiB download, sampling memory meanwhile.
    let before = rss_mib(pid);
    let peak = Arc::new(std::sync::Mutex::new(before));
    let sampler = {
        let peak = peak.clone();
        tokio::spawn(async move {
            loop {
                if let Some(r) = rss_mib(pid) {
                    let mut p = peak.lock().unwrap();
                    *p = Some(p.map_or(r, |p| p.max(r)));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
    };
    let mut sender = connect(&via).await.unwrap();
    let start = Instant::now();
    let (_, _, bytes) = get(&mut sender, "/big").await;
    let secs = start.elapsed().as_secs_f64();
    sampler.abort();
    let peak = *peak.lock().unwrap();
    assert_eq!(bytes, BIG, "short download");
    let gbits = bytes as f64 * 8.0 / secs / 1e9;
    let growth = match (before, peak) {
        (Some(b), Some(p)) => Some(p - b),
        _ => None,
    };
    drop(hostip);

    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let added_p99 = ms(p99_via) - ms(p99_direct);
    let added_ttfb = ms(ttfb_via) - ms(ttfb_direct);
    let mib =
        |v: Option<f64>| v.map_or_else(|| "n/a (Linux only)".into(), |v| format!("{v:.1} MiB"));
    let rows = [
        Row {
            metric: "Requests/s through hostip (64 connections)",
            result: format!("{rps:.0}"),
            target: "≥ 5000",
            ok: Some(rps >= 5000.0),
        },
        Row {
            metric: "Added p99 latency vs direct (small responses)",
            result: format!(
                "{added_p99:.2} ms ({:.2} vs {:.2} ms)",
                ms(p99_via),
                ms(p99_direct)
            ),
            target: "< 2 ms",
            ok: Some(added_p99 < 2.0),
        },
        Row {
            metric: "Time-to-first-byte overhead (median)",
            result: format!("{added_ttfb:.2} ms"),
            target: "< 5 ms",
            ok: Some(added_ttfb < 5.0),
        },
        Row {
            metric: "Streaming throughput (1 GiB, one connection, TLS)",
            result: format!("{gbits:.2} Gbit/s"),
            target: "≥ 1 Gbit/s",
            ok: Some(gbits >= 1.0),
        },
        Row {
            metric: "Memory growth while streaming 1 GiB",
            result: mib(growth),
            target: "bounded (< 16 MiB)",
            ok: growth.map(|g| g < 16.0),
        },
        Row {
            metric: "Idle memory (RSS)",
            result: mib(idle),
            target: "< 30 MiB",
            ok: idle.map(|r| r < 30.0),
        },
        Row {
            metric: "Startup (to first TLS handshake)",
            result: format!("{:.0} ms", ms(startup)),
            target: "< 500 ms",
            ok: Some(ms(startup) < 500.0),
        },
    ];

    let mut table = String::from("| Metric | Result | Target | |\n|---|---|---|---|\n");
    for r in &rows {
        let mark = match r.ok {
            Some(true) => "✅",
            Some(false) => "❌",
            None => "–",
        };
        table.push_str(&format!(
            "| {} | {} | {} | {mark} |\n",
            r.metric, r.result, r.target
        ));
    }
    println!("\n{table}");
    if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(path) {
            let _ = writeln!(
                f,
                "## hostip benchmarks ({})\n\n{table}",
                std::env::consts::OS
            );
        }
    }
    if rows.iter().any(|r| r.ok == Some(false)) {
        eprintln!("a performance target was missed");
        std::process::exit(1);
    }
}

async fn wait_for_port(port: u16, limit: Duration) {
    let start = Instant::now();
    while TcpStream::connect(SocketAddr::from((LOCALHOST, port)))
        .await
        .is_err()
    {
        assert!(start.elapsed() < limit, "hostip did not start");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
