//! Stream adapters used by the connection handlers.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// Replays bytes that were already read (while sniffing the protocol) before
/// reading from the inner stream.
pub struct Prefixed<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Bytes, inner: S) -> Self {
        Self { prefix, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Counts reads that returned data, so idle connections can be detected.
pub struct Activity<S> {
    inner: S,
    counter: Arc<AtomicU64>,
}

impl<S> Activity<S> {
    pub fn new(inner: S, counter: Arc<AtomicU64>) -> Self {
        Self { inner, counter }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Activity<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.counter.fetch_add(1, Ordering::Relaxed);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Activity<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Limits how fast data is written to the inner stream (bytes per second) with a
/// token bucket holding up to one second's worth; reads are not limited (F23).
pub struct Throttled<S> {
    inner: S,
    rate: f64,
    tokens: f64,
    last: Instant,
    sleep: Option<Pin<Box<Sleep>>>,
}

/// Smallest write worth waking up for.
const MIN_CHUNK: f64 = 1024.0;

impl<S> Throttled<S> {
    pub fn new(inner: S, bytes_per_sec: u64) -> Self {
        let rate = (bytes_per_sec as f64).max(1.0);
        Self {
            inner,
            rate,
            tokens: rate,
            last: Instant::now(),
            sleep: None,
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let earned = (now - self.last).as_secs_f64() * self.rate;
        self.tokens = (self.tokens + earned).min(self.rate.max(MIN_CHUNK));
        self.last = now;
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Throttled<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Throttled<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        loop {
            if let Some(sleep) = self.sleep.as_mut() {
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.sleep = None;
            }
            self.refill();
            let wanted = (buf.len() as f64).min(MIN_CHUNK.min(self.rate));
            if self.tokens >= wanted {
                break;
            }
            // At least 1 ms: a zero-length sleep would complete at once without
            // earning any tokens and spin forever.
            let wait = ((wanted - self.tokens) / self.rate).max(0.001);
            self.sleep = Some(Box::pin(tokio::time::sleep(
                std::time::Duration::from_secs_f64(wait),
            )));
        }
        let allowed = (self.tokens as usize).clamp(1, buf.len());
        let poll = Pin::new(&mut self.inner).poll_write(cx, &buf[..allowed]);
        if let Poll::Ready(Ok(n)) = poll {
            self.tokens -= n as f64;
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Parses a rate like `5mbit`, `500kbit`, `2MB` or `100kB` into bytes per second.
pub fn parse_rate(text: &str) -> anyhow::Result<u64> {
    let t = text.trim();
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let (number, unit) = t.split_at(split);
    let n: f64 = number
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid rate `{text}`"))?;
    let bytes = match unit.trim() {
        "kbit" => n * 1e3 / 8.0,
        "mbit" => n * 1e6 / 8.0,
        "gbit" => n * 1e9 / 8.0,
        "B" | "" => n,
        "kB" => n * 1e3,
        "MB" => n * 1e6,
        other => anyhow::bail!("invalid rate unit `{other}` (use kbit, mbit, gbit, B, kB or MB)"),
    };
    if bytes < 1.0 {
        anyhow::bail!("rate `{text}` is too small");
    }
    Ok(bytes as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn throttles_writes() {
        let (a, mut b) = tokio::io::duplex(1 << 20);
        let mut limited = Throttled::new(a, 10_000);
        let started = Instant::now();
        let writer = tokio::spawn(async move {
            limited.write_all(&[0u8; 50_000]).await.unwrap();
        });
        let mut received = vec![0u8; 50_000];
        b.read_exact(&mut received).await.unwrap();
        writer.await.unwrap();
        // One second of burst, then 10 kB/s: about four more seconds.
        let elapsed = started.elapsed().as_secs_f64();
        assert!((3.5..5.0).contains(&elapsed), "took {elapsed}s");
    }

    #[test]
    fn parses_rates() {
        assert_eq!(parse_rate("8mbit").unwrap(), 1_000_000);
        assert_eq!(parse_rate("500kbit").unwrap(), 62_500);
        assert_eq!(parse_rate("2MB").unwrap(), 2_000_000);
        assert!(parse_rate("5 parsecs").is_err());
    }

    #[tokio::test]
    async fn prefixed_replays_prefix_first() {
        let inner: &[u8] = b" world";
        let mut s = Prefixed::new(Bytes::from_static(b"hello"), inner);
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "hello world");
    }
}
