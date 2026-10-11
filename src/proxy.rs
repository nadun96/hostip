//! HTTP reverse proxy: streams bodies, passes WebSocket/other upgrades through,
//! sets forwarded headers and rewrites localhost redirects (F2, F8, F11, F20–F22, F33).

use std::any::Any;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tracing::{debug, info, warn};

use crate::access::{AuthOutcome, BasicAuth, Guard};

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;
/// Connection permits kept alive for as long as the connection (or its upgrade) lives.
pub type Hold = Arc<dyn Any + Send + Sync>;

/// Headers that describe a single hop and must not be forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Client-supplied values for these are untrusted; hostip is the edge, so it replaces them.
const FORWARDED_HEADERS: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
];

/// Why a request was refused before reaching the app.
enum Denied {
    Blocked,
    LoginRequired,
}

pub struct HttpProxy {
    client: Client<HttpConnector, Incoming>,
    upstream: SocketAddr,
    /// Used for redirects when the client sent no Host header.
    fallback_authority: String,
    auth: Option<Arc<BasicAuth>>,
    guard: Arc<Guard>,
    access_log: bool,
}

impl HttpProxy {
    pub fn new(
        upstream: SocketAddr,
        fallback_authority: String,
        auth: Option<Arc<BasicAuth>>,
        guard: Arc<Guard>,
        access_log: bool,
    ) -> Arc<Self> {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        connector.set_connect_timeout(Some(Duration::from_secs(5)));
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .build(connector);
        Arc::new(Self {
            client,
            upstream,
            fallback_authority,
            auth,
            guard,
            access_log,
        })
    }

    pub async fn handle(
        self: Arc<Self>,
        mut req: Request<Incoming>,
        peer: SocketAddr,
        hold: Hold,
    ) -> Result<Response<ProxyBody>, Infallible> {
        let started = Instant::now();
        let ip = peer.ip().to_canonical();
        let method = req.method().clone();
        // Path only: query strings often carry tokens.
        let path = req.uri().path().to_owned();

        let mut resp = match self.authorize(&mut req, ip) {
            Ok(session_cookie) => {
                let Ok(mut resp) = self.clone().forward(req, peer, hold).await;
                if let Some(cookie) = session_cookie {
                    resp.headers_mut().append(header::SET_COOKIE, cookie);
                }
                resp
            }
            Err(Denied::Blocked) => error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed logins; try again later",
            ),
            Err(Denied::LoginRequired) => unauthorized(),
        };
        if self.auth.is_some() {
            // Responses behind a login must not be cached by shared caches.
            resp.headers_mut()
                .entry(header::CACHE_CONTROL)
                .or_insert(HeaderValue::from_static("private"));
        }

        let (status, ms) = (resp.status().as_u16(), started.elapsed().as_millis());
        if self.access_log {
            info!(target: "hostip::access", "{ip} {method} {path} {status} {ms}ms");
        } else {
            debug!(target: "hostip::access", "{ip} {method} {path} {status} {ms}ms");
        }
        Ok(resp)
    }

    /// Enforces the port's login, if any. `Ok` may carry a session cookie to set.
    fn authorize(
        &self,
        req: &mut Request<Incoming>,
        ip: IpAddr,
    ) -> Result<Option<HeaderValue>, Denied> {
        let Some(auth) = &self.auth else {
            return Ok(None);
        };
        if self.guard.is_blocked(ip) {
            return Err(Denied::Blocked);
        }
        match auth.check(req.headers()) {
            AuthOutcome::Allowed(cookie) => {
                if cookie.is_some() {
                    self.guard.record_auth_success(ip);
                }
                auth.strip(req.headers_mut());
                Ok(cookie)
            }
            AuthOutcome::Missing => Err(Denied::LoginRequired),
            AuthOutcome::Failed => {
                if self.guard.record_auth_failure(ip) {
                    warn!(%ip, "failed login; blocking this address for a while");
                } else {
                    warn!(%ip, "failed login");
                }
                Err(Denied::LoginRequired)
            }
        }
    }

    async fn forward(
        self: Arc<Self>,
        mut req: Request<Incoming>,
        peer: SocketAddr,
        hold: Hold,
    ) -> Result<Response<ProxyBody>, Infallible> {
        let authority = request_authority(&req).unwrap_or_else(|| self.fallback_authority.clone());

        let upgrade = requested_upgrade(req.headers());
        let client_upgrade = upgrade.is_some().then(|| hyper::upgrade::on(&mut req));

        let (mut parts, body) = req.into_parts();
        let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
        parts.uri = match format!("http://{}{}", self.upstream, path).parse::<Uri>() {
            Ok(uri) => uri,
            Err(_) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid request target",
                ));
            }
        };
        parts.version = Version::HTTP_11;
        strip_hop_by_hop(&mut parts.headers);
        if let Some(protocol) = &upgrade {
            parts
                .headers
                .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            parts.headers.insert(header::UPGRADE, protocol.clone());
        }
        if !parts.headers.contains_key(header::HOST)
            && let Ok(host) = HeaderValue::from_str(&authority)
        {
            parts.headers.insert(header::HOST, host);
        }
        set_forwarded(&mut parts.headers, peer, &authority);

        let mut resp = match self.client.request(Request::from_parts(parts, body)).await {
            Ok(resp) => resp,
            Err(e) => {
                debug!(upstream = %self.upstream, error = %e, "upstream request failed");
                return Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream unavailable",
                ));
            }
        };

        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let Some(client_upgrade) = client_upgrade else {
                return Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    "unexpected protocol switch",
                ));
            };
            let upstream_upgrade = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                let _hold = hold;
                match tokio::try_join!(client_upgrade, upstream_upgrade) {
                    Ok((client, upstream)) => {
                        let (mut client, mut upstream) =
                            (TokioIo::new(client), TokioIo::new(upstream));
                        if let Err(e) =
                            tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                        {
                            debug!(error = %e, "upgraded connection closed with error");
                        }
                    }
                    Err(e) => debug!(error = %e, "upgrade failed"),
                }
            });
        } else {
            strip_hop_by_hop(resp.headers_mut());
        }

        let local_port = self.upstream.port();
        if let Some(location) = resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            && let Some(rewritten) = rewrite_location(location, local_port, &authority)
            && let Ok(value) = HeaderValue::from_str(&rewritten)
        {
            resp.headers_mut().insert(header::LOCATION, value);
        }

        Ok(resp.map(|b| b.boxed()))
    }
}

/// The host (and port) the client used to reach us.
fn request_authority<B>(req: &Request<B>) -> Option<String> {
    req.headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .or_else(|| req.uri().authority().map(|a| a.to_string()))
}

/// Returns the `Upgrade` protocol if the request asks to switch protocols.
fn requested_upgrade(headers: &HeaderMap) -> Option<HeaderValue> {
    let wants_upgrade = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    wants_upgrade
        .then(|| headers.get(header::UPGRADE).cloned())
        .flatten()
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

fn set_forwarded(headers: &mut HeaderMap, peer: SocketAddr, authority: &str) {
    for name in FORWARDED_HEADERS {
        headers.remove(*name);
    }
    let ip = peer.ip().to_string();
    let for_value = if peer.is_ipv6() {
        format!("\"[{ip}]\"")
    } else {
        ip.clone()
    };
    let mut set = |name: &'static str, value: String| {
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.insert(name, v);
        }
    };
    set("x-forwarded-for", ip.clone());
    set("x-real-ip", ip);
    set("x-forwarded-proto", "https".into());
    set("x-forwarded-host", authority.to_owned());
    set(
        "forwarded",
        format!("for={for_value};proto=https;host=\"{authority}\""),
    );
}

/// Rewrites redirects that point at the app's own local address to the public address.
pub fn rewrite_location(location: &str, local_port: u16, public_authority: &str) -> Option<String> {
    let uri: Uri = location.parse().ok()?;
    let default_port = match uri.scheme_str()? {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let authority = uri.authority()?;
    let local_host = matches!(
        authority.host(),
        "localhost" | "127.0.0.1" | "[::1]" | "0.0.0.0"
    );
    if !local_host || authority.port_u16().unwrap_or(default_port) != local_port {
        return None;
    }
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    Some(format!("https://{public_authority}{path}"))
}

fn unauthorized() -> Response<ProxyBody> {
    let mut resp = error_response(StatusCode::UNAUTHORIZED, "login required");
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"hostip\", charset=\"UTF-8\""),
    );
    resp
}

fn error_response(status: StatusCode, message: &'static str) -> Response<ProxyBody> {
    let body = Full::new(Bytes::from(format!("hostip: {message}\n")))
        .map_err(|never| match never {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_local_redirects_only() {
        let public = "203.0.113.7:3000";
        assert_eq!(
            rewrite_location("http://localhost:3000/login?next=/", 3000, public).as_deref(),
            Some("https://203.0.113.7:3000/login?next=/")
        );
        assert_eq!(
            rewrite_location("http://127.0.0.1:3000", 3000, public).as_deref(),
            Some("https://203.0.113.7:3000/")
        );
        assert_eq!(
            rewrite_location("http://localhost:4000/", 3000, public),
            None
        );
        assert_eq!(rewrite_location("https://example.com/", 3000, public), None);
        assert_eq!(rewrite_location("/relative", 3000, public), None);
    }

    #[test]
    fn strips_hop_by_hop_and_listed_headers() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-secret"),
        );
        h.insert("x-secret", HeaderValue::from_static("1"));
        h.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        h.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        strip_hop_by_hop(&mut h);
        assert_eq!(h.len(), 1);
        assert!(h.contains_key(header::ACCEPT));
    }

    #[test]
    fn replaces_spoofed_forwarded_headers() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6"));
        set_forwarded(
            &mut h,
            "198.51.100.4:5555".parse().unwrap(),
            "203.0.113.7:3000",
        );
        assert_eq!(h["x-forwarded-for"], "198.51.100.4");
        assert_eq!(h["x-forwarded-proto"], "https");
        assert_eq!(
            h["forwarded"],
            "for=198.51.100.4;proto=https;host=\"203.0.113.7:3000\""
        );
    }

    #[test]
    fn detects_upgrade_requests() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, Upgrade"),
        );
        h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        assert_eq!(requested_upgrade(&h).unwrap(), "websocket");
        h.remove(header::CONNECTION);
        assert!(requested_upgrade(&h).is_none());
    }
}
