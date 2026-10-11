//! Access control: IP allow/deny lists (S4), per-IP connection and rate limits (S5),
//! per-port connection caps (F23), password login with brute-force blocking (S3, S8).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hyper::header::{self, HeaderMap, HeaderValue};
use ipnet::IpNet;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;

const SESSION_COOKIE: &str = "hostip_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
/// Bound on remembered (already verified) Authorization header digests.
const VERIFIED_CACHE_LIMIT: usize = 1024;
const RATE_WINDOW: Duration = Duration::from_secs(60);

/// Global per-IP limits.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Concurrent connections from one IP across all ports.
    pub max_connections_per_ip: usize,
    /// New connections from one IP per minute.
    pub new_connections_per_ip_per_minute: u32,
    /// Failed logins from one IP before it is blocked.
    pub auth_failures_before_block: u32,
    pub block_minutes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        // Generous: many participants can share one IP (office, school, mobile CGNAT).
        Self {
            max_connections_per_ip: 256,
            new_connections_per_ip_per_minute: 1200,
            auth_failures_before_block: 10,
            block_minutes: 15,
        }
    }
}

#[derive(Debug, Default)]
struct IpState {
    open: usize,
    window_start: Option<Instant>,
    window_count: u32,
    auth_failures: u32,
    blocked_until: Option<Instant>,
}

impl IpState {
    fn idle(&self, now: Instant) -> bool {
        self.open == 0
            && self.blocked_until.is_none_or(|t| t <= now)
            && self.window_start.is_none_or(|t| now - t > RATE_WINDOW)
    }
}

/// Why a connection was turned away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    TooManyConnections,
    RateLimited,
}

/// Shared per-IP accounting for every listener.
#[derive(Debug, Default)]
pub struct Guard {
    limits: Limits,
    ips: Mutex<HashMap<IpAddr, IpState>>,
}

impl Guard {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            ips: Mutex::new(HashMap::new()),
        })
    }

    /// Admits a new connection from `ip`, or says why not. The permit releases the slot on drop.
    pub fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<ConnPermit, Reject> {
        let now = Instant::now();
        let mut ips = self.ips.lock().unwrap();
        if ips.len() > 10_000 {
            ips.retain(|_, s| !s.idle(now));
        }
        let state = ips.entry(ip).or_default();
        if state.open >= self.limits.max_connections_per_ip {
            return Err(Reject::TooManyConnections);
        }
        match state.window_start {
            Some(start) if now - start <= RATE_WINDOW => {
                if state.window_count >= self.limits.new_connections_per_ip_per_minute {
                    return Err(Reject::RateLimited);
                }
                state.window_count += 1;
            }
            _ => {
                state.window_start = Some(now);
                state.window_count = 1;
            }
        }
        state.open += 1;
        Ok(ConnPermit {
            guard: self.clone(),
            ip,
        })
    }

    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let ips = self.ips.lock().unwrap();
        ips.get(&ip)
            .and_then(|s| s.blocked_until)
            .is_some_and(|until| until > Instant::now())
    }

    /// Counts a failed login; returns true when this IP is now blocked.
    pub fn record_auth_failure(&self, ip: IpAddr) -> bool {
        let mut ips = self.ips.lock().unwrap();
        let state = ips.entry(ip).or_default();
        state.auth_failures += 1;
        if state.auth_failures >= self.limits.auth_failures_before_block {
            state.auth_failures = 0;
            state.blocked_until =
                Some(Instant::now() + Duration::from_secs(self.limits.block_minutes * 60));
            return true;
        }
        false
    }

    pub fn record_auth_success(&self, ip: IpAddr) {
        if let Some(state) = self.ips.lock().unwrap().get_mut(&ip) {
            state.auth_failures = 0;
        }
    }
}

/// Holds one connection slot for an IP until dropped.
#[derive(Debug)]
pub struct ConnPermit {
    guard: Arc<Guard>,
    ip: IpAddr,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        let mut ips = self.guard.ips.lock().unwrap();
        if let Some(state) = ips.get_mut(&self.ip) {
            state.open = state.open.saturating_sub(1);
        }
    }
}

/// Holds one slot of a port's connection cap until dropped.
#[derive(Debug)]
pub struct PortPermit(Arc<AtomicUsize>);

impl Drop for PortPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Per-port settings as written in the config (plain data).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessConfig {
    pub allow: Vec<IpNet>,
    pub deny: Vec<IpNet>,
    pub max_connections: Option<usize>,
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub user: String,
    /// Plain-text password (prefer `password_hash`, see `hostip hash-password`).
    pub password: Option<String>,
    /// Argon2 PHC string, e.g. `$argon2id$v=19$...`.
    pub password_hash: Option<String>,
}

impl AuthConfig {
    /// Parses the CLI form `user:password`.
    pub fn parse_cli(s: &str) -> Result<Self> {
        let (user, password) = s.split_once(':').context("expected user:password")?;
        if user.is_empty() || password.is_empty() {
            bail!("user and password must not be empty");
        }
        Ok(Self {
            user: user.to_owned(),
            password: Some(password.to_owned()),
            password_hash: None,
        })
    }
}

/// Runtime rules for one port.
#[derive(Debug)]
pub struct AccessRules {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
    max_connections: Option<usize>,
    open: Arc<AtomicUsize>,
    pub auth: Option<Arc<BasicAuth>>,
}

impl AccessRules {
    pub fn new(config: &AccessConfig) -> Result<Self> {
        Ok(Self {
            allow: config.allow.clone(),
            deny: config.deny.clone(),
            max_connections: config.max_connections,
            open: Arc::new(AtomicUsize::new(0)),
            auth: config
                .auth
                .as_ref()
                .map(BasicAuth::new)
                .transpose()?
                .map(Arc::new),
        })
    }

    pub fn ip_allowed(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        if self.deny.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        self.allow.is_empty() || self.allow.iter().any(|net| net.contains(&ip))
    }

    /// Takes a slot of this port's connection cap, if one is free.
    pub fn take_slot(&self) -> Option<PortPermit> {
        let max = self.max_connections.unwrap_or(usize::MAX);
        let mut current = self.open.load(Ordering::Relaxed);
        loop {
            if current >= max {
                return None;
            }
            match self.open.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(PortPermit(self.open.clone())),
                Err(actual) => current = actual,
            }
        }
    }
}

enum Secret {
    Plain(String),
    Hash(String),
}

/// Outcome of checking a request's credentials.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Allowed; `Some` carries a session cookie to set on the response.
    Allowed(Option<HeaderValue>),
    Missing,
    Failed,
}

/// HTTP Basic login. A successful login also gets a signed session cookie, so apps
/// that send their own `Authorization` header (e.g. bearer tokens) keep working.
pub struct BasicAuth {
    user: String,
    secret: Secret,
    session_key: hmac::Key,
    verified: Mutex<HashSet<Vec<u8>>>,
}

impl std::fmt::Debug for BasicAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicAuth")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl BasicAuth {
    pub fn new(config: &AuthConfig) -> Result<Self> {
        let secret = match (&config.password, &config.password_hash) {
            (Some(_), Some(_)) => bail!("set either `password` or `password_hash`, not both"),
            (Some(p), None) => Secret::Plain(p.clone()),
            (None, Some(h)) => {
                PasswordHash::new(h).map_err(|e| anyhow::anyhow!("invalid password_hash: {e}"))?;
                Secret::Hash(h.clone())
            }
            (None, None) => bail!("auth needs `password` or `password_hash`"),
        };
        let mut key = [0u8; 32];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| anyhow::anyhow!("no secure randomness"))?;
        Ok(Self {
            user: config.user.clone(),
            secret,
            session_key: hmac::Key::new(hmac::HMAC_SHA256, &key),
            verified: Mutex::new(HashSet::new()),
        })
    }

    pub fn check(&self, headers: &HeaderMap) -> AuthOutcome {
        if self.has_valid_session(headers) {
            return AuthOutcome::Allowed(None);
        }
        let Some(credentials) = basic_credentials(headers) else {
            return AuthOutcome::Missing;
        };
        let digest = ring::digest::digest(&ring::digest::SHA256, credentials.as_bytes())
            .as_ref()
            .to_vec();
        let known = self.verified.lock().unwrap().contains(&digest);
        if !known {
            let Some((user, password)) = credentials.split_once(':') else {
                return AuthOutcome::Failed;
            };
            if !self.verify(user, password) {
                return AuthOutcome::Failed;
            }
            let mut verified = self.verified.lock().unwrap();
            if verified.len() >= VERIFIED_CACHE_LIMIT {
                verified.clear();
            }
            verified.insert(digest);
        }
        AuthOutcome::Allowed(Some(self.session_cookie()))
    }

    fn verify(&self, user: &str, password: &str) -> bool {
        let user_ok = self.constant_time_eq(user, &self.user);
        let password_ok = match &self.secret {
            Secret::Plain(expected) => self.constant_time_eq(password, expected),
            Secret::Hash(phc) => PasswordHash::new(phc).is_ok_and(|hash| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &hash)
                    .is_ok()
            }),
        };
        user_ok && password_ok
    }

    /// Compares via HMAC tags so timing does not reveal how much of `given` matched.
    fn constant_time_eq(&self, given: &str, expected: &str) -> bool {
        let tag = hmac::sign(&self.session_key, expected.as_bytes());
        hmac::verify(&self.session_key, given.as_bytes(), tag.as_ref()).is_ok()
    }

    fn session_cookie(&self) -> HeaderValue {
        let expires = unix_now() + SESSION_TTL.as_secs();
        let tag = hmac::sign(&self.session_key, expires.to_string().as_bytes());
        let token = format!("{expires}.{}", URL_SAFE_NO_PAD.encode(tag.as_ref()));
        HeaderValue::from_str(&format!(
            "{SESSION_COOKIE}={token}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Lax",
            SESSION_TTL.as_secs()
        ))
        .expect("cookie is ASCII")
    }

    fn has_valid_session(&self, headers: &HeaderMap) -> bool {
        cookies(headers)
            .filter(|(name, _)| *name == SESSION_COOKIE)
            .any(|(_, token)| {
                let Some((expires, tag)) = token.split_once('.') else {
                    return false;
                };
                let (Ok(expiry), Ok(tag)) = (expires.parse::<u64>(), URL_SAFE_NO_PAD.decode(tag))
                else {
                    return false;
                };
                expiry > unix_now()
                    && hmac::verify(&self.session_key, expires.as_bytes(), &tag).is_ok()
            })
    }

    /// Removes hostip's own credentials so they are never passed to the app.
    pub fn strip(&self, headers: &mut HeaderMap) {
        if basic_credentials(headers)
            .is_some_and(|c| c.split(':').next() == Some(self.user.as_str()))
        {
            headers.remove(header::AUTHORIZATION);
        }
        let remaining: Vec<String> = cookies(headers)
            .filter(|(name, _)| *name != SESSION_COOKIE)
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        headers.remove(header::COOKIE);
        if !remaining.is_empty()
            && let Ok(value) = HeaderValue::from_str(&remaining.join("; "))
        {
            headers.insert(header::COOKIE, value);
        }
    }
}

fn basic_credentials(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()
}

fn cookies(headers: &HeaderMap) -> impl Iterator<Item = (&str, &str)> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Hashes a password for `password_hash` in the config file.
pub fn hash_password(password: &str) -> Result<String> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow::anyhow!("hashing failed: {e}"))?
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(user: &str, password: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        let value = format!("Basic {}", STANDARD.encode(format!("{user}:{password}")));
        h.insert(header::AUTHORIZATION, value.parse().unwrap());
        h
    }

    #[test]
    fn checks_ip_lists() {
        let rules = AccessRules::new(&AccessConfig {
            allow: vec!["203.0.113.0/24".parse().unwrap()],
            deny: vec!["203.0.113.66/32".parse().unwrap()],
            ..AccessConfig::default()
        })
        .unwrap();
        assert!(rules.ip_allowed("203.0.113.5".parse().unwrap()));
        assert!(rules.ip_allowed("::ffff:203.0.113.5".parse().unwrap()));
        assert!(!rules.ip_allowed("203.0.113.66".parse().unwrap()));
        assert!(!rules.ip_allowed("198.51.100.1".parse().unwrap()));
        let open = AccessRules::new(&AccessConfig::default()).unwrap();
        assert!(open.ip_allowed("198.51.100.1".parse().unwrap()));
    }

    #[test]
    fn caps_connections_per_port() {
        let rules = AccessRules::new(&AccessConfig {
            max_connections: Some(2),
            ..AccessConfig::default()
        })
        .unwrap();
        let a = rules.take_slot().unwrap();
        let _b = rules.take_slot().unwrap();
        assert!(rules.take_slot().is_none());
        drop(a);
        assert!(rules.take_slot().is_some());
    }

    #[test]
    fn limits_connections_per_ip() {
        let guard = Guard::new(Limits {
            max_connections_per_ip: 2,
            new_connections_per_ip_per_minute: 3,
            ..Limits::default()
        });
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let a = guard.admit(ip).unwrap();
        let _b = guard.admit(ip).unwrap();
        assert_eq!(guard.admit(ip).unwrap_err(), Reject::TooManyConnections);
        drop(a);
        let _c = guard.admit(ip).unwrap();
        // Fourth new connection within a minute.
        assert!(guard.admit("198.51.100.1".parse().unwrap()).is_err());
        assert!(guard.admit("198.51.100.2".parse().unwrap()).is_ok());
    }

    #[test]
    fn blocks_after_repeated_failures() {
        let guard = Guard::new(Limits {
            auth_failures_before_block: 3,
            ..Limits::default()
        });
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(!guard.record_auth_failure(ip));
        assert!(!guard.record_auth_failure(ip));
        assert!(guard.record_auth_failure(ip));
        assert!(guard.is_blocked(ip));
        assert!(!guard.is_blocked("198.51.100.2".parse().unwrap()));
    }

    #[test]
    fn basic_auth_with_plain_and_hashed_passwords() {
        for config in [
            AuthConfig::parse_cli("alice:s3cret").unwrap(),
            AuthConfig {
                user: "alice".into(),
                password: None,
                password_hash: Some(hash_password("s3cret").unwrap()),
            },
        ] {
            let auth = BasicAuth::new(&config).unwrap();
            assert_eq!(auth.check(&HeaderMap::new()), AuthOutcome::Missing);
            assert_eq!(auth.check(&basic("alice", "wrong")), AuthOutcome::Failed);
            assert_eq!(auth.check(&basic("bob", "s3cret")), AuthOutcome::Failed);
            let AuthOutcome::Allowed(Some(cookie)) = auth.check(&basic("alice", "s3cret")) else {
                panic!("login failed");
            };
            // Cached second check.
            assert!(matches!(
                auth.check(&basic("alice", "s3cret")),
                AuthOutcome::Allowed(_)
            ));

            // The session cookie alone is enough afterwards.
            let token = cookie
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            let mut h = HeaderMap::new();
            h.insert(
                header::COOKIE,
                format!("theme=dark; {token}").parse().unwrap(),
            );
            assert_eq!(auth.check(&h), AuthOutcome::Allowed(None));

            // A forged cookie is not.
            let mut forged = HeaderMap::new();
            forged.insert(
                header::COOKIE,
                "hostip_session=9999999999.AAAA".parse().unwrap(),
            );
            assert_eq!(auth.check(&forged), AuthOutcome::Missing);
        }
    }

    #[test]
    fn strips_own_credentials_only() {
        let auth = BasicAuth::new(&AuthConfig::parse_cli("alice:pw").unwrap()).unwrap();
        let mut h = basic("alice", "pw");
        h.insert(
            header::COOKIE,
            "hostip_session=x; theme=dark".parse().unwrap(),
        );
        auth.strip(&mut h);
        assert!(!h.contains_key(header::AUTHORIZATION));
        assert_eq!(h[header::COOKIE], "theme=dark");

        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer app-token".parse().unwrap());
        auth.strip(&mut h);
        assert_eq!(h[header::AUTHORIZATION], "Bearer app-token");
    }
}
