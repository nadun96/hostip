//! Let's Encrypt (ACME) certificates for the bare public IP (F17, F19).
//!
//! IP certificates can only be validated with TLS-ALPN-01 (public port 443) or
//! HTTP-01 (public port 80); DNS-01 is impossible for IP identifiers. Let's
//! Encrypt issues them only with the short-lived (~6-day) profile, so renewal
//! runs every few days and re-issue happens immediately when the IP changes.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use rustls::sign::CertifiedKey;
use time::OffsetDateTime;
use tokio::sync::{OnceCell, watch};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::cert::{self, CertStore, PemPair};

pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
/// Let's Encrypt issues IP-address certificates only with this profile.
pub const DEFAULT_PROFILE: &str = "shortlived";

/// Waits after failed attempts: 5, 10, 20, 40 minutes, then hourly (stays under CA rate limits).
const RETRY_DELAYS: &[Duration] = &[
    Duration::from_secs(300),
    Duration::from_secs(600),
    Duration::from_secs(1200),
    Duration::from_secs(2400),
    Duration::from_secs(3600),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    /// Validated over TLS on public port 443.
    TlsAlpn01,
    /// Validated over plain HTTP on public port 80.
    Http01,
}

impl ChallengeKind {
    fn acme_type(self) -> ChallengeType {
        match self {
            ChallengeKind::TlsAlpn01 => ChallengeType::TlsAlpn01,
            ChallengeKind::Http01 => ChallengeType::Http01,
        }
    }
}

impl fmt::Display for ChallengeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ChallengeKind::TlsAlpn01 => "tls-alpn-01 (TCP 443)",
            ChallengeKind::Http01 => "http-01 (TCP 80)",
        })
    }
}

#[derive(Debug, Clone)]
pub struct AcmeOptions {
    /// ACME directory URL.
    pub directory: String,
    /// Contact email (optional).
    pub contact: Option<String>,
    /// Certificate profile; ignored if the CA does not advertise it.
    pub profile: Option<String>,
    /// Extra root CA for talking to a test CA such as Pebble.
    pub ca_root: Option<PathBuf>,
    /// Where account credentials and issued certificates are stored.
    pub dir: PathBuf,
    /// Challenge types that can work with the current port setup, in order of preference.
    pub challenges: Vec<ChallengeKind>,
    /// Renew this long before expiry; default is one third of the certificate lifetime.
    pub renew_before: Option<Duration>,
}

impl AcmeOptions {
    pub fn directory_for(staging: bool) -> &'static str {
        if staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        }
    }
}

/// Pending HTTP-01 responses: token -> key authorization.
#[derive(Debug, Default)]
pub struct HttpChallenges(Mutex<HashMap<String, String>>);

impl HttpChallenges {
    pub fn get(&self, token: &str) -> Option<String> {
        self.0.lock().unwrap().get(token).cloned()
    }

    fn insert(&self, token: String, key_authorization: String) {
        self.0.lock().unwrap().insert(token, key_authorization);
    }

    fn remove(&self, token: &str) {
        self.0.lock().unwrap().remove(token);
    }
}

/// An issued certificate and its validity window.
pub struct Issued {
    pub key: CertifiedKey,
    pub pem: PemPair,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl Issued {
    fn from_pem(chain_pem: &str, key_pem: &str) -> Result<Self> {
        let key = cert::certified_key_from_pem(chain_pem, key_pem)?;
        let leaf = key.cert.first().context("empty certificate chain")?;
        let (_, parsed) = x509_parser::parse_x509_certificate(leaf)
            .map_err(|e| anyhow!("invalid certificate: {e}"))?;
        let validity = parsed.validity();
        Ok(Self {
            pem: PemPair {
                chain: chain_pem.to_owned(),
                key: key_pem.to_owned(),
            },
            not_before: OffsetDateTime::from_unix_timestamp(validity.not_before.timestamp())?,
            not_after: OffsetDateTime::from_unix_timestamp(validity.not_after.timestamp())?,
            key,
        })
    }

    pub fn renew_at(&self, renew_before: Option<Duration>) -> OffsetDateTime {
        let lifetime = self.not_after - self.not_before;
        let before = renew_before.map_or(lifetime / 3, |d| {
            time::Duration::try_from(d).unwrap_or(lifetime / 3)
        });
        self.not_after - before
    }
}

/// Produces the certificate to serve for a new IP until Let's Encrypt has issued one.
pub type Fallback = Box<dyn Fn(IpAddr) -> Result<CertifiedKey> + Send + Sync>;

pub struct AcmeManager {
    opts: AcmeOptions,
    certs: Arc<CertStore>,
    http: Arc<HttpChallenges>,
    account: OnceCell<Account>,
    fallback: OnceLock<Fallback>,
}

impl AcmeManager {
    pub fn new(opts: AcmeOptions, certs: Arc<CertStore>, http: Arc<HttpChallenges>) -> Arc<Self> {
        Arc::new(Self {
            opts,
            certs,
            http,
            account: OnceCell::new(),
            fallback: OnceLock::new(),
        })
    }

    /// Sets how to build the stand-in certificate served right after an IP change.
    pub fn set_fallback(&self, fallback: Fallback) {
        let _ = self.fallback.set(fallback);
    }

    /// Keeps a valid certificate for the current public IP in the store: loads a stored one,
    /// issues when missing, renews before expiry, and re-issues when the IP changes.
    pub async fn run(
        self: Arc<Self>,
        mut ip: watch::Receiver<Option<IpAddr>>,
        shutdown: CancellationToken,
    ) {
        let mut failures = 0usize;
        loop {
            let current = *ip.borrow_and_update();
            let wake_at = match current {
                None => None,
                Some(addr) => match self.ensure(addr).await {
                    Ok(renew_at) => {
                        failures = 0;
                        Some(renew_at)
                    }
                    Err(e) => {
                        let delay = RETRY_DELAYS[failures.min(RETRY_DELAYS.len() - 1)];
                        failures += 1;
                        warn!("Let's Encrypt certificate for {addr} failed: {e:#}");
                        warn!(
                            "serving the self-signed certificate; retrying in {} min",
                            delay.as_secs() / 60
                        );
                        Some(OffsetDateTime::now_utc() + delay)
                    }
                },
            };
            let sleep = async {
                match wake_at {
                    Some(at) => tokio::time::sleep(until(at)).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = sleep => {}
                changed = ip.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    failures = 0;
                    // The old certificate names the old IP; serve a stand-in until re-issued.
                    if let (Some(addr), Some(fallback)) = (*ip.borrow(), self.fallback.get()) {
                        match fallback(addr) {
                            Ok(key) => self.certs.replace(key),
                            Err(e) => warn!("cannot build a stand-in certificate for {addr}: {e:#}"),
                        }
                    }
                }
            }
        }
    }

    /// Makes sure a valid certificate for `ip` is being served; returns when to renew it.
    async fn ensure(&self, ip: IpAddr) -> Result<OffsetDateTime> {
        let now = OffsetDateTime::now_utc();
        if let Some(stored) = self.load_stored(ip)
            && stored.renew_at(self.opts.renew_before) > now
        {
            let renew_at = stored.renew_at(self.opts.renew_before);
            self.certs.replace_with_pem(stored.key, stored.pem);
            return Ok(renew_at);
        }
        let issued = self.issue(ip).await?;
        info!(
            "Let's Encrypt certificate for {ip} issued, valid until {}",
            issued.not_after
        );
        let renew_at = issued.renew_at(self.opts.renew_before);
        self.certs.replace_with_pem(issued.key, issued.pem);
        Ok(renew_at)
    }

    fn cert_paths(&self, ip: IpAddr) -> (PathBuf, PathBuf) {
        // Windows file names cannot contain ':', so IPv6 colons become '_'.
        let name = ip.to_string().replace(':', "_");
        (
            self.opts.dir.join(format!("{name}.pem")),
            self.opts.dir.join(format!("{name}.key")),
        )
    }

    pub fn load_stored(&self, ip: IpAddr) -> Option<Issued> {
        let (cert_path, key_path) = self.cert_paths(ip);
        let chain = std::fs::read_to_string(cert_path).ok()?;
        let key = std::fs::read_to_string(key_path).ok()?;
        let issued = Issued::from_pem(&chain, &key).ok()?;
        (issued.not_after > OffsetDateTime::now_utc()).then_some(issued)
    }

    /// Runs one complete ACME order for `ip` and stores the result.
    pub async fn issue(&self, ip: IpAddr) -> Result<Issued> {
        let kind = *self.opts.challenges.first().context(
            "no ACME challenge can work: publish a port on public 443 in auto/https mode, or enable the HTTP port (80)",
        )?;
        let account = self.account().await?;
        let identifiers = [Identifier::Ip(ip)];
        let mut request = NewOrder::new(&identifiers);
        if let Some(profile) = &self.opts.profile {
            if account.profiles().any(|p| p.name == profile) {
                request = request.profile(profile);
            } else {
                warn!("ACME server does not offer the `{profile}` profile; using its default");
            }
        }
        let mut order = account
            .new_order(&request)
            .await
            .context("creating the order failed")?;

        let mut cleanup = ChallengeCleanup {
            certs: &self.certs,
            http: &self.http,
            tokens: Vec::new(),
        };
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => bail!("authorization is {other:?}"),
            }
            let mut challenge = authz
                .challenge(kind.acme_type())
                .with_context(|| format!("the CA does not offer {kind} for {ip}"))?;
            let key_authorization = challenge.key_authorization();
            match kind {
                ChallengeKind::TlsAlpn01 => {
                    let answer = tls_alpn_certificate(ip, key_authorization.digest().as_ref())?;
                    self.certs.set_acme_challenge(Some(answer));
                }
                ChallengeKind::Http01 => {
                    let token = challenge.token.clone();
                    self.http
                        .insert(token.clone(), key_authorization.as_str().to_owned());
                    cleanup.tokens.push(token);
                }
            }
            challenge.set_ready().await?;
        }

        let retries = RetryPolicy::new()
            .initial_delay(Duration::from_secs(1))
            .backoff(1.5)
            .timeout(Duration::from_secs(120));
        let status = order
            .poll_ready(&retries)
            .await
            .context("waiting for validation failed")?;
        if status != OrderStatus::Ready {
            let mut details = Vec::new();
            let mut authorizations = order.authorizations();
            while let Some(Ok(mut authz)) = authorizations.next().await {
                if authz.refresh().await.is_ok() {
                    details.extend(
                        authz
                            .challenges
                            .iter()
                            .filter_map(|c| c.error.as_ref())
                            .map(|e| e.to_string()),
                    );
                }
            }
            bail!(
                "validation via {kind} failed ({}); check that the router forwards that port to this PC",
                if details.is_empty() {
                    format!("order is {status:?}")
                } else {
                    details.join("; ")
                }
            );
        }
        drop(cleanup);

        let key_pem = order
            .finalize()
            .await
            .context("finalizing the order failed")?;
        let chain_pem = order
            .poll_certificate(&retries)
            .await
            .context("downloading the certificate failed")?;

        std::fs::create_dir_all(&self.opts.dir)?;
        let (cert_path, key_path) = self.cert_paths(ip);
        cert::write_private(&key_path, key_pem.as_bytes())?;
        std::fs::write(&cert_path, &chain_pem)?;
        Issued::from_pem(&chain_pem, &key_pem)
    }

    async fn account(&self) -> Result<&Account> {
        self.account
            .get_or_try_init(|| async {
                let path = self.opts.dir.join(account_file_name(&self.opts.directory));
                let builder = match &self.opts.ca_root {
                    Some(root) => Account::builder_with_root(root)?,
                    None => Account::builder()?,
                };
                if let Ok(text) = std::fs::read_to_string(&path) {
                    let credentials: AccountCredentials = serde_json::from_str(&text)
                        .with_context(|| format!("invalid ACME account file {}", path.display()))?;
                    return Ok(builder.from_credentials(credentials).await?);
                }
                let contact = self.opts.contact.as_ref().map(|c| format!("mailto:{c}"));
                let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
                let new_account = NewAccount {
                    contact: &contacts,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                };
                let (account, credentials) = builder
                    .create(&new_account, self.opts.directory.clone(), None)
                    .await
                    .with_context(|| {
                        format!("creating an ACME account at {} failed", self.opts.directory)
                    })?;
                std::fs::create_dir_all(&self.opts.dir)?;
                cert::write_private(&path, serde_json::to_string(&credentials)?.as_bytes())?;
                info!("created ACME account at {}", self.opts.directory);
                Ok(account)
            })
            .await
    }
}

/// Removes challenge answers once validation is over, even on error.
struct ChallengeCleanup<'a> {
    certs: &'a CertStore,
    http: &'a HttpChallenges,
    tokens: Vec<String>,
}

impl Drop for ChallengeCleanup<'_> {
    fn drop(&mut self) {
        self.certs.set_acme_challenge(None);
        for token in &self.tokens {
            self.http.remove(token);
        }
    }
}

/// The self-signed certificate that answers a TLS-ALPN-01 challenge (RFC 8737, RFC 8738).
fn tls_alpn_certificate(ip: IpAddr, key_authorization_digest: &[u8]) -> Result<CertifiedKey> {
    let mut params = CertificateParams::new(vec![ip.to_string()])?;
    params.custom_extensions = vec![CustomExtension::new_acme_identifier(
        key_authorization_digest,
    )];
    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    let private = PrivateKeyDer::Pkcs8(key.serialize_der().into());
    Ok(CertifiedKey::new(
        vec![cert.der().clone()],
        any_supported_type(&private)?,
    ))
}

/// One account file per CA, e.g. `account-acme-v02.api.letsencrypt.org.json`.
fn account_file_name(directory: &str) -> String {
    let host = directory
        .split("://")
        .nth(1)
        .unwrap_or(directory)
        .split('/')
        .next()
        .unwrap_or("ca");
    let safe: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("account-{safe}.json")
}

fn until(at: OffsetDateTime) -> Duration {
    Duration::try_from(at - OffsetDateTime::now_utc()).unwrap_or(Duration::ZERO)
}

/// Issued certificates in `dir`: (IP, expiry).
pub fn list_stored(dir: &Path) -> Vec<(String, OffsetDateTime)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "pem"))
        .filter_map(|path| {
            let pem = std::fs::read(&path).ok()?;
            let der = rustls::pki_types::CertificateDer::pem_slice_iter(&pem)
                .next()?
                .ok()?;
            let (_, parsed) = x509_parser::parse_x509_certificate(&der).ok()?;
            let not_after =
                OffsetDateTime::from_unix_timestamp(parsed.validity().not_after.timestamp())
                    .ok()?;
            let name = path.file_stem()?.to_string_lossy().replace('_', ":");
            Some((name, not_after))
        })
        .collect();
    found.sort();
    found
}

/// Default storage location for ACME data under the certificate directory.
pub fn default_dir(cert_dir: &Path) -> PathBuf {
    cert_dir.join("acme")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_account_files_per_ca() {
        assert_eq!(
            account_file_name(LETS_ENCRYPT_STAGING),
            "account-acme-staging-v02.api.letsencrypt.org.json"
        );
        assert_eq!(
            account_file_name("https://localhost:14000/dir"),
            "account-localhost_14000.json"
        );
    }

    #[test]
    fn renews_after_two_thirds_of_lifetime() {
        let not_before = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
        let issued = Issued {
            key: tls_alpn_certificate("203.0.113.7".parse().unwrap(), &[0; 32]).unwrap(),
            pem: PemPair {
                chain: String::new(),
                key: String::new(),
            },
            not_before,
            not_after: not_before + time::Duration::days(6),
        };
        assert_eq!(issued.renew_at(None), not_before + time::Duration::days(4));
        assert_eq!(
            issued.renew_at(Some(Duration::from_secs(86_400))),
            not_before + time::Duration::days(5)
        );
    }
}
