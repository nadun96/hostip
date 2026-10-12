//! Certificate storage and hot-swappable serving.
//!
//! The self-signed certificate (F4) is served until the Let's Encrypt bare-IP
//! certificate (F17, see [`crate::acme`]) is issued and swapped in, unless the
//! user supplies their own certificate files (F6), which are then served instead.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::{ArcSwap, ArcSwapOption};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

const CERT_FILE: &str = "self-signed.pem";
const KEY_FILE: &str = "self-signed.key";
const META_FILE: &str = "self-signed.toml";

/// Browsers reject leaf certificates valid for more than 398 days.
const VALIDITY_DAYS: i64 = 397;
/// Regenerate once fewer than this many days remain.
const RENEW_DAYS: i64 = 30;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Meta {
    sans: BTreeSet<String>,
    not_after: i64,
}

/// Information about the certificate currently being served.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub sans: Vec<String>,
    pub not_after: OffsetDateTime,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub generated: bool,
}

impl CertInfo {
    pub fn read_pem(&self) -> Result<PemPair> {
        Ok(PemPair {
            chain: std::fs::read_to_string(&self.cert_path)?,
            key: std::fs::read_to_string(&self.key_path)?,
        })
    }
}

impl fmt::Display for CertInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "self-signed certificate for [{}], valid until {} ({})",
            self.sans.join(", "),
            self.not_after.date(),
            self.cert_path.display()
        )
    }
}

/// ALPN protocol used by ACME TLS-ALPN-01 validation (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// Serves whichever certificate is current; swapping it never drops connections.
#[derive(Debug)]
pub struct CertStore {
    current: ArcSwap<CertifiedKey>,
    /// PEM text of `current`, when known (for exporting it to other programs, F28).
    current_pem: ArcSwapOption<PemPair>,
    /// Answer for a pending TLS-ALPN-01 challenge, if any.
    acme_challenge: ArcSwapOption<CertifiedKey>,
    /// Bumped on every replacement.
    changes: watch::Sender<u64>,
}

/// A certificate chain and its private key as PEM text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemPair {
    pub chain: String,
    pub key: String,
}

impl CertStore {
    pub fn new(key: CertifiedKey) -> Arc<Self> {
        Arc::new(Self {
            current: ArcSwap::from_pointee(key),
            current_pem: ArcSwapOption::empty(),
            acme_challenge: ArcSwapOption::empty(),
            changes: watch::Sender::new(0),
        })
    }

    pub fn replace(&self, key: CertifiedKey) {
        self.current.store(Arc::new(key));
        self.current_pem.store(None);
        self.changes.send_modify(|n| *n += 1);
    }

    pub fn replace_with_pem(&self, key: CertifiedKey, pem: PemPair) {
        self.current.store(Arc::new(key));
        self.current_pem.store(Some(Arc::new(pem)));
        self.changes.send_modify(|n| *n += 1);
    }

    pub fn current_pem(&self) -> Option<Arc<PemPair>> {
        self.current_pem.load_full()
    }

    /// Notifies on every certificate replacement.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    pub fn current(&self) -> Arc<CertifiedKey> {
        self.current.load_full()
    }

    pub fn set_acme_challenge(&self, key: Option<CertifiedKey>) {
        self.acme_challenge.store(key.map(Arc::new));
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let is_acme = hello
            .alpn()
            .is_some_and(|mut protocols| protocols.any(|p| p == ACME_TLS_ALPN));
        if is_acme {
            return self.acme_challenge.load_full();
        }
        Some(self.current.load_full())
    }
}

/// Loads the self-signed certificate from `dir`, generating a new one when it is
/// missing, expiring, or does not cover every name in `sans`.
pub fn load_or_generate(dir: &Path, sans: &[String]) -> Result<(CertifiedKey, CertInfo)> {
    let wanted: BTreeSet<String> = sans.iter().cloned().collect();
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);

    if let Some(meta) = read_meta(dir)
        && meta.sans.is_superset(&wanted)
        && meta.not_after - OffsetDateTime::now_utc().unix_timestamp() > RENEW_DAYS * 86_400
        && let Ok(key) = load_pem(&cert_path, &key_path)
    {
        let info = CertInfo {
            sans: meta.sans.into_iter().collect(),
            not_after: OffsetDateTime::from_unix_timestamp(meta.not_after)?,
            cert_path,
            key_path,
            generated: false,
        };
        return Ok((key, info));
    }

    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let (cert_pem, key_pem, not_after) = generate(&wanted)?;
    std::fs::write(&cert_path, &cert_pem)?;
    write_private(&key_path, key_pem.as_bytes())?;
    let meta = Meta {
        sans: wanted.clone(),
        not_after: not_after.unix_timestamp(),
    };
    std::fs::write(dir.join(META_FILE), toml::to_string(&meta)?)?;

    let key = load_pem(&cert_path, &key_path)?;
    let info = CertInfo {
        sans: wanted.into_iter().collect(),
        not_after,
        cert_path,
        key_path,
        generated: true,
    };
    Ok((key, info))
}

/// Reads the stored certificate info without generating anything.
pub fn stored_info(dir: &Path) -> Option<CertInfo> {
    let meta = read_meta(dir)?;
    Some(CertInfo {
        sans: meta.sans.into_iter().collect(),
        not_after: OffsetDateTime::from_unix_timestamp(meta.not_after).ok()?,
        cert_path: dir.join(CERT_FILE),
        key_path: dir.join(KEY_FILE),
        generated: false,
    })
}

fn read_meta(dir: &Path) -> Option<Meta> {
    toml::from_str(&std::fs::read_to_string(dir.join(META_FILE)).ok()?).ok()
}

fn generate(sans: &BTreeSet<String>) -> Result<(String, String, OffsetDateTime)> {
    let mut params = CertificateParams::new(sans.iter().cloned().collect::<Vec<_>>())
        .context("invalid certificate name")?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "hostip self-signed");
    params.distinguished_name = dn;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(VALIDITY_DAYS);
    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem(), params.not_after))
}

/// Builds a rustls signing key from PEM text.
pub fn certified_key_from_pem(chain_pem: &str, key_pem: &str) -> Result<CertifiedKey> {
    let certs =
        CertificateDer::pem_slice_iter(chain_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
    Ok(CertifiedKey::new(certs, any_supported_type(&key)?))
}

/// Builds a rustls signing key from PEM files.
pub fn load_pem(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("cannot read {}", cert_path.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("cannot read {}", key_path.display()))?;
    Ok(CertifiedKey::new(certs, any_supported_type(&key)?))
}

/// A certificate and key the user supplied as PEM files (F6).
#[derive(Debug)]
pub struct UserCert {
    pub key: CertifiedKey,
    pub pem: PemPair,
    /// Names (DNS and IP) the leaf certificate covers.
    pub sans: Vec<String>,
    pub not_after: OffsetDateTime,
}

/// Loads a user-supplied certificate chain and its private key, checking that
/// they belong together.
pub fn load_user(cert_path: &Path, key_path: &Path) -> Result<UserCert> {
    let chain = std::fs::read_to_string(cert_path)
        .with_context(|| format!("cannot read {}", cert_path.display()))?;
    let key_pem = std::fs::read_to_string(key_path)
        .with_context(|| format!("cannot read {}", key_path.display()))?;
    let key = certified_key_from_pem(&chain, &key_pem)
        .with_context(|| format!("invalid certificate files {}", cert_path.display()))?;
    let leaf = key
        .cert
        .first()
        .with_context(|| format!("no certificate in {}", cert_path.display()))?;
    key.keys_match().map_err(|e| {
        anyhow!(
            "{} does not match the certificate in {}: {e}",
            key_path.display(),
            cert_path.display()
        )
    })?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf)
        .map_err(|e| anyhow!("invalid certificate in {}: {e}", cert_path.display()))?;
    let not_after = OffsetDateTime::from_unix_timestamp(parsed.validity().not_after.timestamp())?;
    let mut sans = Vec::new();
    if let Ok(Some(ext)) = parsed.subject_alternative_name() {
        use x509_parser::extensions::GeneralName;
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => sans.push((*dns).to_owned()),
                GeneralName::IPAddress(bytes) => {
                    if let Ok(v4) = <[u8; 4]>::try_from(*bytes) {
                        sans.push(std::net::IpAddr::from(v4).to_string());
                    } else if let Ok(v6) = <[u8; 16]>::try_from(*bytes) {
                        sans.push(std::net::IpAddr::from(v6).to_string());
                    }
                }
                _ => {}
            }
        }
    }
    Ok(UserCert {
        key,
        pem: PemPair {
            chain,
            key: key_pem,
        },
        sans,
        not_after,
    })
}

impl fmt::Display for UserCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "certificate for [{}], valid until {}",
            self.sans.join(", "),
            self.not_after.date()
        )
    }
}

/// Loads the user's certificate files and serves them, re-reading both whenever
/// either changes on disk (e.g. after certbot renews them). A broken update keeps
/// the previous certificate in service.
pub fn serve_user(
    certs: Arc<CertStore>,
    cert_path: PathBuf,
    key_path: PathBuf,
    interval: std::time::Duration,
    shutdown: CancellationToken,
) -> impl Future<Output = ()> {
    let stamp = move |c: &Path, k: &Path| (modified(c), modified(k));
    async move {
        let mut last = stamp(&cert_path, &key_path);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(interval) => {}
            }
            let now = stamp(&cert_path, &key_path);
            if now == last {
                continue;
            }
            // Give a writer replacing both files a moment to finish the second one.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            last = stamp(&cert_path, &key_path);
            match load_user(&cert_path, &key_path) {
                Ok(user) => {
                    info!("reloaded {user}");
                    certs.replace_with_pem(user.key, user.pem);
                }
                Err(e) => warn!("keeping the current certificate: {e:#}"),
            }
        }
    }
}

fn modified(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Checks that a certificate covers `name` (an IP address or host name).
pub fn covers(sans: &[String], name: &str) -> bool {
    sans.iter().any(|san| {
        san.eq_ignore_ascii_case(name)
            || san.strip_prefix("*.").is_some_and(|base| {
                name.split_once('.').is_some_and(|(label, rest)| {
                    !label.is_empty() && rest.eq_ignore_ascii_case(base)
                })
            })
    })
}

/// Rejects a certificate path pair given only half-way.
pub fn user_paths(
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
) -> Result<Option<(PathBuf, PathBuf)>> {
    match (cert, key) {
        (Some(c), Some(k)) => Ok(Some((c, k))),
        (None, None) => Ok(None),
        _ => bail!("a certificate needs both `cert` and `key`"),
    }
}

/// Writes a private key readable only by the current user (S6).
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)?;
    }
    // Windows: files under %ProgramData%\hostip inherit the folder ACL; tightening it
    // to SYSTEM + Administrators is part of the service installer (M2.5).
    #[cfg(not(unix))]
    std::fs::write(path, data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sans(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn generates_then_reuses() {
        let dir = tempfile::tempdir().unwrap();
        let (_, first) =
            load_or_generate(dir.path(), &sans(&["203.0.113.7", "localhost"])).unwrap();
        assert!(first.generated);
        let (_, second) = load_or_generate(dir.path(), &sans(&["localhost"])).unwrap();
        assert!(
            !second.generated,
            "subset of names must reuse the certificate"
        );
        assert_eq!(second.sans, sans(&["203.0.113.7", "localhost"]));
    }

    #[test]
    fn regenerates_when_ip_changes() {
        let dir = tempfile::tempdir().unwrap();
        load_or_generate(dir.path(), &sans(&["203.0.113.7"])).unwrap();
        let (_, info) = load_or_generate(dir.path(), &sans(&["198.51.100.9"])).unwrap();
        assert!(info.generated);
        assert_eq!(info.sans, sans(&["198.51.100.9"]));
    }

    fn write_pair(dir: &Path, names: &[&str]) -> (PathBuf, PathBuf) {
        let (cert_pem, key_pem, _) =
            generate(&names.iter().map(|s| s.to_string()).collect()).unwrap();
        let (c, k) = (dir.join("user.pem"), dir.join("user.key"));
        std::fs::write(&c, cert_pem).unwrap();
        std::fs::write(&k, key_pem).unwrap();
        (c, k)
    }

    #[test]
    fn loads_user_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let (c, k) = write_pair(dir.path(), &["example.org", "203.0.113.7", "::1"]);
        let user = load_user(&c, &k).unwrap();
        assert_eq!(user.sans, sans(&["203.0.113.7", "::1", "example.org"]));
        assert!(user.not_after > OffsetDateTime::now_utc());
    }

    #[test]
    fn rejects_mismatched_key() {
        let dir = tempfile::tempdir().unwrap();
        let (c, _) = write_pair(dir.path(), &["example.org"]);
        let other = KeyPair::generate().unwrap();
        let k = dir.path().join("other.key");
        std::fs::write(&k, other.serialize_pem()).unwrap();
        let err = load_user(&c, &k).unwrap_err();
        assert!(format!("{err:#}").contains("does not match"), "{err:#}");
    }

    #[test]
    fn name_coverage() {
        let names = sans(&["203.0.113.7", "*.example.org", "Host.test"]);
        assert!(covers(&names, "203.0.113.7"));
        assert!(covers(&names, "a.example.org"));
        assert!(covers(&names, "host.test"));
        assert!(!covers(&names, "example.org"));
        assert!(!covers(&names, "a.b.example.org"));
        assert!(!covers(&names, "198.51.100.9"));
    }

    #[test]
    fn half_given_paths_are_an_error() {
        assert!(user_paths(Some("c".into()), None).is_err());
        assert!(user_paths(None, None).unwrap().is_none());
    }

    #[tokio::test]
    async fn reloads_changed_files() {
        let dir = tempfile::tempdir().unwrap();
        let (c, k) = write_pair(dir.path(), &["one.test"]);
        let user = load_user(&c, &k).unwrap();
        let store = CertStore::new(user.key);
        let mut changes = store.subscribe();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(serve_user(
            store.clone(),
            c.clone(),
            k.clone(),
            std::time::Duration::from_millis(50),
            shutdown.clone(),
        ));
        // Coarse file-system timestamps: make sure the rewrite gets a new mtime.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        write_pair(dir.path(), &["two.test"]);
        tokio::time::timeout(std::time::Duration::from_secs(10), changes.changed())
            .await
            .expect("reload")
            .unwrap();
        assert!(
            store
                .current_pem()
                .unwrap()
                .chain
                .contains("BEGIN CERTIFICATE")
        );
        let leaf = store.current().cert[0].clone();
        let (_, parsed) = x509_parser::parse_x509_certificate(&leaf).unwrap();
        let san = parsed.subject_alternative_name().unwrap().unwrap();
        assert_eq!(
            format!("{:?}", san.value.general_names[0]),
            "DNSName(\"two.test\")"
        );
        shutdown.cancel();
        task.await.unwrap();
    }
}
