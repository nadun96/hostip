//! Certificate storage and hot-swappable serving.
//!
//! The self-signed certificate (F4) is served until the Let's Encrypt bare-IP
//! certificate (F17, see [`crate::acme`]) is issued and swapped in. In local-CA
//! mode (F5) that certificate is signed by a private CA instead, which devices
//! can install (`hostip cert export-ca`) so browsers stop warning.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::{ArcSwap, ArcSwapOption};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tokio::sync::watch;

const CERT_FILE: &str = "self-signed.pem";
const KEY_FILE: &str = "self-signed.key";
const META_FILE: &str = "self-signed.toml";
/// The leaf signed by the local CA, kept apart from the self-signed one.
const CA_LEAF: &str = "local-ca-leaf";
const CA_DIR: &str = "local-ca";
/// The local CA lives this long; devices that installed it keep trusting it.
const CA_VALIDITY_DAYS: i64 = 3650;

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
    /// `self-signed`, or the local CA's name.
    pub issuer: String,
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
            "{} certificate for [{}], valid until {} ({})",
            if self.issuer == "self-signed" {
                "self-signed".to_owned()
            } else {
                format!("{}-signed", self.issuer)
            },
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
    load_or_generate_with(dir, sans, None)
}

/// Like [`load_or_generate`], but signed by `ca` when given (local-CA mode, F5).
pub fn load_or_generate_with(
    dir: &Path,
    sans: &[String],
    ca: Option<&LocalCa>,
) -> Result<(CertifiedKey, CertInfo)> {
    let wanted: BTreeSet<String> = sans.iter().cloned().collect();
    let (cert_path, key_path, meta_path) = match ca {
        None => (dir.join(CERT_FILE), dir.join(KEY_FILE), dir.join(META_FILE)),
        Some(_) => (
            dir.join(format!("{CA_LEAF}.pem")),
            dir.join(format!("{CA_LEAF}.key")),
            dir.join(format!("{CA_LEAF}.toml")),
        ),
    };
    let issuer = ca.map_or_else(|| "self-signed".to_owned(), |ca| ca.name.clone());

    if let Some(meta) = read_meta(&meta_path)
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
            issuer,
        };
        return Ok((key, info));
    }

    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let (cert_pem, key_pem, not_after) = generate(&wanted, ca)?;
    std::fs::write(&cert_path, &cert_pem)?;
    write_private(&key_path, key_pem.as_bytes())?;
    let meta = Meta {
        sans: wanted.clone(),
        not_after: not_after.unix_timestamp(),
    };
    std::fs::write(&meta_path, toml::to_string(&meta)?)?;

    let key = load_pem(&cert_path, &key_path)?;
    let info = CertInfo {
        sans: wanted.into_iter().collect(),
        not_after,
        cert_path,
        key_path,
        generated: true,
        issuer,
    };
    Ok((key, info))
}

/// Reads the stored certificate info without generating anything.
pub fn stored_info(dir: &Path) -> Option<CertInfo> {
    let meta = read_meta(&dir.join(META_FILE))?;
    Some(CertInfo {
        sans: meta.sans.into_iter().collect(),
        not_after: OffsetDateTime::from_unix_timestamp(meta.not_after).ok()?,
        cert_path: dir.join(CERT_FILE),
        key_path: dir.join(KEY_FILE),
        generated: false,
        issuer: "self-signed".to_owned(),
    })
}

fn read_meta(path: &Path) -> Option<Meta> {
    toml::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// A leaf certificate for `sans`: self-signed, or signed by `ca`.
fn generate(
    sans: &BTreeSet<String>,
    ca: Option<&LocalCa>,
) -> Result<(String, String, OffsetDateTime)> {
    let mut params = CertificateParams::new(sans.iter().cloned().collect::<Vec<_>>())
        .context("invalid certificate name")?;
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        if ca.is_some() {
            "hostip"
        } else {
            "hostip self-signed"
        },
    );
    params.distinguished_name = dn;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(VALIDITY_DAYS);
    let key = KeyPair::generate()?;
    let pem = match ca {
        None => params.self_signed(&key)?.pem(),
        Some(ca) => {
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let leaf = params.signed_by(&key, &ca.issuer()?)?;
            // Serve the CA after the leaf so clients can build the chain.
            format!("{}{}", leaf.pem(), ca.cert_pem)
        }
    };
    Ok((pem, key.serialize_pem(), params.not_after))
}

/// How to make a device trust the local CA; `{file}` is the exported certificate.
pub const CA_INSTALL_HELP: &str = "
Install it on each device that should trust hostip without a warning:
  Windows   double-click {file} > Install Certificate > Local Machine >
            \"Trusted Root Certification Authorities\"
            (or, as Administrator: certutil -addstore -f Root {file})
  macOS     sudo security add-trusted-cert -d -r trustRoot \\
              -k /Library/Keychains/System.keychain {file}
  Linux     sudo cp {file} /usr/local/share/ca-certificates/hop-local-ca.crt
            && sudo update-ca-certificates     (Debian, Ubuntu)
  Firefox   Settings > Privacy & Security > Certificates > View Certificates >
            Authorities > Import
  Android   Settings > Security > Encryption & credentials > Install a certificate > CA certificate
  iPhone    open the file (AirDrop / mail), install the profile in Settings, then enable it in
            Settings > General > About > Certificate Trust Settings

Only install it on your own devices, and keep the CA key (local-ca/ca.key in the
certificate folder) private: whoever has it can issue certificates those devices trust.";

/// A private certificate authority for local-CA mode (F5), created once in
/// `<cert-dir>/local-ca` and reused, so devices only install it once.
#[derive(Debug, Clone)]
pub struct LocalCa {
    /// Shown in certificate stores, e.g. "Hop local CA 3f9a2c".
    pub name: String,
    pub cert_pem: String,
    pub cert_path: PathBuf,
    key_pem: String,
}

#[derive(Serialize, Deserialize)]
struct CaMeta {
    name: String,
}

impl LocalCa {
    /// Loads the local CA from `cert_dir`, creating it on first use; the bool is
    /// true when it was created now.
    pub fn load_or_create(cert_dir: &Path) -> Result<(Self, bool)> {
        let dir = cert_dir.join(CA_DIR);
        let (cert_path, key_path, meta_path) =
            (dir.join("ca.pem"), dir.join("ca.key"), dir.join("ca.toml"));
        if let (Ok(cert_pem), Ok(key_pem), Ok(meta)) = (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
            std::fs::read_to_string(&meta_path),
        ) {
            let meta: CaMeta = toml::from_str(&meta)
                .with_context(|| format!("invalid {}", meta_path.display()))?;
            let ca = Self {
                name: meta.name,
                cert_pem,
                cert_path,
                key_pem,
            };
            ca.issuer()?;
            return Ok((ca, false));
        }

        std::fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        let mut tag = [0u8; 3];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut tag)
            .map_err(|_| anyhow::anyhow!("no secure randomness"))?;
        let name = format!("Hop local CA {:02x}{:02x}{:02x}", tag[0], tag[1], tag[2]);
        let key = KeyPair::generate()?;
        let mut params = Self::params(&name);
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(CA_VALIDITY_DAYS);
        let cert_pem = params.self_signed(&key)?.pem();
        let key_pem = key.serialize_pem();
        std::fs::write(&cert_path, &cert_pem)?;
        write_private(&key_path, key_pem.as_bytes())?;
        std::fs::write(&meta_path, toml::to_string(&CaMeta { name: name.clone() })?)?;
        Ok((
            Self {
                name,
                cert_pem,
                cert_path,
                key_pem,
            },
            true,
        ))
    }

    /// The fields an issuer needs; the same name and key reproduce the stored CA.
    fn params(name: &str) -> CertificateParams {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        dn.push(DnType::OrganizationName, "Hop (hostip) local CA");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
    }

    fn issuer(&self) -> Result<Issuer<'static, KeyPair>> {
        let key = KeyPair::from_pem(&self.key_pem).context("invalid local CA key")?;
        Ok(Issuer::new(Self::params(&self.name), key))
    }
}

/// Builds a rustls signing key from PEM text.
pub fn certified_key_from_pem(chain_pem: &str, key_pem: &str) -> Result<CertifiedKey> {
    let certs =
        CertificateDer::pem_slice_iter(chain_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
    Ok(CertifiedKey::new(certs, any_supported_type(&key)?))
}

/// Reloads a user-supplied certificate whenever its files change (e.g. after an
/// external renewal), checking every 30 seconds.
pub async fn watch_files(
    certs: Arc<CertStore>,
    cert_path: PathBuf,
    key_path: PathBuf,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let modified = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    let mut last = (modified(&cert_path), modified(&key_path));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
        }
        let now = (modified(&cert_path), modified(&key_path));
        if now == last {
            continue;
        }
        last = now;
        let loaded = (|| -> Result<(CertifiedKey, PemPair)> {
            let pem = PemPair {
                chain: std::fs::read_to_string(&cert_path)?,
                key: std::fs::read_to_string(&key_path)?,
            };
            Ok((certified_key_from_pem(&pem.chain, &pem.key)?, pem))
        })();
        match loaded {
            Ok((key, pem)) => {
                certs.replace_with_pem(key, pem);
                tracing::info!("reloaded the certificate from {}", cert_path.display());
            }
            // Often a half-written pair during renewal; the next check picks it up.
            Err(e) => tracing::warn!("cannot reload {}: {e:#}", cert_path.display()),
        }
    }
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

    #[tokio::test(start_paused = true)]
    async fn reloads_user_certificate_files() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (key_a, info_a) = load_or_generate(a.path(), &sans(&["a.example"])).unwrap();
        let (_, info_b) = load_or_generate(b.path(), &sans(&["b.example"])).unwrap();
        let store = CertStore::new(key_a);
        let shutdown = tokio_util::sync::CancellationToken::new();
        tokio::spawn(watch_files(
            store.clone(),
            info_a.cert_path.clone(),
            info_a.key_path.clone(),
            shutdown.clone(),
        ));
        tokio::task::yield_now().await;
        std::thread::sleep(std::time::Duration::from_millis(20)); // distinct mtimes
        std::fs::copy(&info_b.cert_path, &info_a.cert_path).unwrap();
        std::fs::copy(&info_b.key_path, &info_a.key_path).unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            store.current_pem().unwrap().chain,
            std::fs::read_to_string(&info_b.cert_path).unwrap()
        );
        shutdown.cancel();
    }

    #[test]
    fn regenerates_when_ip_changes() {
        let dir = tempfile::tempdir().unwrap();
        load_or_generate(dir.path(), &sans(&["203.0.113.7"])).unwrap();
        let (_, info) = load_or_generate(dir.path(), &sans(&["198.51.100.9"])).unwrap();
        assert!(info.generated);
        assert_eq!(info.sans, sans(&["198.51.100.9"]));
    }

    fn verify_with(ca: &LocalCa, chain_pem: &str, name: &str) -> Result<(), rustls::Error> {
        use rustls::client::WebPkiServerVerifier;
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{ServerName, UnixTime};
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(ca.cert_pem.as_bytes()).unwrap())
            .unwrap();
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(chain_pem.as_bytes())
                .collect::<Result<_, _>>()
                .unwrap();
        verifier
            .verify_server_cert(
                &chain[0],
                &chain[1..],
                &ServerName::try_from(name.to_owned()).unwrap(),
                &[],
                UnixTime::now(),
            )
            .map(|_| ())
    }

    #[test]
    fn local_ca_is_created_once() {
        let dir = tempfile::tempdir().unwrap();
        let (first, created) = LocalCa::load_or_create(dir.path()).unwrap();
        assert!(created);
        assert!(first.name.starts_with("Hop local CA "));
        let (again, created) = LocalCa::load_or_create(dir.path()).unwrap();
        assert!(!created);
        assert_eq!(first.cert_pem, again.cert_pem);
        assert_eq!(first.name, again.name);
    }

    #[test]
    fn ca_signed_leaf_is_trusted_by_the_ca_only() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, _) = LocalCa::load_or_create(dir.path()).unwrap();
        let (_, info) =
            load_or_generate_with(dir.path(), &sans(&["192.168.1.10", "localhost"]), Some(&ca))
                .unwrap();
        assert!(info.generated);
        assert_eq!(info.issuer, ca.name);
        let chain = std::fs::read_to_string(&info.cert_path).unwrap();
        verify_with(&ca, &chain, "192.168.1.10").expect("IP name trusted");
        verify_with(&ca, &chain, "localhost").expect("DNS name trusted");
        assert!(
            verify_with(&ca, &chain, "203.0.113.7").is_err(),
            "name not in the certificate"
        );

        // A reloaded CA (from its files) still signs certificates that validate.
        let (reloaded, _) = LocalCa::load_or_create(dir.path()).unwrap();
        let other = tempfile::tempdir().unwrap();
        let (_, info) =
            load_or_generate_with(other.path(), &sans(&["10.0.0.5"]), Some(&reloaded)).unwrap();
        let chain = std::fs::read_to_string(&info.cert_path).unwrap();
        verify_with(&ca, &chain, "10.0.0.5").expect("reloaded CA signs valid certificates");

        // Another CA does not vouch for it.
        let elsewhere = tempfile::tempdir().unwrap();
        let (stranger, _) = LocalCa::load_or_create(elsewhere.path()).unwrap();
        assert!(verify_with(&stranger, &chain, "10.0.0.5").is_err());
    }

    #[test]
    fn self_signed_and_ca_leaf_are_kept_apart() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, _) = LocalCa::load_or_create(dir.path()).unwrap();
        let (_, plain) = load_or_generate(dir.path(), &sans(&["localhost"])).unwrap();
        let (_, signed) =
            load_or_generate_with(dir.path(), &sans(&["localhost"]), Some(&ca)).unwrap();
        assert_ne!(plain.cert_path, signed.cert_path);
        assert_eq!(plain.issuer, "self-signed");
        assert!(signed.to_string().contains("Hop local CA"), "{signed}");
    }
}
