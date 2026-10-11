//! Certificate storage and hot-swappable serving.
//!
//! M1 provides the self-signed fallback (F4). The Let's Encrypt bare-IP
//! certificate (F17) plugs into the same [`CertStore`] later.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

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
    pub generated: bool,
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

/// Serves whichever certificate is current; swapping it never drops connections.
#[derive(Debug)]
pub struct CertStore {
    current: ArcSwap<CertifiedKey>,
}

impl CertStore {
    pub fn new(key: CertifiedKey) -> Arc<Self> {
        Arc::new(Self {
            current: ArcSwap::from_pointee(key),
        })
    }

    pub fn replace(&self, key: CertifiedKey) {
        self.current.store(Arc::new(key));
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
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
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
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
}
