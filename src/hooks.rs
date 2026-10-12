//! Hand the public IP and the certificate to other programs (F27, F28): files on disk
//! plus user commands run on change, e.g. to restart a WebRTC media server so it
//! announces the new IP, or to reload a TURN server with the renewed certificate.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::process::Command;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::cert::{self, CertStore, PemPair};

const HOOK_TIMEOUT: Duration = Duration::from_secs(120);

/// Where to write the current IP and what to run when it changes.
#[derive(Debug, Clone, Default)]
pub struct IpHooks {
    pub ip_file: Option<PathBuf>,
    pub on_change: Option<String>,
}

/// Where to export the certificate and what to run after each export.
#[derive(Debug, Clone)]
pub struct CertExport {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub on_renew: Option<String>,
}

/// Runs `command` through the system shell with extra environment variables.
pub async fn run_hook(command: &str, env: &[(&str, String)]) -> Result<()> {
    #[cfg(windows)]
    let mut cmd = {
        // cmd.exe parses its own command line; Rust's argument quoting (\") would
        // mangle commands that contain quotes, so pass it through untouched.
        let mut c = Command::new("cmd");
        c.arg("/C").raw_arg(command);
        c
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    };
    cmd.envs(env.iter().map(|(k, v)| (*k, v.as_str())))
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(HOOK_TIMEOUT, cmd.output())
        .await
        .with_context(|| format!("`{command}` did not finish within {HOOK_TIMEOUT:?}"))?
        .with_context(|| format!("cannot run `{command}`"))?;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        info!("hook: {line}");
    }
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        warn!("hook: {line}");
    }
    if !output.status.success() {
        bail!("`{command}` failed with {}", output.status);
    }
    Ok(())
}

/// Writes `contents` via a temporary file, so readers never see a half-written file.
fn write_atomic(path: &Path, contents: &[u8], private: bool) -> Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    if private {
        cert::write_private(&tmp, contents)?;
    } else {
        std::fs::write(&tmp, contents)?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("cannot write {}", path.display()))
}

/// Publishes the current public IP at start and after every change.
/// The last IP handed to the hooks in this process, so a config reload does not
/// re-run `on_ip_change` (and e.g. restart a media server) for an unchanged IP.
static LAST_PUBLISHED: std::sync::Mutex<Option<IpAddr>> = std::sync::Mutex::new(None);

pub async fn watch_ip(mut ip: watch::Receiver<Option<IpAddr>>, hooks: IpHooks) {
    loop {
        let current = *ip.borrow_and_update();
        let previous = *LAST_PUBLISHED.lock().unwrap();
        if let Some(addr) = current
            && current != previous
        {
            publish_ip(addr, previous, &hooks).await;
            *LAST_PUBLISHED.lock().unwrap() = current;
        }
        if ip.changed().await.is_err() {
            return;
        }
    }
}

async fn publish_ip(addr: IpAddr, previous: Option<IpAddr>, hooks: &IpHooks) {
    if let Some(path) = &hooks.ip_file
        && let Err(e) = write_atomic(path, format!("{addr}\n").as_bytes(), false)
    {
        warn!("cannot write the public IP to {}: {e:#}", path.display());
    }
    if let Some(command) = &hooks.on_change {
        let env = [
            ("HOSTIP_PUBLIC_IP", addr.to_string()),
            (
                "HOSTIP_PREVIOUS_IP",
                previous.map(|p| p.to_string()).unwrap_or_default(),
            ),
        ];
        match run_hook(command, &env).await {
            Ok(()) => info!("on_ip_change hook ran for {addr}"),
            Err(e) => warn!("on_ip_change hook failed: {e:#}"),
        }
    }
}

/// Exports the served certificate whenever it changes (only certificates with known PEM).
pub async fn export_certs(certs: Arc<CertStore>, export: CertExport) {
    let mut changes = certs.subscribe();
    let mut last: Option<Arc<PemPair>> = None;
    loop {
        if let Some(pem) = certs.current_pem()
            && last.as_deref() != Some(&*pem)
        {
            match write_export(&pem, &export).await {
                Ok(()) => info!("exported the certificate to {}", export.cert.display()),
                Err(e) => warn!("certificate export failed: {e:#}"),
            }
            last = Some(pem);
        }
        if changes.changed().await.is_err() {
            return;
        }
    }
}

async fn write_export(pem: &PemPair, export: &CertExport) -> Result<()> {
    write_atomic(&export.key, pem.key.as_bytes(), true)?;
    write_atomic(&export.cert, pem.chain.as_bytes(), false)?;
    if let Some(command) = &export.on_renew {
        let env = [
            ("HOSTIP_CERT_FILE", export.cert.display().to_string()),
            ("HOSTIP_KEY_FILE", export.key.display().to_string()),
        ];
        run_hook(command, &env).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A command that appends `$VAR` to `file`, for the current platform's shell.
    fn append_env(var: &str, file: &Path) -> String {
        if cfg!(windows) {
            format!("echo %{var}%>> \"{}\"", file.display())
        } else {
            format!("echo \"${var}\" >> '{}'", file.display())
        }
    }

    #[tokio::test]
    async fn publishes_ip_changes_to_file_and_hook() {
        let dir = tempfile::tempdir().unwrap();
        let ip_file = dir.path().join("public_ip.txt");
        let log = dir.path().join("hook.log");
        let (tx, rx) = watch::channel(Some("203.0.113.7".parse().unwrap()));
        let hooks = IpHooks {
            ip_file: Some(ip_file.clone()),
            on_change: Some(append_env("HOSTIP_PUBLIC_IP", &log)),
        };
        let task = tokio::spawn(watch_ip(rx, hooks));

        let wait_for = |path: PathBuf, text: &'static str| async move {
            for _ in 0..100 {
                if std::fs::read_to_string(&path).is_ok_and(|s| s.contains(text)) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("{} never contained {text}", path.display());
        };
        wait_for(log.clone(), "203.0.113.7").await;
        assert_eq!(std::fs::read_to_string(&ip_file).unwrap(), "203.0.113.7\n");

        tx.send(Some("198.51.100.9".parse().unwrap())).unwrap();
        wait_for(log.clone(), "198.51.100.9").await;
        assert_eq!(std::fs::read_to_string(&ip_file).unwrap(), "198.51.100.9\n");
        drop(tx);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn exports_certificates_when_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let (key, info) = cert::load_or_generate(dir.path(), &["localhost".into()]).unwrap();
        let store = CertStore::new(key);
        let export = CertExport {
            cert: dir.path().join("out/cert.pem"),
            key: dir.path().join("out/key.pem"),
            on_renew: Some(append_env("HOSTIP_CERT_FILE", &dir.path().join("hook.log"))),
        };
        tokio::spawn(export_certs(store.clone(), export.clone()));

        let pem = info.read_pem().unwrap();
        let (key, _) = cert::load_or_generate(dir.path(), &["localhost".into()]).unwrap();
        store.replace_with_pem(key, pem.clone());
        for _ in 0..100 {
            if export.cert.exists() && dir.path().join("hook.log").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(std::fs::read_to_string(&export.cert).unwrap(), pem.chain);
        assert_eq!(std::fs::read_to_string(&export.key).unwrap(), pem.key);
        assert!(
            std::fs::read_to_string(dir.path().join("hook.log"))
                .unwrap()
                .contains("cert.pem")
        );
    }

    #[tokio::test]
    async fn reports_failing_hooks() {
        let err = run_hook("exit 3", &[]).await.unwrap_err();
        assert!(err.to_string().contains("failed"), "{err}");
    }
}
