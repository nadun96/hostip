//! Default locations shared by the `hostip` command and the Hop GUI.

use std::path::PathBuf;

/// Where certificates are kept: `%ProgramData%\hostip\certs` on Windows,
/// `~/.hostip/certs` elsewhere.
pub fn default_cert_dir() -> PathBuf {
    if cfg!(windows)
        && let Some(dir) = std::env::var_os("ProgramData")
    {
        return PathBuf::from(dir).join("hostip").join("certs");
    }
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".hostip").join("certs"),
        None => PathBuf::from(".hostip").join("certs"),
    }
}

/// The folder holding the certificates, the status file and other state.
pub fn default_data_dir() -> PathBuf {
    default_cert_dir()
        .parent()
        .map_or_else(|| PathBuf::from(".hostip"), PathBuf::from)
}
