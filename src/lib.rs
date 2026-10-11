//! hostip: publish local apps on this machine's public IP over HTTPS.
//!
//! See `docs/REQUIREMENTS.md` for the requirements and design.

pub mod cert;
pub mod config;
pub mod io;
pub mod proxy;
pub mod publicip;
pub mod server;
