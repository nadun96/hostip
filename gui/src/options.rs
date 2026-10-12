//! The settings form and the `hostip` command line it turns into.

/// How visitors log in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Login {
    /// Anyone with the link (needed for public conference links).
    Open,
    /// hostip generates a password and prints it once (quick mode).
    Generated,
    /// A user and password chosen here.
    Custom,
}

#[derive(Debug, Clone)]
pub struct Settings {
    /// Port specs as typed, e.g. `3000 8080:443 udp:3478`.
    pub ports: String,
    /// Optional config file; its `[[port]]` entries are added to `ports`.
    pub config: String,
    pub acme: bool,
    pub upnp: bool,
    pub local_ca: bool,
    pub login: Login,
    pub user: String,
    pub password: String,
    /// More `hostip expose` options, split on whitespace.
    pub extra: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            ports: "3000".into(),
            config: String::new(),
            acme: true,
            upnp: true,
            local_ca: false,
            login: Login::Generated,
            user: "hop".into(),
            password: String::new(),
            extra: String::new(),
        }
    }
}

impl Settings {
    pub fn port_list(&self) -> Vec<String> {
        self.ports.split_whitespace().map(String::from).collect()
    }

    /// Arguments for `hostip` that publish these settings.
    pub fn expose_args(&self) -> Result<Vec<String>, String> {
        let ports = self.port_list();
        let config = self.config.trim();
        if ports.is_empty() && config.is_empty() {
            return Err("Enter at least one port, or choose a config file.".into());
        }
        let mut args = Vec::new();
        match self.login {
            // Quick mode is `hostip PORTS...`: hostip generates and prints the login.
            Login::Generated => {
                if ports.is_empty() {
                    return Err(
                        "A generated login needs ports; with only a config file, choose another login option."
                            .into(),
                    );
                }
                args.extend(ports.iter().cloned());
            }
            Login::Open | Login::Custom => {
                args.push("expose".into());
                args.extend(ports.iter().cloned());
            }
        }
        if self.login == Login::Custom {
            let (user, password) = (self.user.trim(), self.password.as_str());
            if user.is_empty() || password.is_empty() || user.contains(':') {
                return Err("Enter a user (without ':') and a password for the login.".into());
            }
            args.push("--auth".into());
            args.push(format!("{user}:{password}"));
        }
        if !config.is_empty() {
            args.push("--config".into());
            args.push(config.into());
        }
        if !self.acme {
            args.push("--no-acme".into());
        }
        if !self.upnp {
            args.push("--no-upnp".into());
        }
        if self.local_ca {
            args.push("--local-ca".into());
        }
        args.extend(self.extra.split_whitespace().map(String::from));
        // Lets the app stop hostip gracefully by closing its stdin.
        args.push("--stop-on-stdin-eof".into());
        Ok(args)
    }

    /// Arguments for `hostip check` with the same ports.
    pub fn check_args(&self) -> Result<Vec<String>, String> {
        let ports = self.port_list();
        let config = self.config.trim();
        if ports.is_empty() && config.is_empty() {
            return Err("Enter at least one port, or choose a config file.".into());
        }
        let mut args = vec!["check".to_owned()];
        args.extend(ports);
        if !config.is_empty() {
            args.push("--config".into());
            args.push(config.into());
        }
        if !self.upnp {
            args.push("--no-upnp".into());
        }
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(ports: &str) -> Settings {
        Settings {
            ports: ports.into(),
            ..Settings::default()
        }
    }

    #[test]
    fn generated_login_uses_quick_mode() {
        let args = settings("3000 udp:3478").expose_args().unwrap();
        assert_eq!(args, ["3000", "udp:3478", "--stop-on-stdin-eof"]);
    }

    #[test]
    fn open_and_custom_logins_use_expose() {
        let mut s = settings("3000:443");
        s.login = Login::Open;
        s.acme = false;
        s.upnp = false;
        s.local_ca = true;
        s.extra = "--access-log  --max-connections 50".into();
        assert_eq!(
            s.expose_args().unwrap(),
            [
                "expose",
                "3000:443",
                "--no-acme",
                "--no-upnp",
                "--local-ca",
                "--access-log",
                "--max-connections",
                "50",
                "--stop-on-stdin-eof"
            ]
        );
        s.login = Login::Custom;
        s.user = "ana".into();
        s.password = "s3cret pass".into();
        let args = s.expose_args().unwrap();
        assert_eq!(
            args[..4],
            ["expose", "3000:443", "--auth", "ana:s3cret pass"]
        );
    }

    #[test]
    fn config_file_and_validation() {
        let mut s = settings("");
        assert!(s.expose_args().is_err(), "nothing to publish");
        s.config = "C:\\hop\\hostip.toml".into();
        assert!(s.expose_args().is_err(), "generated login needs ports");
        s.login = Login::Open;
        assert_eq!(
            s.expose_args().unwrap(),
            [
                "expose",
                "--config",
                "C:\\hop\\hostip.toml",
                "--stop-on-stdin-eof"
            ]
        );
        s.login = Login::Custom;
        s.user = "a:b".into();
        s.password = "x".into();
        assert!(s.expose_args().is_err(), "':' in the user");
    }

    #[test]
    fn check_uses_the_same_ports() {
        let mut s = settings("3000 udp:50000-50010");
        s.upnp = false;
        assert_eq!(
            s.check_args().unwrap(),
            ["check", "3000", "udp:50000-50010", "--no-upnp"]
        );
    }
}
