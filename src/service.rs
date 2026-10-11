//! Running hostip in the background: a Windows service with firewall rules, or a
//! systemd unit on Linux.

use std::path::Path;

use crate::config::{Mode, PortSpec};
use crate::portmap::Proto;

pub const SERVICE_NAME: &str = "hostip";
pub const DISPLAY_NAME: &str = "hostip";
pub const DESCRIPTION: &str = "Publishes local apps on this PC's public IP over HTTPS";

/// One inbound firewall rule (all ports of one protocol).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub name: String,
    pub proto: Proto,
    /// netsh syntax: `443,13000,50000-50100`.
    pub ports: String,
}

/// The inbound ports this PC must accept: hostip's TCP listeners, the HTTP port,
/// and the UDP ports that go straight to the apps.
pub fn firewall_rules(specs: &[PortSpec], http_listen: Option<u16>) -> Vec<FirewallRule> {
    let mut tcp: Vec<String> = specs
        .iter()
        .filter(|s| s.mode != Mode::Udp)
        .filter_map(|s| s.listen.map(|p| p.to_string()))
        .collect();
    tcp.extend(http_listen.map(|p| p.to_string()));
    let udp: Vec<String> = specs
        .iter()
        .filter(|s| s.mode == Mode::Udp)
        .map(|s| s.local.to_string())
        .collect();
    let mut rules = Vec::new();
    if !tcp.is_empty() {
        rules.push(FirewallRule {
            name: format!("{SERVICE_NAME} TCP"),
            proto: Proto::Tcp,
            ports: tcp.join(","),
        });
    }
    if !udp.is_empty() {
        rules.push(FirewallRule {
            name: format!("{SERVICE_NAME} UDP"),
            proto: Proto::Udp,
            ports: udp.join(","),
        });
    }
    rules
}

/// `netsh` arguments that add `rule`.
pub fn netsh_add_args(rule: &FirewallRule) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "add".into(),
        "rule".into(),
        format!("name={}", rule.name),
        "dir=in".into(),
        "action=allow".into(),
        format!("protocol={}", rule.proto),
        format!("localport={}", rule.ports),
        "profile=any".into(),
    ]
}

/// `netsh` arguments that delete every rule called `name`.
pub fn netsh_delete_args(name: &str) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "delete".into(),
        "rule".into(),
        format!("name={name}"),
    ]
}

/// A hardened systemd unit that runs `hostip expose --config <config>`.
pub fn systemd_unit(exe: &Path, config: &Path) -> String {
    format!(
        "[Unit]
Description={DESCRIPTION}
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=\"{exe}\" expose --config \"{config}\"
Restart=on-failure
RestartSec=10
DynamicUser=yes
StateDirectory=hostip
Environment=HOME=/var/lib/hostip
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
",
        exe = exe.display(),
        config = config.display()
    )
}

#[cfg(windows)]
pub mod windows {
    //! Windows service install/uninstall and the service entry point.

    use std::ffi::{OsStr, OsString};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::OnceLock;
    use std::time::Duration;

    use anyhow::{Context, Result, bail};
    use tokio_util::sync::CancellationToken;
    use tracing::{error, info};
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
        ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    use super::{DESCRIPTION, DISPLAY_NAME, FirewallRule, SERVICE_NAME};

    const LOCAL_SERVICE: &str = r"NT AUTHORITY\LocalService";

    /// `%ProgramData%\hostip`, where the service keeps its certificates and log.
    pub fn data_dir() -> PathBuf {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("hostip")
    }

    pub fn log_path() -> PathBuf {
        data_dir().join("hostip.log")
    }

    fn run_tool(program: &str, args: &[String]) -> Result<()> {
        let output = Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("cannot run {program}"))?;
        if !output.status.success() {
            bail!(
                "{program} {} failed: {}{}",
                args.join(" "),
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    /// Installs and starts the service; `system` runs it as LocalSystem instead of LocalService.
    pub fn install(config: &Path, rules: &[FirewallRule], system: bool) -> Result<()> {
        let dir = data_dir();
        std::fs::create_dir_all(&dir)?;
        // Only SYSTEM, Administrators and the service account may touch keys and logs.
        let mut grants = vec![
            dir.display().to_string(),
            "/inheritance:r".into(),
            "/grant:r".into(),
            "*S-1-5-18:(OI)(CI)F".into(),
            "/grant:r".into(),
            "*S-1-5-32-544:(OI)(CI)F".into(),
        ];
        if !system {
            grants.extend(["/grant:r".to_string(), "*S-1-5-19:(OI)(CI)M".to_string()]);
        }
        run_tool("icacls", &grants)?;

        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: std::env::current_exe()?,
            launch_arguments: vec![
                "service".into(),
                "run".into(),
                "--config".into(),
                config.as_os_str().to_owned(),
            ],
            dependencies: vec![],
            account_name: (!system).then(|| OsString::from(LOCAL_SERVICE)),
            account_password: None,
        };
        let service = manager
            .create_service(
                &info,
                ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
            )
            .context("creating the service failed (run this from an Administrator prompt)")?;
        service.set_description(DESCRIPTION)?;
        let restart = ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(10),
        };
        service.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![restart.clone(), restart.clone(), restart]),
        })?;
        service.set_failure_actions_on_non_crash_failures(true)?;

        for rule in rules {
            let _ = run_tool("netsh", &super::netsh_delete_args(&rule.name));
            run_tool("netsh", &super::netsh_add_args(rule))?;
        }
        service.start(&[] as &[&OsStr])?;
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager
            .open_service(
                SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .context("the hostip service is not installed (or this prompt is not elevated)")?;
        if service.query_status()?.current_state != ServiceState::Stopped {
            let _ = service.stop();
        }
        service.delete()?;
        for proto in ["TCP", "UDP"] {
            let _ = run_tool(
                "netsh",
                &super::netsh_delete_args(&format!("{SERVICE_NAME} {proto}")),
            );
        }
        Ok(())
    }

    /// What the service runs: given the config and a stop signal, serve until stopped.
    pub type Body = fn(PathBuf, CancellationToken) -> Result<()>;

    static CONFIG: OnceLock<PathBuf> = OnceLock::new();
    static BODY: OnceLock<Body> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    /// Hands this process to the Service Control Manager; returns when the service stops.
    pub fn run(config: PathBuf, body: Body) -> Result<()> {
        let _ = CONFIG.set(config);
        let _ = BODY.set(body);
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .context("not started by the Service Control Manager; use `hostip expose` in a console")
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(e) = run_service() {
            error!("service failed: {e:#}");
        }
    }

    fn status(state: ServiceState, exit: u32) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: if exit == 0 {
                ServiceExitCode::Win32(0)
            } else {
                ServiceExitCode::ServiceSpecific(exit)
            },
            checkpoint: 0,
            wait_hint: Duration::from_secs(15),
            process_id: None,
        }
    }

    fn run_service() -> Result<()> {
        let shutdown = CancellationToken::new();
        let stop = shutdown.clone();
        let handle =
            service_control_handler::register(SERVICE_NAME, move |control| match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    stop.cancel();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            })?;
        handle.set_service_status(status(ServiceState::Running, 0))?;
        info!("service started");

        let config = CONFIG.get().cloned().context("no config")?;
        let body = *BODY.get().context("no service body")?;
        let result = body(config, shutdown);
        if let Err(e) = &result {
            error!("{e:#}");
        }
        handle.set_service_status(status(ServiceState::Stopped, u32::from(result.is_err())))?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_firewall_rules_from_specs() {
        let specs = [
            PortSpec::parse_cli("3000:443").unwrap(),
            PortSpec::parse_cli("8080").unwrap(),
            PortSpec::parse_cli("udp:3478").unwrap(),
            PortSpec::parse_cli("udp:50000-50100").unwrap(),
        ];
        let rules = firewall_rules(&specs, Some(80));
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].ports, "443,18080,80");
        assert_eq!(rules[1].ports, "3478,50000-50100");
        assert_eq!(
            netsh_add_args(&rules[1]).join(" "),
            "advfirewall firewall add rule name=hostip UDP dir=in action=allow protocol=UDP \
             localport=3478,50000-50100 profile=any"
        );
        assert!(firewall_rules(&[], None).is_empty());
    }

    #[test]
    fn writes_a_systemd_unit() {
        let unit = systemd_unit(
            Path::new("/usr/local/bin/hostip"),
            Path::new("/etc/hostip.toml"),
        );
        assert!(
            unit.contains(
                "ExecStart=\"/usr/local/bin/hostip\" expose --config \"/etc/hostip.toml\""
            )
        );
        assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    }
}
