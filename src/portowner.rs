//! Names the program holding a TCP port, so "port already in use" errors can say
//! who to stop (IIS/HTTP.sys, Skype, VMware, another web server...).
//!
//! Linux reads `/proc`; Windows asks `netstat` and `tasklist`; macOS and other
//! Unixes ask `lsof`. Every step is best effort: `None` when it cannot tell.

use std::process::Command;

/// The program listening on TCP `port`, e.g. `nginx (pid 812)`.
pub fn tcp_listener(port: u16) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        linux(port)
    }
    #[cfg(windows)]
    {
        windows(port)
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let out = run(
            "lsof",
            &["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-Fpc"],
        )?;
        parse_lsof(&out).map(|(pid, name)| format!("{name} (pid {pid})"))
    }
}

/// Builds the message for a failed bind on `port`.
pub fn describe_bind_error(addr: &str, port: u16, e: &std::io::Error) -> String {
    if e.kind() != std::io::ErrorKind::AddrInUse {
        return format!("cannot listen on {addr}: {e}");
    }
    match tcp_listener(port) {
        Some(owner) => format!(
            "cannot listen on {addr}: port {port} is already in use by {owner}; \
             stop it or publish on another port"
        ),
        None => format!("cannot listen on {addr}: port {port} is already in use"),
    }
}

#[allow(dead_code)]
fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(target_os = "linux")]
fn linux(port: u16) -> Option<String> {
    let mut inodes = Vec::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(table) {
            inodes.extend(parse_proc_net(&text, port));
        }
    }
    if inodes.is_empty() {
        return None;
    }
    let wanted: Vec<String> = inodes.iter().map(|i| format!("socket:[{i}]")).collect();
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        // Other users' processes are not readable without privileges; skipped.
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path())
                && wanted.iter().any(|w| target.as_os_str() == w.as_str())
            {
                let name = std::fs::read_to_string(entry.path().join("comm"))
                    .map(|n| n.trim().to_owned())
                    .unwrap_or_else(|_| "unknown".into());
                return Some(format!("{name} (pid {pid})"));
            }
        }
    }
    Some("a program of another user (run as administrator/root to see which)".into())
}

/// Socket inodes listening on `port` in a `/proc/net/tcp{,6}` table.
#[allow(dead_code)]
fn parse_proc_net(text: &str, port: u16) -> Vec<u64> {
    const LISTEN: &str = "0A";
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let local_port = cols.get(1)?.rsplit_once(':')?.1;
            (u16::from_str_radix(local_port, 16).ok()? == port && *cols.get(3)? == LISTEN)
                .then(|| cols.get(9)?.parse().ok())
                .flatten()
        })
        .filter(|&inode| inode != 0)
        .collect()
}

#[cfg(windows)]
fn windows(port: u16) -> Option<String> {
    let pid = parse_netstat(&run("netstat", &["-ano", "-p", "TCP"])?, port)
        .or_else(|| parse_netstat(&run("netstat", &["-ano", "-p", "TCPv6"])?, port))?;
    if pid == 4 {
        return Some(
            "Windows (HTTP.sys: IIS or another Windows web service; \
             `netsh http show servicestate` lists them)"
                .into(),
        );
    }
    let name = run(
        "tasklist",
        &["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"],
    )
    .and_then(|out| parse_tasklist(&out))
    .unwrap_or_else(|| "unknown".into());
    Some(format!("{name} (pid {pid})"))
}

/// PID listening on `port` in `netstat -ano` output.
#[allow(dead_code)]
fn parse_netstat(text: &str, port: u16) -> Option<u32> {
    text.lines().find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let [proto, local, _remote, state, pid] = cols[..] else {
            return None;
        };
        let local_port: u16 = local.rsplit_once(':')?.1.parse().ok()?;
        (proto.starts_with("TCP") && state == "LISTENING" && local_port == port)
            .then(|| pid.parse().ok())
            .flatten()
    })
}

/// Image name from `tasklist /FO CSV /NH` output (`"nginx.exe","812",...`).
#[allow(dead_code)]
fn parse_tasklist(text: &str) -> Option<String> {
    let first = text.lines().next()?.strip_prefix('"')?;
    Some(first.split_once('"')?.0.to_owned()).filter(|n| !n.is_empty())
}

/// (pid, command) from `lsof -F pc` output.
#[allow(dead_code)]
fn parse_lsof(text: &str) -> Option<(u32, String)> {
    let mut pid = None;
    for line in text.lines() {
        if let Some(p) = line.strip_prefix('p') {
            pid = p.parse().ok();
        } else if let (Some(c), Some(pid)) = (line.strip_prefix('c'), pid) {
            return Some((pid, c.to_owned()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_proc_net_tcp() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31337 1 0000000000000000 100 0 0 10 0
   1: 0100007F:01BB 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 20 4 30 10 -1
   2: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777 1 0000000000000000 100 0 0 10 0";
        assert_eq!(
            parse_proc_net(table, 443),
            vec![31337],
            "only the LISTEN row"
        );
        assert_eq!(parse_proc_net(table, 8080), vec![777]);
        assert!(parse_proc_net(table, 22).is_empty());
    }

    #[test]
    fn reads_netstat_and_tasklist() {
        let netstat = "
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1032
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4
  TCP    192.168.1.10:443       203.0.113.7:51000      ESTABLISHED     4
  TCP    [::]:8443              [::]:0                 LISTENING       5120
";
        assert_eq!(parse_netstat(netstat, 443), Some(4));
        assert_eq!(parse_netstat(netstat, 8443), Some(5120));
        assert_eq!(parse_netstat(netstat, 80), None);
        assert_eq!(
            parse_tasklist("\"vmware-hostd.exe\",\"5120\",\"Services\",\"0\",\"12,345 K\"\r\n"),
            Some("vmware-hostd.exe".into())
        );
        assert_eq!(parse_tasklist("INFO: No tasks are running"), None);
    }

    #[test]
    fn reads_lsof() {
        assert_eq!(
            parse_lsof("p812\ncnginx\nf6\n"),
            Some((812, "nginx".into()))
        );
        assert_eq!(parse_lsof(""), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finds_this_process() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let owner = tcp_listener(port).expect("owner of our own port");
        assert!(
            owner.contains(&format!("pid {}", std::process::id())),
            "{owner}"
        );
        let err = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap_err();
        let text = describe_bind_error(&format!("127.0.0.1:{port}"), port, &err);
        assert!(text.contains("already in use by"), "{text}");
    }
}
