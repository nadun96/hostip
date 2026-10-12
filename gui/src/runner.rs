//! Runs the `hostip` command for the app: the long-running `expose`, and
//! one-shot tools like `check` and `cert export-ca`.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Lines kept in the log view.
const MAX_LINES: usize = 2000;
/// How long a graceful stop may take before hostip is killed.
const STOP_GRACE: Duration = Duration::from_secs(10);

/// The `hostip` executable: next to this app if present, otherwise on PATH.
pub fn hostip_path() -> PathBuf {
    let name = if cfg!(windows) {
        "hostip.exe"
    } else {
        "hostip"
    };
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(name)))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

fn command(args: &[String]) -> Command {
    let mut cmd = Command::new(hostip_path());
    cmd.args(args)
        // Plain text logs: no colour codes in the log view.
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Removes ANSI escape sequences (colours) from a line.
pub fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Shared log lines, appended by reader threads.
#[derive(Clone, Default)]
pub struct Log(Arc<Mutex<VecDeque<String>>>);

impl Log {
    pub fn push(&self, line: impl Into<String>) {
        let mut lines = self.0.lock().unwrap();
        if lines.len() == MAX_LINES {
            lines.pop_front();
        }
        lines.push_back(line.into());
    }

    pub fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().iter().cloned().collect()
    }

    pub fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}

fn pump(stream: impl Read + Send + 'static, log: Log, repaint: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            log.push(strip_ansi(&line));
            repaint();
        }
    });
}

/// A running `hostip expose`.
pub struct Running {
    child: Child,
    /// Closing it asks hostip to shut down (`--stop-on-stdin-eof`).
    stdin: Option<ChildStdin>,
    stopping: Option<Instant>,
}

impl Running {
    pub fn start(
        args: &[String],
        log: &Log,
        repaint: impl Fn() + Clone + Send + 'static,
    ) -> std::io::Result<Self> {
        let mut child = command(args).stdin(Stdio::piped()).spawn()?;
        let stdin = child.stdin.take();
        if let Some(out) = child.stdout.take() {
            pump(out, log.clone(), repaint.clone());
        }
        if let Some(err) = child.stderr.take() {
            pump(err, log.clone(), repaint);
        }
        Ok(Self {
            child,
            stdin,
            stopping: None,
        })
    }

    /// Asks hostip to stop gracefully (it removes router mappings on the way out).
    pub fn stop(&mut self) {
        self.stdin = None;
        self.stopping.get_or_insert_with(Instant::now);
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.is_some()
    }

    /// The exit message once hostip has ended; kills it if a stop takes too long.
    pub fn poll(&mut self) -> Option<String> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(match status.code() {
                Some(0) => "hostip stopped.".to_owned(),
                Some(code) => format!("hostip exited with code {code}."),
                None => "hostip was stopped.".to_owned(),
            }),
            Ok(None) => {
                if self.stopping.is_some_and(|t| t.elapsed() > STOP_GRACE) {
                    let _ = self.child.kill();
                }
                None
            }
            Err(e) => Some(format!("cannot watch hostip: {e}")),
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        // Closing stdin already makes hostip shut down; make sure it does.
        self.stdin = None;
        let deadline = Instant::now() + STOP_GRACE;
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Runs a short `hostip` command in the background; its output arrives in the result.
pub fn run_tool(
    args: Vec<String>,
    repaint: impl Fn() + Send + 'static,
) -> Arc<Mutex<Option<String>>> {
    let result = Arc::new(Mutex::new(None));
    let slot = result.clone();
    std::thread::spawn(move || {
        let text = match command(&args).stdin(Stdio::null()).output() {
            Ok(out) => {
                let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                strip_ansi(&text)
            }
            Err(e) => format!("cannot run {}: {e}", hostip_path().display()),
        };
        *slot.lock().unwrap() = Some(text);
        repaint();
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_colour_codes() {
        assert_eq!(
            strip_ansi("\u{1b}[2m2026\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m hostip: ready"),
            "2026  INFO hostip: ready"
        );
        assert_eq!(strip_ansi("plain"), "plain");
    }

    #[test]
    fn log_keeps_the_last_lines() {
        let log = Log::default();
        for i in 0..MAX_LINES + 5 {
            log.push(i.to_string());
        }
        let lines = log.lines();
        assert_eq!(lines.len(), MAX_LINES);
        assert_eq!(lines[0], "5");
    }
}
