//! The Hop window: settings and tools on the left, live status and the log on the right.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use hostip::status::{self, Status};
use time::OffsetDateTime;

use crate::options::{Login, Settings};
use crate::runner::{self, Log, Running};

const ACCENT: Color32 = Color32::from_rgb(0x3B, 0x82, 0xF6);
const OK: Color32 = Color32::from_rgb(0x16, 0xA3, 0x4A);
const WARN: Color32 = Color32::from_rgb(0xD9, 0x77, 0x06);
const STATUS_POLL: Duration = Duration::from_secs(1);

struct Tool {
    title: String,
    output: Arc<Mutex<Option<String>>>,
    open: bool,
}

pub struct HopApp {
    settings: Settings,
    log: Log,
    running: Option<Running>,
    status: Option<Status>,
    status_file: PathBuf,
    polled: Option<Instant>,
    error: Option<String>,
    tool: Option<Tool>,
    qr: Option<(String, egui::TextureHandle)>,
}

impl HopApp {
    pub fn new() -> Self {
        Self {
            settings: Settings::default(),
            log: Log::default(),
            running: None,
            status: None,
            status_file: status::path(&hostip::paths::default_data_dir()),
            polled: None,
            error: None,
            tool: None,
            qr: None,
        }
    }

    fn now() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    /// The status hostip reports, if it is running (here or elsewhere).
    fn live_status(&self) -> Option<&Status> {
        self.status.as_ref().filter(|s| s.is_running(Self::now()))
    }

    fn start(&mut self, ctx: &egui::Context) {
        self.error = None;
        let args = match self.settings.expose_args() {
            Ok(args) => args,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        self.log.clear();
        self.log.push(format!("$ hostip {}", display_args(&args)));
        let repaint = {
            let ctx = ctx.clone();
            move || ctx.request_repaint()
        };
        match Running::start(&args, &self.log, repaint) {
            Ok(running) => self.running = Some(running),
            Err(e) => {
                self.error = Some(format!(
                    "Could not start {}: {e}. Keep hop-gui next to hostip, or put hostip on the PATH.",
                    runner::hostip_path().display()
                ));
            }
        }
    }

    fn run_tool(&mut self, ctx: &egui::Context, title: &str, args: Vec<String>) {
        let ctx = ctx.clone();
        self.tool = Some(Tool {
            title: title.to_owned(),
            output: runner::run_tool(args, move || ctx.request_repaint()),
            open: true,
        });
    }

    /// The login hostip generated in quick mode, read from its output.
    fn generated_login(&self) -> Option<(String, String)> {
        let lines = self.log.lines();
        let value = |key: &str| {
            lines
                .iter()
                .rev()
                .find_map(|l| l.trim().strip_prefix(key).map(|v| v.trim().to_owned()))
        };
        Some((value("user:")?, value("password:")?))
    }

    fn qr_texture(&mut self, ctx: &egui::Context, url: &str) -> Option<egui::TextureHandle> {
        if let Some((cached, tex)) = &self.qr
            && cached == url
        {
            return Some(tex.clone());
        }
        let code = qrcode::QrCode::new(url).ok()?;
        let width = code.width();
        let quiet = 2;
        let size = width + 2 * quiet;
        let mut image = egui::ColorImage::filled([size, size], Color32::WHITE);
        for (i, color) in code.to_colors().into_iter().enumerate() {
            if color == qrcode::Color::Dark {
                image[(i % width + quiet, i / width + quiet)] = Color32::BLACK;
            }
        }
        let tex = ctx.load_texture("share-qr", image, egui::TextureOptions::NEAREST);
        self.qr = Some((url.to_owned(), tex.clone()));
        Some(tex)
    }

    fn header(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            logo(ui, 30.0);
            ui.vertical(|ui| {
                ui.label(RichText::new("Hop").size(22.0).strong());
                ui.label(RichText::new("Publish apps on your PC over HTTPS").weak());
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (text, color) = match (&self.running, self.live_status()) {
                    (Some(r), _) if r.is_stopping() => ("Stopping…", WARN),
                    (Some(_), Some(_)) => ("Running", OK),
                    (Some(_), None) => ("Starting…", WARN),
                    (None, Some(_)) => ("Running outside Hop", ACCENT),
                    (None, None) => ("Stopped", Color32::GRAY),
                };
                ui.label(RichText::new(text).color(color).strong().size(15.0));
                // A drawn dot: the default fonts have no filled-circle glyph.
                let (dot, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                ui.painter().circle_filled(dot.center(), 5.0, color);
            });
        });
    }

    fn settings_panel(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let busy = self.running.is_some();
        let elsewhere = !busy && self.live_status().is_some();
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_enabled_ui(!busy, |ui| {
                ui.heading("Publish");
                ui.label("Ports");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.ports)
                        .hint_text("3000 8080:443 udp:3478"),
                );
                ui.label(
                    RichText::new("local[:public], tcp: / udp: for raw ports, e.g. udp:50000-50100")
                        .small()
                        .weak(),
                );
                ui.add_space(4.0);
                ui.label("Config file (optional)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.config)
                        .hint_text("path to hostip.toml"),
                );
                ui.add_space(6.0);
                ui.checkbox(&mut self.settings.acme, "Trusted certificate (Let's Encrypt)");
                ui.checkbox(&mut self.settings.upnp, "Open router ports automatically (UPnP)");
                ui.checkbox(&mut self.settings.local_ca, "Sign with my local CA (private use)");
                ui.add_space(6.0);
                ui.label("Visitors log in with");
                ui.radio_value(&mut self.settings.login, Login::Generated, "a generated password");
                ui.radio_value(&mut self.settings.login, Login::Custom, "my user and password");
                if self.settings.login == Login::Custom {
                    ui.horizontal(|ui| {
                        ui.label("User");
                        ui.text_edit_singleline(&mut self.settings.user);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Password");
                        ui.add(egui::TextEdit::singleline(&mut self.settings.password).password(true));
                    });
                }
                ui.radio_value(
                    &mut self.settings.login,
                    Login::Open,
                    "no login (anyone with the link)",
                );
                ui.add_space(6.0);
                ui.collapsing("More options", |ui| {
                    ui.label(RichText::new("Extra `hostip expose` options").small());
                    ui.add(
                        egui::TextEdit::singleline(&mut self.settings.extra)
                            .hint_text("--access-log --max-connections 100"),
                    );
                });
            });

            ui.add_space(10.0);
            if let Some(running) = &mut self.running {
                let label = if running.is_stopping() { "Stopping…" } else { "Stop" };
                if ui
                    .add_enabled(
                        !running.is_stopping(),
                        egui::Button::new(RichText::new(label).size(16.0))
                            .min_size(egui::vec2(ui.available_width(), 34.0)),
                    )
                    .clicked()
                {
                    running.stop();
                }
            } else if ui
                .add_enabled(
                    !elsewhere,
                    egui::Button::new(RichText::new("Start").size(16.0).color(Color32::WHITE))
                        .fill(ACCENT)
                        .min_size(egui::vec2(ui.available_width(), 34.0)),
                )
                .clicked()
            {
                self.start(&ctx);
            }
            if elsewhere {
                ui.label(
                    RichText::new("hostip is already running (e.g. as a service); its status is shown here.")
                        .small()
                        .color(ACCENT),
                );
            }
            if let Some(error) = &self.error {
                ui.colored_label(WARN, error);
            }

            ui.add_space(14.0);
            ui.separator();
            ui.heading("Tools");
            if ui
                .button("Check reachability from the internet")
                .on_hover_text("Runs `hostip check` with these ports; uses the relay in your config file, if any")
                .clicked()
            {
                match self.settings.check_args() {
                    Ok(args) => self.run_tool(&ctx, "Reachability check", args),
                    Err(e) => self.error = Some(e),
                }
            }
            if ui
                .button("Export my local CA…")
                .on_hover_text("Writes hop-local-ca.crt to your home folder, with install steps")
                .clicked()
            {
                let out = home_dir().join("hop-local-ca.crt");
                self.run_tool(
                    &ctx,
                    "Local CA",
                    vec![
                        "cert".into(),
                        "export-ca".into(),
                        "--out".into(),
                        out.display().to_string(),
                    ],
                );
            }
        });
    }

    fn status_panel(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let Some(status) = self.live_status().cloned() else {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("Not running").size(18.0).weak());
                ui.label(
                    RichText::new("Choose the ports of your app on the left and press Start.")
                        .weak(),
                );
            });
            return;
        };
        let now = Self::now();
        let login = self.generated_login().filter(|_| self.running.is_some());

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new("Visitors use").strong());
                    for url in &status.urls {
                        ui.horizontal(|ui| {
                            ui.hyperlink(url);
                            if ui.small_button("Copy").clicked() {
                                ctx.copy_text(url.clone());
                            }
                        });
                    }
                    if let Some((user, password)) = &login {
                        ui.add_space(6.0);
                        ui.label(RichText::new("Login").strong());
                        ui.horizontal(|ui| {
                            ui.monospace(format!("{user} / {password}"));
                            if ui.small_button("Copy password").clicked() {
                                ctx.copy_text(password.clone());
                            }
                        });
                    }
                    ui.add_space(6.0);
                    egui::Grid::new("facts")
                        .num_columns(2)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            ui.label("Public IP");
                            ui.label(
                                status
                                    .public_ip
                                    .map_or("unknown".into(), |ip| ip.to_string()),
                            );
                            ui.end_row();
                            ui.label("Mode");
                            ui.label(&status.mode);
                            ui.end_row();
                            ui.label("Connections");
                            ui.label(status.open_connections.to_string());
                            ui.end_row();
                            if let Some(cert) = &status.certificate {
                                let days = (cert.not_after - now) as f64 / 86_400.0;
                                ui.label("Certificate");
                                ui.label(format!(
                                    "{}\n{} (expires {}, {days:.1} days)",
                                    cert.issuer,
                                    cert.subject,
                                    date(cert.not_after)
                                ))
                                .on_hover_text("The certificate visitors see");
                                ui.end_row();
                            }
                            if let Some(acme) = &status.acme {
                                ui.label("Renewal");
                                match &acme.error {
                                    None => ui.colored_label(
                                        OK,
                                        format!("OK {}; next {}", date(acme.at), date(acme.next)),
                                    ),
                                    Some(e) => ui.colored_label(
                                        WARN,
                                        format!(
                                            "failed {}: {e}; retry {}",
                                            date(acme.at),
                                            date(acme.next)
                                        ),
                                    ),
                                };
                                ui.end_row();
                            }
                        });
                });
                if let Some(url) = status.urls.iter().find(|u| u.starts_with("https://"))
                    && let Some(tex) = self.qr_texture(&ctx, url)
                {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                        ui.vertical(|ui| {
                            ui.add(
                                egui::Image::new(&tex).fit_to_exact_size(egui::vec2(150.0, 150.0)),
                            );
                            ui.label(RichText::new("Scan to open on a phone").small().weak());
                        });
                    });
                }
            });
        });
    }

    fn log_view(&self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Log").strong());
            if ui.small_button("Copy all").clicked() {
                ui.ctx().copy_text(self.log.lines().join("\n"));
            }
        });
        egui::Frame::group(ui.style()).show(ui, |ui| {
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for line in self.log.lines() {
                        ui.label(RichText::new(line).monospace().size(12.0));
                    }
                });
        });
    }

    fn tool_window(&mut self, ctx: &egui::Context) {
        let Some(tool) = &mut self.tool else { return };
        let output = tool.output.lock().unwrap().clone();
        egui::Window::new(&tool.title)
            .open(&mut tool.open)
            .default_width(760.0)
            .default_pos(ctx.content_rect().center() - egui::vec2(380.0, 230.0))
            .show(ctx, |ui| match output {
                None => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Running…");
                    });
                }
                Some(text) => {
                    egui::ScrollArea::vertical()
                        .max_height(420.0)
                        .show(ui, |ui| {
                            ui.label(RichText::new(text).monospace().size(12.0));
                        });
                }
            });
        if !tool.open {
            self.tool = None;
        }
    }
}

impl eframe::App for HopApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(running) = &mut self.running
            && let Some(message) = running.poll()
        {
            self.log.push(message);
            self.running = None;
        }
        if self.polled.is_none_or(|t| t.elapsed() >= STATUS_POLL) {
            self.status = status::read(&self.status_file).ok();
            self.polled = Some(Instant::now());
        }
        ctx.request_repaint_after(STATUS_POLL);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        egui::Panel::top("header").show(ui, |ui| {
            ui.add_space(6.0);
            self.header(ui);
            ui.add_space(6.0);
        });
        egui::Panel::left("settings")
            .exact_size(330.0)
            .show(ui, |ui| {
                ui.add_space(6.0);
                self.settings_panel(ui);
            });
        egui::CentralPanel::default().show(ui, |ui| {
            self.status_panel(ui);
            self.log_view(ui);
        });
        self.tool_window(&ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Dropping `Running` stops hostip gracefully.
        self.running = None;
    }
}

/// The arguments as shown in the log, with any password hidden.
fn display_args(args: &[String]) -> String {
    let mut out = Vec::new();
    let mut hide_next = false;
    for arg in args {
        if hide_next {
            let user = arg.split_once(':').map_or("", |(u, _)| u);
            out.push(format!("{user}:••••••"));
            hide_next = false;
        } else {
            hide_next = arg == "--auth";
            out.push(arg.clone());
        }
    }
    out.join(" ")
}

fn date(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix).map_or_else(
        |_| unix.to_string(),
        |t| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02} UTC",
                t.year(),
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute()
            )
        },
    )
}

fn home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
}

/// The Hop mark: a rounded square with an arc hopping from home to the internet.
fn logo(ui: &mut egui::Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, size * 0.24, ACCENT);
    let p = |x: f32, y: f32| rect.min + egui::vec2(x * size, y * size);
    let stroke = egui::Stroke::new(size * 0.08, Color32::WHITE);
    let arc: Vec<egui::Pos2> = (0..=16)
        .map(|i| {
            let t = i as f32 / 16.0;
            let (a, b, c, d) = (p(0.28, 0.70), p(0.33, 0.23), p(0.70, 0.23), p(0.74, 0.62));
            let u = 1.0 - t;
            egui::pos2(
                u * u * u * a.x + 3.0 * u * u * t * b.x + 3.0 * u * t * t * c.x + t * t * t * d.x,
                u * u * u * a.y + 3.0 * u * u * t * b.y + 3.0 * u * t * t * c.y + t * t * t * d.y,
            )
        })
        .collect();
    painter.add(egui::Shape::line(arc, stroke));
    painter.add(egui::Shape::line(
        vec![p(0.65, 0.56), p(0.74, 0.66), p(0.83, 0.56)],
        stroke,
    ));
    painter.circle_filled(p(0.28, 0.70), size * 0.08, Color32::WHITE);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_are_hidden_in_the_log() {
        let args: Vec<String> = ["expose", "3000", "--auth", "ana:secret", "--no-upnp"]
            .map(String::from)
            .to_vec();
        assert_eq!(
            display_args(&args),
            "expose 3000 --auth ana:•••••• --no-upnp"
        );
    }

    #[test]
    fn dates_are_readable() {
        assert_eq!(date(1_800_000_000), "2027-01-15 08:00 UTC");
    }
}
