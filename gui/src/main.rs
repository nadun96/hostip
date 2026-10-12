//! Hop: a desktop app for hostip. It runs the `hostip` command next to it,
//! shows the links, certificate and log, and offers the common tools.

// No console window on Windows.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod options;
mod runner;

fn main() -> eframe::Result {
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title("Hop")
        .with_inner_size([1040.0, 680.0])
        .with_min_inner_size([760.0, 480.0]);
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png")) {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "Hop",
        options,
        Box::new(|_cc| Ok(Box::new(app::HopApp::new()))),
    )
}
