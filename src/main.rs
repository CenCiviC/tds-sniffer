use rust_wireshark::gui::GuiState;
use rust_wireshark::output::SqlEvent;
use rust_wireshark::Extractor;
use std::sync::mpsc;
use std::thread;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1400.0, 900.0]),
        ..Default::default()
    };

    eframe::run_native(
        "MSSQL TDS SQL 추출기",
        options,
        Box::new(|cc| {
            let fonts = egui::FontDefinitions::default();

            // Windows system font path trial
            #[cfg(target_os = "windows")]
            {
                use std::path::Path;

                let font_paths = [
                    "C:/Windows/Fonts/malgun.ttf", // 맑은 고딕
                    "C:/Windows/Fonts/gulim.ttc",  // 굴림
                    "C:/Windows/Fonts/batang.ttc", // 바탕
                ];

                for font_path in &font_paths {
                    if Path::new(font_path).exists() {
                        if let Ok(font_data) = std::fs::read(font_path) {
                            fonts
                                .font_data
                                .insert("Korean".to_owned(), egui::FontData::from_owned(font_data));
                            fonts
                                .families
                                .get_mut(&egui::FontFamily::Proportional)
                                .unwrap()
                                .insert(0, "Korean".to_owned());
                            break;
                        }
                    }
                }
            }

            cc.egui_ctx.set_fonts(fonts);

            // Real-time event channel(thread)
            let (event_tx, event_rx) = mpsc::channel();
            // Stop signal channel(thread)
            let (stop_tx, stop_rx) = mpsc::channel();

            let mut state = GuiState::new();
            state.set_event_receiver(event_rx);
            state.set_stop_sender(stop_tx);
            Box::new(GuiApp {
                state,
                event_sender: Some(event_tx),
                stop_receiver: Some(stop_rx),
            })
        }),
    )?;

    Ok(())
}

struct GuiApp {
    state: GuiState,
    event_sender: Option<mpsc::Sender<SqlEvent>>,
    stop_receiver: Option<mpsc::Receiver<()>>,
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle capture start request
        if self.state.is_capturing && !self.state.capture_started {
            // If stop_receiver is None, create a new channel (for restart)
            if self.stop_receiver.is_none() {
                let (stop_tx, stop_rx) = mpsc::channel();
                self.state.set_stop_sender(stop_tx);
                self.stop_receiver = Some(stop_rx);
            }

            if let (Some(ref interface), Some(ref sender)) =
                (&self.state.selected_interface, &self.event_sender)
            {
                let interface = interface.clone();
                let sender = sender.clone();
                let stop_rx = self.stop_receiver.take();

                thread::spawn(move || {
                    let mut extractor = Extractor::new(true);

                    if let Some(stop_rx) = stop_rx {
                        // Start real-time capture (pass stop signal receiver)
                        if let Err(e) = extractor.start_live_capture(&interface, sender, stop_rx) {
                            eprintln!("캡처 오류: {}", e);
                        }
                    }
                });

                self.state.capture_started = true;
            }
        }

        rust_wireshark::gui::show_gui(ctx, &mut self.state);
        ctx.request_repaint();
    }
}
