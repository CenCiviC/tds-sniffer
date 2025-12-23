use rust_wireshark::gui::GuiState;
use rust_wireshark::Extractor;
use rust_wireshark::output::SqlEvent;
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
            // 한글 폰트 설정
            let mut fonts = egui::FontDefinitions::default();

            // Windows 시스템 폰트 경로 시도
            #[cfg(target_os = "windows")]
            {
                use std::path::Path;

                // 여러 한글 폰트 경로 시도
                let font_paths = [
                    "C:/Windows/Fonts/malgun.ttf", // 맑은 고딕
                    "C:/Windows/Fonts/gulim.ttc", // 굴림
                    "C:/Windows/Fonts/batang.ttc", // 바탕
                ];

                for font_path in &font_paths {
                    if Path::new(font_path).exists() {
                        if let Ok(font_data) = std::fs::read(font_path) {
                            fonts.font_data.insert(
                                "Korean".to_owned(),
                                egui::FontData::from_owned(font_data),
                            );
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

            // 실시간 이벤트 채널
            let (event_tx, event_rx) = mpsc::channel();
            // 중지 신호 채널
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
        // 캡처 시작 요청 처리
        if self.state.is_capturing && !self.state.capture_started {
            if let (Some(ref interface), Some(ref sender)) =
                (&self.state.selected_interface, &self.event_sender)
            {
                let interface = interface.clone();
                let use_tds = self.state.use_tds_parsing;
                let sender = sender.clone();
                let stop_rx = self.stop_receiver.take();

                thread::spawn(move || {
                    let mut extractor = Extractor::new(use_tds);
                    let stop_rx = stop_rx;

                    // 중지 신호를 받으면 종료
                    let stop_handle = thread::spawn(move || {
                        if let Some(rx) = stop_rx {
                            let _ = rx.recv();
                        }
                    });

                    // 실시간 캡처 시작
                    if let Err(e) = extractor.start_live_capture(&interface, sender) {
                        eprintln!("캡처 오류: {}", e);
                    }

                    // 중지 신호 대기
                    let _ = stop_handle.join();
                });

                self.state.capture_started = true;
            }
        }

        rust_wireshark::gui::show_gui(ctx, &mut self.state);
        ctx.request_repaint();
    }
}
