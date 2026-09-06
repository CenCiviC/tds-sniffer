//! MSSQL TDS SQL 추출기 GUI 진입점.

use rust_wireshark::gui::{show_gui, GuiState};
use std::time::Duration;

/// 한글 표시를 위해 시도할 Windows 시스템 폰트.
const KOREAN_FONTS: [&str; 3] = [
    "C:/Windows/Fonts/malgun.ttf", // 맑은 고딕
    "C:/Windows/Fonts/gulim.ttc",  // 굴림
    "C:/Windows/Fonts/batang.ttc", // 바탕
];

fn main() -> Result<(), eframe::Error> {
    if !cfg!(target_os = "windows") {
        eprintln!("오류: 이 프로그램은 Windows에서만 실행할 수 있습니다.");
        eprintln!("Error: This program can only run on Windows.");
        std::process::exit(1);
    }

    env_logger::init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1400.0, 900.0]),
        ..Default::default()
    };

    eframe::run_native(
        "MSSQL TDS SQL 추출기",
        options,
        Box::new(|cc| {
            install_korean_font(&cc.egui_ctx);
            Box::new(App {
                state: GuiState::detect(),
            })
        }),
    )
}

/// 시스템에 있는 첫 번째 한글 폰트를 UI 기본 글꼴 앞에 끼워 넣는다.
fn install_korean_font(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // `read`가 이미 없는 파일에 실패하므로 `exists()` 사전 검사는 중복 syscall이자
    // TOCTOU 창이다.
    let loaded = KOREAN_FONTS
        .iter()
        .find_map(|path| std::fs::read(path).ok());

    let Some(font_data) = loaded else {
        return; // 한글 폰트가 없어도 프로그램은 동작한다
    };

    fonts
        .font_data
        .insert("Korean".to_owned(), egui::FontData::from_owned(font_data));
    if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        family.insert(0, "Korean".to_owned());
    }
    ctx.set_fonts(fonts);
}

/// eframe 애플리케이션 껍데기.
///
/// 캡처 스레드와 채널은 [`GuiState`] 안의 `Capture`가 직접 소유하므로,
/// 여기서 `Option<Sender>` / `Option<Receiver>` 조각을 들고 다닐 필요가 없다.
struct App {
    state: GuiState,
}

/// 캡처 중일 때 채널을 확인하는 주기.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        show_gui(ctx, &mut self.state);

        // 무조건 다시 그리면 유휴 상태에서도 CPU를 계속 태운다. 캡처 중일 때만
        // 주기적으로 깨우고, 그 밖에는 egui의 입력 기반 갱신에 맡긴다.
        if self.state.is_capturing() {
            ctx.request_repaint_after(POLL_INTERVAL);
        }
    }

    /// 창을 닫을 때 캡처를 정리한다.
    ///
    /// 그냥 드롭하면 채널에 남은 이벤트가 사라지고 로그 파일에 종료 푸터가
    /// 남지 않는다.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.state.shutdown();
    }
}
