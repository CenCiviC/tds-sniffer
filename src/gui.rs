use crate::capture::{Capture, CaptureStatus, Interfaces};
use crate::output::{hex_dump, SqlEvent, SqlOp};
use crate::store::{EventIdx, EventStore};
use egui::{CentralPanel, Color32, Context, RichText, ScrollArea, SidePanel, TextEdit, Ui};

/// 사이드바 그룹화 기준.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    ByTable,
    ByOperation,
}

/// 사용자가 무엇을 보고 있는지. 도메인 데이터를 전혀 소유하지 않는다.
///
/// 저장소와 타입이 분리되어 있어 `&EventStore`와 `&mut Selection`을 동시에
/// 넘길 수 있고, 그래서 렌더링 경로에 방어적 복사가 없다.
pub struct Selection {
    view_mode: ViewMode,
    table: Option<String>,
    op: Option<SqlOp>,
    /// 펼쳐진 상세 SQL.
    details: Option<EventIdx>,
    /// 펼쳐진 원본 hex. 덤프 문자열을 함께 들고 있어 매 프레임 다시 만들지 않는다.
    raw: Option<(EventIdx, String)>,
}

impl Default for Selection {
    fn default() -> Self {
        Self {
            view_mode: ViewMode::ByTable,
            table: None,
            op: None,
            details: None,
            raw: None,
        }
    }
}

impl Selection {
    /// 현재 그룹화 기준.
    #[must_use]
    pub const fn view_mode(&self) -> ViewMode {
        self.view_mode
    }

    /// 그룹화 기준을 바꾼다. 이전 기준의 그룹 선택은 의미가 없으므로 함께 지운다.
    ///
    /// 두 동작을 호출자에게 맡기면 "모드만 바꾸고 선택은 남기는" 상태가 생긴다.
    pub fn set_view_mode(&mut self, mode: ViewMode) {
        self.view_mode = mode;
        self.reset();
    }

    /// 그룹 선택과 펼침 상태를 모두 초기화한다.
    pub fn reset(&mut self) {
        self.table = None;
        self.op = None;
        self.collapse();
    }

    /// 펼쳐 둔 항목만 접는다.
    fn collapse(&mut self) {
        self.details = None;
        self.raw = None;
    }

    /// 현재 선택에 해당하는 인덱스를 저장소에서 **빌려서** 돌려준다.
    ///
    /// 예전에는 이 자리에서 `Vec<usize>`를 통째로 복사해 프레임마다 힙 할당이
    /// 일어났다.
    fn indices<'a>(&self, store: &'a EventStore) -> &'a [EventIdx] {
        match self.view_mode {
            ViewMode::ByTable => self
                .table
                .as_ref()
                .map_or_else(|| store.all(), |name| store.table_group(name)),
            ViewMode::ByOperation => self.op.map_or_else(|| store.all(), |op| store.op_group(op)),
        }
    }
}

/// 애플리케이션 상태. 소유권이 서로 다른 세 덩어리와 뷰 상태로 나뉘어 있다.
///
/// 필드는 비공개다. 공개하면 바깥에서 `store.clear()`만 호출해 `Selection`에
/// 오래된 `EventIdx`를 남길 수 있는데, 그 불변식은 [`Self::begin_capture`]가
/// 유일하게 지킨다.
pub struct GuiState {
    store: EventStore,
    sel: Selection,
    cap: Capture,
    ifaces: Interfaces,
}

impl GuiState {
    /// 인터페이스를 조회한 실사용 상태를 만든다.
    #[must_use]
    pub fn detect() -> Self {
        Self {
            store: EventStore::default(),
            sel: Selection::default(),
            cap: Capture::default(),
            ifaces: Interfaces::detect(),
        }
    }

    /// 캡처가 진행 중인가.
    #[must_use]
    pub const fn is_capturing(&self) -> bool {
        self.cap.is_running()
    }

    /// 캡처를 중지하고 로그를 마무리한다 (창을 닫을 때 등).
    pub fn shutdown(&mut self) {
        self.cap.stop(&mut self.store);
    }

    /// 이전 결과를 비우고 새 캡처를 시작한다.
    ///
    /// "저장소를 비우면 선택도 반드시 초기화해야 한다"는 불변식의 **유일한**
    /// 시행 지점이다. 두 호출이 흩어지면 오래된 `EventIdx`가 남는다.
    ///
    /// 인터페이스 이름을 인자로 받지 않고 직접 읽는다. 밖에서 읽어 넘기면
    /// `&self.ifaces` 빌림이 이 호출을 넘길 수 없어 이름을 복사해야 한다.
    fn begin_capture(&mut self) {
        let Some(interface) = self.ifaces.selected() else {
            return;
        };
        // 서로 다른 필드라 `ifaces` 빌림과 겹치지 않는다.
        self.store.clear();
        self.sel.reset();
        self.cap.start(interface);
    }
}

/// GUI 전체를 그린다.
pub fn show_gui(ctx: &Context, state: &mut GuiState) {
    if state.cap.poll(&mut state.store) {
        // 회수 예산이 남은 이벤트를 남겼다. 다음 주기를 기다리지 말고 곧바로
        // 다시 그려서 큐가 밀리지 않게 한다.
        ctx.request_repaint();
    }

    egui::TopBottomPanel::top("control_panel").show(ctx, |ui| {
        control_panel(ui, state);
    });

    if state.store.is_empty() {
        CentralPanel::default().show(ctx, |ui| empty_state(ui, state.cap.is_running()));
        return;
    }

    SidePanel::left("group_panel")
        .default_width(280.0)
        .show(ctx, |ui| {
            // &EventStore(읽기) + &mut Selection(쓰기)를 동시에 넘긴다.
            group_sidebar(ui, &state.store, &mut state.sel);
        });

    CentralPanel::default().show(ctx, |ui| {
        sql_list(ui, ctx, &state.store, &mut state.sel);
    });
}

fn control_panel(ui: &mut Ui, state: &mut GuiState) {
    ui.heading("MSSQL TDS SQL 추출기");

    ui.horizontal(|ui| {
        ui.label("네트워크 인터페이스:");
        interface_combo(ui, &mut state.ifaces, state.cap.is_running());
        ui.separator();

        if state.cap.is_running() {
            if ui.button("중지").clicked() {
                state.cap.stop(&mut state.store);
            }
            ui.spinner();
        } else {
            let can_start = state.ifaces.selected().is_some();
            if ui
                .add_enabled(can_start, egui::Button::new("시작"))
                .clicked()
            {
                state.begin_capture();
            }
        }
    });

    // Npcap 미설치·권한 부족은 가장 흔한 실패다. GUI에는 콘솔이 없으므로
    // 로그가 아니라 화면에 이유를 보여준다.
    if let Some(error) = state.ifaces.error() {
        ui.colored_label(ERROR_COLOR, format!("인터페이스를 열 수 없습니다: {error}"));
    }

    status_label(ui, state.cap.status());

    if !state.store.is_empty() {
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("보기 모드:");
            for (mode, label) in [
                (ViewMode::ByTable, "테이블별"),
                (ViewMode::ByOperation, "작업별"),
            ] {
                if ui
                    .selectable_label(state.sel.view_mode() == mode, label)
                    .clicked()
                {
                    state.sel.set_view_mode(mode);
                }
            }
        });
    }
}

fn interface_combo(ui: &mut Ui, ifaces: &mut Interfaces, locked: bool) {
    egui::ComboBox::from_id_source("interface_select")
        .selected_text(ifaces.selected().unwrap_or("선택 안 됨"))
        .show_ui(ui, |ui| {
            // 캡처 중에는 위젯 자체를 비활성화한다. 클릭을 받아 놓고 무시하면
            // 눌리는 것처럼 보인다.
            ui.add_enabled_ui(!locked, |ui| {
                // 선택은 인덱스로 한다. 이름을 복사해 돌려줄 필요가 없다.
                let mut pick = None;
                for (index, (name, desc)) in ifaces.available().iter().enumerate() {
                    let selected = ifaces.is_selected(index);
                    if ui
                        .selectable_label(selected, format!("{name} - {desc}"))
                        .clicked()
                    {
                        pick = Some(index);
                    }
                }
                if let Some(index) = pick {
                    ifaces.select(index);
                }
            });
        });
}

/// 캡처 상태를 사람이 읽을 문장으로 그린다.
///
/// 문장 조립은 표시를 담당하는 여기서 한다. `Capture`는 무슨 일이 있었는지만
/// 알고 어떻게 보일지는 모른다.
fn status_label(ui: &mut Ui, status: &CaptureStatus) {
    match status {
        CaptureStatus::Idle => {}
        CaptureStatus::Running {
            unique,
            log,
            log_error,
        } => {
            ui.label(format!(
                "캡처 중... (고유 SQL {unique}개, 로그: {})",
                log.display()
            ));
            if let Some(e) = log_error {
                ui.colored_label(ERROR_COLOR, e);
            }
        }
        CaptureStatus::Stopped {
            unique,
            log,
            log_error,
        } => {
            ui.label(format!(
                "캡처 중지됨 (고유 SQL {unique}개, 로그: {})",
                log.display()
            ));
            if let Some(e) = log_error {
                ui.colored_label(ERROR_COLOR, e);
            }
        }
        CaptureStatus::Failed { reason } => {
            ui.colored_label(ERROR_COLOR, reason);
        }
    }
}

/// 오류 표시 색상.
const ERROR_COLOR: Color32 = Color32::from_rgb(255, 120, 120);

fn empty_state(ui: &mut Ui, capturing: bool) {
    ui.vertical_centered(|ui| {
        ui.add_space(100.0);
        if capturing {
            ui.heading("패킷 캡처 중...");
            ui.add_space(20.0);
            ui.label("SQL 쿼리가 감지되면 여기에 표시됩니다.");
            ui.spinner();
        } else {
            ui.heading("네트워크 캡처 대기 중");
            ui.add_space(20.0);
            ui.label("시작 버튼을 눌러 네트워크 캡처를 시작하세요");
        }
    });
}

fn group_sidebar(ui: &mut Ui, store: &EventStore, sel: &mut Selection) {
    ui.heading(match sel.view_mode() {
        ViewMode::ByTable => "테이블",
        ViewMode::ByOperation => "작업 유형",
    });
    ui.separator();

    ScrollArea::vertical()
        .id_source("group_scroll")
        .show(ui, |ui| {
            let all_selected = match sel.view_mode() {
                ViewMode::ByTable => sel.table.is_none(),
                ViewMode::ByOperation => sel.op.is_none(),
            };
            if ui
                .selectable_label(all_selected, format!("전체 ({})", store.len()))
                .clicked()
            {
                sel.reset();
            }
            ui.separator();

            match sel.view_mode() {
                // store.tables()는 슬라이스를 빌려준다. 프레임마다 키를 복사하지 않는다.
                ViewMode::ByTable => {
                    let mut pick = None;
                    for (name, group) in store.table_groups().take(MAX_RENDERED_GROUPS) {
                        let selected = sel.table.as_deref() == Some(name);
                        if ui
                            .selectable_label(selected, format!("{name} ({})", group.len()))
                            .clicked()
                        {
                            pick = Some((name.to_owned(), selected));
                        }
                    }
                    if let Some((name, was_selected)) = pick {
                        sel.table = (!was_selected).then_some(name);
                        sel.collapse();
                    }
                    if store.table_group_count() > MAX_RENDERED_GROUPS {
                        ui.label(format!(
                            "... 그룹 {}개 중 {MAX_RENDERED_GROUPS}개만 표시",
                            store.table_group_count()
                        ));
                    }
                }
                // SqlOp::ALL 덕분에 표시 순서가 고정되고 변형 추가 시 누락되지 않는다.
                ViewMode::ByOperation => {
                    for op in SqlOp::ALL {
                        let count = store.op_group(op).len();
                        if count == 0 {
                            continue;
                        }
                        let selected = sel.op == Some(op);
                        if ui
                            .selectable_label(selected, format!("{op} ({count})"))
                            .clicked()
                        {
                            sel.op = (!selected).then_some(op);
                            sel.collapse();
                        }
                    }
                }
            }
        });
}

/// 한 번에 그릴 최대 행 수.
///
/// egui는 화면 밖 위젯도 레이아웃하므로, 수만 건이 쌓이면 프레임마다 수십 ms를
/// 쓰게 된다. 그 스레드가 채널을 비우고 로그를 쓰는 스레드이기도 하다.
const MAX_RENDERED_ROWS: usize = 500;

/// 사이드바에 그릴 최대 그룹 수. 목록과 같은 이유로 상한이 필요하다 —
/// 쿼리 하나가 수만 개의 테이블 그룹을 만들 수 있다.
const MAX_RENDERED_GROUPS: usize = 300;

/// 테이블을 식별하지 못했거나 그룹 상한을 넘긴 SQL이 모이는 그룹 이름.
const UNGROUPED_LABEL: &str = crate::store::UNGROUPED;

fn sql_list(ui: &mut Ui, ctx: &Context, store: &EventStore, sel: &mut Selection) {
    let indices = sel.indices(store);
    let title = match (sel.view_mode(), &sel.table, sel.op) {
        (ViewMode::ByTable, Some(table), _) => format!("테이블: {table} ({}개)", indices.len()),
        (ViewMode::ByOperation, _, Some(op)) => format!("작업 유형: {op} ({}개)", indices.len()),
        _ => format!("전체 SQL 목록 ({}개)", indices.len()),
    };
    ui.heading(title);

    ScrollArea::vertical()
        .auto_shrink([false; 2])
        .id_source("sql_list_scroll")
        .show(ui, |ui| {
            // 최신 항목이 위로 오도록 뒤에서부터, 상한까지만 그린다.
            for &idx in indices.iter().rev().take(MAX_RENDERED_ROWS) {
                if let Some(event) = store.get(idx) {
                    sql_card(ui, ctx, event, idx, sel);
                    ui.add_space(5.0);
                }
            }
            if indices.len() > MAX_RENDERED_ROWS {
                ui.separator();
                ui.label(format!(
                    "... {}개 중 최근 {MAX_RENDERED_ROWS}개만 표시합니다. \
                     테이블/작업으로 좁히거나 로그 파일을 보세요.",
                    indices.len()
                ));
            }
            if store.overflow_table_names() > 0 {
                ui.label(format!(
                    "테이블 이름 {}건은 그룹 상한을 넘어 '{UNGROUPED_LABEL}'로 묶였습니다.",
                    store.overflow_table_names()
                ));
            }
            if store.over_capacity() > 0 {
                ui.label(format!(
                    "SQL {}건은 메모리 상한을 넘어 화면에 담지 않았습니다. \
                     로그 파일에는 모두 기록되어 있습니다.",
                    store.over_capacity()
                ));
            }
        });
}

fn sql_card(ui: &mut Ui, ctx: &Context, event: &SqlEvent, idx: EventIdx, sel: &mut Selection) {
    ui.group(|ui| {
        ui.horizontal(|ui| {
            let op = event.primary_op();
            let (r, g, b) = op.rgb();
            ui.label(
                RichText::new(op.as_str())
                    .color(Color32::from_rgb(r, g, b))
                    .strong(),
            );
            ui.separator();
            // 아래 문자열들은 이벤트 생성 시점에 만들어 둔 것이다. 매 프레임
            // 같은 `format!`을 다시 돌리지 않는다.
            ui.label(event.timestamp_text());
            ui.separator();
            ui.label(event.flow_text());
            if let Some(tables) = event.tables_text() {
                ui.separator();
                ui.label(tables);
            }
        });

        ui.label(event.preview());

        ui.horizontal(|ui| {
            if ui.button("상세 보기").clicked() {
                sel.details = (sel.details != Some(idx)).then_some(idx);
            }
            if !event.raw().is_empty() && ui.button("원본 보기").clicked() {
                // hex 덤프는 여는 순간 한 번만 만든다. 예전에는 패널이 열려 있는
                // 동안 매 프레임 다시 만들었다 (request_repaint로 최대 프레임률).
                sel.raw = match &sel.raw {
                    Some((open, _)) if *open == idx => None,
                    _ => Some((idx, bounded_hex_dump(event.raw()))),
                };
            }
        });

        if sel.details == Some(idx) {
            ui.separator();
            let (shown, truncated) = clip_chars(event.sql(), SQL_VIEW_CHARS);
            // 복사는 언제나 전문을 넘긴다. 화면만 자른다.
            read_only_block(ui, ctx, "전체 SQL:", shown, event.sql(), false);
            if truncated {
                ui.label(format!(
                    "... 전체 {}바이트 중 앞 {SQL_VIEW_CHARS}자만 표시합니다. \
                     전체는 로그 파일에 있고, 복사 버튼은 전문을 복사합니다.",
                    event.sql().len()
                ));
            }
        }
        if let Some((open, dump)) = &sel.raw {
            if *open == idx {
                ui.separator();
                read_only_block(ui, ctx, "원본 데이터 (Hex):", dump, dump, true);
            }
        }
    });
}

/// hex 뷰에 표시할 최대 원본 바이트.
///
/// 덤프는 입력 1바이트당 약 4글자가 되므로, 멀티패킷 메시지(최대 4 MiB)를 그대로
/// 그리면 16 MB짜리 텍스트를 매 프레임 레이아웃하게 된다.
const HEX_VIEW_BYTES: usize = 16 * 1024;

/// 상세 보기에 표시할 최대 SQL 글자 수.
///
/// 멀티패킷 배치는 수 MB짜리 SQL이 될 수 있다. `TextEdit`은 문자열 전체의
/// 레이아웃을 만들므로 그대로 넘기면 클릭 한 번에 화면이 멈춘다.
const SQL_VIEW_CHARS: usize = 64 * 1024;

/// 문자 경계를 지키며 `max`자까지 잘라낸다. 잘렸는지도 함께 돌려준다.
fn clip_chars(text: &str, max: usize) -> (&str, bool) {
    match text.char_indices().nth(max) {
        Some((byte, _)) => (&text[..byte], true),
        None => (text, false),
    }
}

/// 표시 상한을 적용한 hex 덤프.
fn bounded_hex_dump(raw: &[u8]) -> String {
    use std::fmt::Write as _;

    if raw.len() <= HEX_VIEW_BYTES {
        return hex_dump(raw);
    }
    let mut dump = hex_dump(&raw[..HEX_VIEW_BYTES]);
    let _ = write!(
        dump,
        "\n... (전체 {}바이트 중 앞 {HEX_VIEW_BYTES}바이트만 표시. 전체는 log/raw 로그 파일에 있습니다)",
        raw.len()
    );
    dump
}

/// 복사 버튼이 달린 읽기 전용 텍스트 블록.
fn read_only_block(
    ui: &mut Ui,
    ctx: &Context,
    label: &str,
    text: &str,
    copy_text: &str,
    monospace: bool,
) {
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label(label);
            if ui.button("복사").clicked() {
                ctx.copy_text(copy_text.to_string());
            }
        });
        ScrollArea::vertical()
            .max_height(300.0)
            .id_source(label)
            .show(ui, |ui| {
                // `&str`도 TextBuffer라 사본이 필요 없다. 선택·복사는 되고 편집은
                // 막힌다 — 예전에는 매 프레임 전문을 복사했고, 사용자가 입력하면
                // 다음 프레임에 사라지는 유령 편집이 가능했다.
                let mut shown = text;
                let mut widget = TextEdit::multiline(&mut shown).desired_width(f32::INFINITY);
                if monospace {
                    widget = widget.font(egui::TextStyle::Monospace);
                }
                ui.add(widget);
            });
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::{Endpoint, FlowId};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn event(sql: &str) -> SqlEvent {
        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        let flow = FlowId::classify(client, server).unwrap().0;
        SqlEvent::new(Utc::now(), flow, sql.to_string(), Vec::new())
    }

    #[test]
    fn selection_narrows_the_visible_indices() {
        let mut store = EventStore::default();
        store.insert(event("SELECT * FROM dbo.TB_Users"));
        store.insert(event("INSERT INTO dbo.TB_Logs VALUES (1)"));

        let mut sel = Selection::default();
        assert_eq!(sel.indices(&store).len(), 2, "선택이 없으면 전체");

        sel.table = Some("Logs".to_string());
        assert_eq!(sel.indices(&store).len(), 1);

        sel.view_mode = ViewMode::ByOperation;
        sel.op = Some(SqlOp::Select);
        assert_eq!(sel.indices(&store).len(), 1);
    }

    #[test]
    fn missing_group_yields_an_empty_selection() {
        let store = EventStore::default();
        let sel = Selection {
            table: Some("없는테이블".to_string()),
            ..Selection::default()
        };
        assert!(sel.indices(&store).is_empty());
    }

    #[test]
    fn reset_clears_group_and_expansion_state() {
        let mut sel = Selection {
            table: Some("Users".to_string()),
            op: Some(SqlOp::Select),
            ..Selection::default()
        };
        sel.reset();
        assert!(sel.table.is_none());
        assert!(sel.op.is_none());
        assert!(sel.details.is_none());
        assert!(sel.raw.is_none());
    }
}
