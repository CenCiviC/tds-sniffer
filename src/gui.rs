use crate::{
    extract_operations, extract_table_name, extract_tables_from_sql, Extractor, SqlEvent, SqlLogger,
};
use egui::{CentralPanel, Color32, RichText, ScrollArea, SidePanel, TextEdit, TopBottomPanel};
use std::collections::HashMap;
use std::sync::mpsc;

/// 뷰 모드
#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    ByTable,
    BySql,
}

/// GUI 상태
pub struct GuiState {
    events: Vec<SqlEvent>,
    // 중복 제거를 위한 SQL 텍스트 -> 이벤트 인덱스 매핑
    unique_sql_map: HashMap<String, usize>, // sql_text -> 첫 번째 이벤트 인덱스
    // 테이블별 그룹화 (TB_ 다음 부분이 테이블명)
    table_groups: HashMap<String, Vec<usize>>, // 테이블명 -> 고유 SQL 인덱스들
    // SQL별 그룹화
    operation_groups: HashMap<String, Vec<usize>>, // operation -> 고유 SQL 인덱스들
    view_mode: ViewMode,
    selected_table: Option<String>,
    selected_operation: Option<String>,
    show_details: Option<usize>,
    show_raw: Option<usize>,
    pub is_capturing: bool,
    pub capture_started: bool,
    processing_status: String,
    pub selected_interface: Option<String>, // 인터페이스 이름만 저장
    available_interfaces: Vec<(String, String)>, // (이름, 설명)
    event_receiver: Option<mpsc::Receiver<SqlEvent>>,
    stop_sender: Option<mpsc::Sender<()>>,
    logger: SqlLogger, // SQL 이벤트 로거
}

impl GuiState {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let interfaces = Extractor::list_interfaces().unwrap_or_default();
        Self {
            events: Vec::new(),
            unique_sql_map: HashMap::new(),
            table_groups: HashMap::new(),
            operation_groups: HashMap::new(),
            view_mode: ViewMode::ByTable,
            selected_table: None,
            selected_operation: None,
            show_details: None,
            show_raw: None,
            is_capturing: false,
            capture_started: false,
            processing_status: String::new(),
            selected_interface: interfaces.first().map(|(name, _)| name.clone()),
            available_interfaces: interfaces,
            event_receiver: None,
            stop_sender: None,
            logger: SqlLogger::new(),
        }
    }

    /// 이벤트 수신기 설정
    pub fn set_event_receiver(&mut self, receiver: mpsc::Receiver<SqlEvent>) {
        self.event_receiver = Some(receiver);
    }

    /// 중지 sender 설정
    pub fn set_stop_sender(&mut self, sender: mpsc::Sender<()>) {
        self.stop_sender = Some(sender);
    }

    /// 캡처 시작
    pub fn start_capture(&mut self) {
        if self.is_capturing || self.selected_interface.is_none() {
            return;
        }

        // 기존 데이터 초기화
        self.events.clear();
        self.unique_sql_map.clear();
        self.table_groups.clear();
        self.operation_groups.clear();
        self.selected_table = None;
        self.selected_operation = None;
        self.show_details = None;
        self.show_raw = None;

        // 로그 파일 생성
        match self.logger.start_capture(self.selected_interface.as_ref()) {
            Ok(log_filename) => {
                self.processing_status = format!("캡처 시작 중... (로그: {})", log_filename);
            }
            Err(e) => {
                self.processing_status = format!("캡처 시작 중... (로그 파일 생성 실패: {})", e);
            }
        }

        self.is_capturing = true;
        self.capture_started = false;
    }

    /// 캡처 중지
    pub fn stop_capture(&mut self) {
        if !self.is_capturing {
            return;
        }

        if let Some(ref sender) = self.stop_sender {
            let _ = sender.send(());
        }

        // 로그 파일에 종료 메시지 작성
        self.logger.stop_capture(self.events.len());

        let log_file_info = if let Some(path) = self.logger.get_file_path() {
            format!(" (로그: {})", path)
        } else {
            String::new()
        };

        self.is_capturing = false;
        self.capture_started = false;
        self.processing_status = format!(
            "캡처 중지됨 (총 {}개 이벤트){}",
            self.events.len(),
            log_file_info
        );
    }

    /// 새 이벤트 추가 (중복 제거 및 그룹화)
    pub fn add_event(&mut self, event: SqlEvent) {
        // 중복 체크: 같은 SQL 텍스트가 이미 있으면 추가하지 않음
        let sql_key = event.sql_text.trim().to_string();
        let unique_idx = if let Some(&existing_idx) = self.unique_sql_map.get(&sql_key) {
            // 이미 존재하는 SQL이면 기존 인덱스 사용
            existing_idx
        } else {
            // 새로운 고유 SQL이면 추가
            let idx = self.events.len();
            self.events.push(event);
            self.unique_sql_map.insert(sql_key, idx);
            idx
        };

        let event = &self.events[unique_idx];

        // 새로운 고유 SQL이 추가되었을 때만 로깅
        if unique_idx == self.events.len() - 1 {
            self.logger.log_event(event);
        }

        // 테이블별 그룹화 (TB_ 다음 부분이 테이블명)
        // event.tables가 비어있으면 SQL 텍스트에서 직접 추출
        let tables = if event.tables.is_empty() {
            extract_tables_from_sql(&event.sql_text)
        } else {
            event.tables.clone()
        };

        // 중복 체크: 이미 그룹에 있으면 추가하지 않음
        if tables.is_empty() {
            let group = self.table_groups.entry("기타".to_string()).or_default();
            if !group.contains(&unique_idx) {
                group.push(unique_idx);
            }
        } else {
            for table in &tables {
                let table_name = extract_table_name(table);
                let group = self.table_groups.entry(table_name).or_default();
                if !group.contains(&unique_idx) {
                    group.push(unique_idx);
                }
            }
        }

        // SQL별 그룹화 (한 쿼리에 여러 operation이 있으면 각 그룹에 포함)
        let operations = extract_operations(&event.sql_text);
        if operations.is_empty() {
            // operation이 없으면 기존 operation 필드 사용
            let group = self
                .operation_groups
                .entry(event.operation.clone())
                .or_default();
            if !group.contains(&unique_idx) {
                group.push(unique_idx);
            }
        } else {
            // 추출된 모든 operation에 추가
            for op in operations {
                let group = self.operation_groups.entry(op).or_default();
                if !group.contains(&unique_idx) {
                    group.push(unique_idx);
                }
            }
        }
    }

    /// 실시간 이벤트 수신 처리
    pub fn process_received_events(&mut self) {
        let mut new_events = Vec::new();

        // 먼저 모든 이벤트를 수집
        if let Some(receiver) = &mut self.event_receiver {
            while let Ok(event) = receiver.try_recv() {
                new_events.push(event);
            }
        }

        // 수집한 이벤트들을 추가
        for event in new_events {
            self.add_event(event);
            if !self.capture_started {
                self.capture_started = true;
            }
            self.processing_status = format!("캡처 중... ({}개 이벤트)", self.events.len());
        }
    }

    /// 선택된 그룹의 고유 SQL 인덱스 가져오기
    fn get_selected_events(&self) -> Vec<usize> {
        match self.view_mode {
            ViewMode::ByTable => {
                if let Some(ref table) = self.selected_table {
                    self.table_groups.get(table).cloned().unwrap_or_default()
                } else {
                    // 중복 제거된 모든 이벤트
                    (0..self.events.len()).collect()
                }
            }
            ViewMode::BySql => {
                if let Some(ref operation) = self.selected_operation {
                    self.operation_groups
                        .get(operation)
                        .cloned()
                        .unwrap_or_default()
                } else {
                    // 중복 제거된 모든 이벤트
                    (0..self.events.len()).collect()
                }
            }
        }
    }
}

/// GUI 렌더링
pub fn show_gui(ctx: &egui::Context, state: &mut GuiState) {
    // 실시간 이벤트 처리
    state.process_received_events();

    // 제어 영역 (상단에 고정)
    TopBottomPanel::top("control_panel").show(ctx, |ui| {
        ui.heading("MSSQL TDS SQL 추출기");

        // 인터페이스 선택 및 캡처 제어
        ui.horizontal(|ui| {
            ui.label("네트워크 인터페이스:");

            let selected_text = if let Some(ref selected) = state.selected_interface {
                // 선택된 인터페이스의 설명 찾기
                state
                    .available_interfaces
                    .iter()
                    .find(|(name, _)| name == selected)
                    .map(|(name, desc)| format!("{} - {}", name, desc))
                    .unwrap_or_else(|| selected.clone())
            } else {
                "선택 안 됨".to_string()
            };

            egui::ComboBox::from_id_source("interface_select")
                .selected_text(&selected_text)
                .show_ui(ui, |ui| {
                    for (name, desc) in &state.available_interfaces {
                        let display_text = format!("{} - {}", name, desc);
                        let is_selected = state.selected_interface.as_ref() == Some(name);

                        if ui.selectable_label(is_selected, &display_text).clicked()
                            && !state.is_capturing
                        {
                            state.selected_interface = Some(name.clone());
                        }
                    }
                });

            ui.separator();

            if !state.is_capturing {
                let can_start = state.selected_interface.is_some();
                if ui
                    .add_enabled(can_start, egui::Button::new("시작"))
                    .clicked()
                {
                    state.start_capture();
                }
            } else {
                if ui.button("중지").clicked() {
                    state.stop_capture();
                }
                ui.spinner();
            }
        });

        if !state.processing_status.is_empty() {
            ui.label(&state.processing_status);
        }

        // 뷰 모드 탭 (데이터가 있을 때만 표시)
        if !state.events.is_empty() {
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("보기 모드:");
                if ui
                    .selectable_label(state.view_mode == ViewMode::ByTable, "테이블별")
                    .clicked()
                {
                    state.view_mode = ViewMode::ByTable;
                    state.selected_table = None;
                    state.selected_operation = None;
                    state.show_details = None;
                    state.show_raw = None;
                }
                if ui
                    .selectable_label(state.view_mode == ViewMode::BySql, "SQL별")
                    .clicked()
                {
                    state.view_mode = ViewMode::BySql;
                    state.selected_table = None;
                    state.selected_operation = None;
                    state.show_details = None;
                    state.show_raw = None;
                }
            });
        }
    });

    // 데이터가 있을 때만 표시
    if !state.events.is_empty() {
        // 왼쪽 패널: 그룹 목록
        SidePanel::left("group_panel")
            .resizable(true)
            .default_width(300.0)
            .min_width(200.0)
            .max_width(500.0)
            .show(ctx, |ui| {
                match state.view_mode {
                    ViewMode::ByTable => {
                        ui.heading("테이블 목록");
                        ScrollArea::vertical()
                            .auto_shrink([false; 2])
                            .id_source("table_list_scroll")
                            .show(ui, |ui| {
                                let mut tables: Vec<String> =
                                    state.table_groups.keys().cloned().collect();
                                tables.sort();

                                for table in &tables {
                                    let count =
                                        state.table_groups.get(table).map(|v| v.len()).unwrap_or(0);
                                    let is_selected = state.selected_table.as_ref() == Some(table);

                                    if ui
                                        .selectable_label(
                                            is_selected,
                                            format!("{} ({})", table, count),
                                        )
                                        .clicked()
                                    {
                                        state.selected_table = if is_selected {
                                            None
                                        } else {
                                            Some(table.clone())
                                        };
                                        state.show_details = None;
                                        state.show_raw = None;
                                    }
                                }

                                // 전체 보기
                                ui.separator();
                                let total_count = state.events.len();
                                let is_all_selected = state.selected_table.is_none();
                                if ui
                                    .selectable_label(
                                        is_all_selected,
                                        format!("전체 ({})", total_count),
                                    )
                                    .clicked()
                                {
                                    state.selected_table = None;
                                    state.show_details = None;
                                    state.show_raw = None;
                                }
                            });
                    }
                    ViewMode::BySql => {
                        ui.heading("SQL 작업 유형");
                        ScrollArea::vertical()
                            .auto_shrink([false; 2])
                            .id_source("operation_list_scroll")
                            .show(ui, |ui| {
                                let mut operations: Vec<String> =
                                    state.operation_groups.keys().cloned().collect();
                                operations.sort();

                                for operation in &operations {
                                    let count = state
                                        .operation_groups
                                        .get(operation)
                                        .map(|v| v.len())
                                        .unwrap_or(0);
                                    let is_selected =
                                        state.selected_operation.as_ref() == Some(operation);

                                    if ui
                                        .selectable_label(
                                            is_selected,
                                            format!("{} ({})", operation, count),
                                        )
                                        .clicked()
                                    {
                                        state.selected_operation = if is_selected {
                                            None
                                        } else {
                                            Some(operation.clone())
                                        };
                                        state.show_details = None;
                                        state.show_raw = None;
                                    }
                                }

                                // 전체 보기
                                ui.separator();
                                let total_count = state.events.len();
                                let is_all_selected = state.selected_operation.is_none();
                                if ui
                                    .selectable_label(
                                        is_all_selected,
                                        format!("전체 ({})", total_count),
                                    )
                                    .clicked()
                                {
                                    state.selected_operation = None;
                                    state.show_details = None;
                                    state.show_raw = None;
                                }
                            });
                    }
                }
            });

        // 오른쪽 중앙 패널: SQL 목록
        CentralPanel::default().show(ctx, |ui| {
            ui.push_id("sql_panel", |ui| {
                let title = match state.view_mode {
                    ViewMode::ByTable => {
                        if let Some(ref table) = state.selected_table {
                            format!(
                                "테이블: {} ({}개)",
                                table,
                                state.get_selected_events().len()
                            )
                        } else {
                            format!("전체 SQL 목록 ({}개)", state.events.len())
                        }
                    }
                    ViewMode::BySql => {
                        if let Some(ref operation) = state.selected_operation {
                            format!(
                                "작업 유형: {} ({}개)",
                                operation,
                                state.get_selected_events().len()
                            )
                        } else {
                            format!("전체 SQL 목록 ({}개)", state.events.len())
                        }
                    }
                };
                ui.heading(&title);

                // heading을 그린 후 남은 높이 계산
                let sql_scroll_height = ui.available_height();

                ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .max_height(sql_scroll_height)
                    .id_source("sql_list_scroll")
                    .show(ui, |ui| {
                        let event_indices = state.get_selected_events();

                        for &idx in &event_indices {
                            let event = &state.events[idx];

                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    // 작업 타입 색상
                                    let color = match event.operation.as_str() {
                                        "SELECT" => Color32::from_rgb(100, 200, 100),
                                        "INSERT" => Color32::from_rgb(100, 150, 255),
                                        "UPDATE" => Color32::from_rgb(255, 200, 100),
                                        "DELETE" => Color32::from_rgb(255, 100, 100),
                                        "EXEC" => Color32::from_rgb(200, 100, 255),
                                        _ => Color32::GRAY,
                                    };

                                    ui.label(RichText::new(&event.operation).color(color).strong());
                                    ui.separator();
                                    ui.label(format!(
                                        "{}",
                                        event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f")
                                    ));
                                    ui.separator();
                                    ui.label(&event.flow_id);

                                    if !event.tables.is_empty() {
                                        ui.separator();
                                        ui.label(format!("테이블: {}", event.tables.join(", ")));
                                    }
                                });

                                // SQL 미리보기
                                let sql_preview = if event.sql_text.chars().count() > 200 {
                                    event.sql_text.chars().take(200).collect::<String>() + "..."
                                } else {
                                    event.sql_text.clone()
                                };
                                ui.label(sql_preview);

                                ui.horizontal(|ui| {
                                    // 상세 보기 버튼
                                    if ui.button("상세 보기").clicked() {
                                        state.show_details = if state.show_details == Some(idx) {
                                            None
                                        } else {
                                            Some(idx)
                                        };
                                    }

                                    // 원본 보기 버튼
                                    if event.raw_data.is_some() && ui.button("원본 보기").clicked()
                                    {
                                        state.show_raw = if state.show_raw == Some(idx) {
                                            None
                                        } else {
                                            Some(idx)
                                        };
                                    }
                                });

                                // 상세 정보
                                if state.show_details == Some(idx) {
                                    ui.separator();
                                    ui.group(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.label("전체 SQL:");
                                            if ui.button("복사").clicked() {
                                                ctx.copy_text(event.sql_text.clone());
                                            }
                                        });
                                        ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                                            let mut sql_text = event.sql_text.clone();
                                            ui.add(
                                                TextEdit::multiline(&mut sql_text)
                                                    .desired_width(f32::INFINITY)
                                                    .interactive(true),
                                            );
                                        });
                                    });
                                }

                                // 원본 데이터 (Hex)
                                if state.show_raw == Some(idx) {
                                    if let Some(ref raw_data) = event.raw_data {
                                        ui.separator();
                                        ui.group(|ui| {
                                            // Hex 문자열 생성 (16바이트씩 줄바꿈)
                                            let hex_string: String = raw_data
                                                .chunks(16)
                                                .enumerate()
                                                .map(|(i, chunk)| {
                                                    let hex: String = chunk
                                                        .iter()
                                                        .map(|b| format!("{:02x}", b))
                                                        .collect::<Vec<_>>()
                                                        .join(" ");
                                                    let offset = i * 16;
                                                    format!("{:08x}:  {}", offset, hex)
                                                })
                                                .collect::<Vec<_>>()
                                                .join("\n");

                                            ui.horizontal(|ui| {
                                                ui.label("원본 데이터 (Hex):");
                                                if ui.button("복사").clicked() {
                                                    ctx.copy_text(hex_string.clone());
                                                }
                                            });
                                            ScrollArea::vertical().max_height(300.0).show(
                                                ui,
                                                |ui| {
                                                    let mut hex_text = hex_string;
                                                    ui.add(
                                                        TextEdit::multiline(&mut hex_text)
                                                            .desired_width(f32::INFINITY)
                                                            .font(egui::TextStyle::Monospace)
                                                            .interactive(true),
                                                    );
                                                },
                                            );
                                        });
                                    }
                                }
                            });

                            ui.add_space(5.0);
                        }
                    });
            });
        });
    } else {
        // 테이블이 없을 때 중앙 패널 표시
        CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(100.0);

                if state.is_capturing {
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
        });
    }
}
