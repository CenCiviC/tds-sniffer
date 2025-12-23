use crate::output::SqlEvent;
use crate::Extractor;
use egui::{Color32, RichText, ScrollArea, TextEdit};
use std::collections::HashMap;
use std::sync::mpsc;

/// GUI 상태
pub struct GuiState {
    events: Vec<SqlEvent>,
    table_groups: HashMap<String, Vec<usize>>, // 테이블명 -> 이벤트 인덱스들
    selected_table: Option<String>,
    show_details: Option<usize>,
    pub is_capturing: bool,
    pub capture_started: bool,
    processing_status: String,
    pub use_tds_parsing: bool,
    pub selected_interface: Option<String>, // 인터페이스 이름만 저장
    available_interfaces: Vec<(String, String)>, // (이름, 설명)
    event_receiver: Option<mpsc::Receiver<SqlEvent>>,
    stop_sender: Option<mpsc::Sender<()>>,
}

impl GuiState {
    pub fn new() -> Self {
        let interfaces = Extractor::list_interfaces().unwrap_or_default();
        Self {
            events: Vec::new(),
            table_groups: HashMap::new(),
            selected_table: None,
            show_details: None,
            is_capturing: false,
            capture_started: false,
            processing_status: String::new(),
            use_tds_parsing: false,
            selected_interface: interfaces.first().map(|(name, _)| name.clone()),
            available_interfaces: interfaces,
            event_receiver: None,
            stop_sender: None,
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

        self.is_capturing = true;
        self.capture_started = false;
        self.processing_status = "캡처 시작 중...".to_string();
    }

    /// 캡처 중지
    pub fn stop_capture(&mut self) {
        if !self.is_capturing {
            return;
        }

        if let Some(ref sender) = self.stop_sender {
            let _ = sender.send(());
        }

        self.is_capturing = false;
        self.capture_started = false;
        self.processing_status = format!("캡처 중지됨 (총 {}개 이벤트)", self.events.len());
    }

    /// 새 이벤트 추가
    pub fn add_event(&mut self, event: SqlEvent) {
        let idx = self.events.len();
        self.events.push(event);

        // 테이블 그룹 업데이트
        let event = &self.events[idx];
        if event.tables.is_empty() {
            self.table_groups
                .entry("기타".to_string())
                .or_insert_with(Vec::new)
                .push(idx);
        } else {
            for table in &event.tables {
                self.table_groups
                    .entry(table.clone())
                    .or_insert_with(Vec::new)
                    .push(idx);
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

    /// 선택된 테이블의 이벤트 가져오기
    fn get_selected_table_events(&self) -> Vec<usize> {
        if let Some(ref table) = self.selected_table {
            self.table_groups.get(table).cloned().unwrap_or_default()
        } else {
            (0..self.events.len()).collect()
        }
    }
}

/// GUI 렌더링
pub fn show_gui(ctx: &egui::Context, state: &mut GuiState) {
    // 실시간 이벤트 처리
    state.process_received_events();

    egui::CentralPanel::default().show(ctx, |ui| {
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
                        
                        if ui.selectable_label(is_selected, &display_text).clicked() {
                            if !state.is_capturing {
                                state.selected_interface = Some(name.clone());
                            }
                        }
                    }
                });

            ui.separator();

            ui.checkbox(&mut state.use_tds_parsing, "TDS 헤더 기반 파싱 (v2)");

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

        ui.separator();

        // 테이블별 그룹화 표시
        if !state.table_groups.is_empty() {
            ui.horizontal(|ui| {
                // 왼쪽: 테이블 목록
                ui.vertical(|ui| {
                    ui.heading("테이블 목록");
                    ScrollArea::vertical().max_width(300.0).show(ui, |ui| {
                        let mut tables: Vec<String> = state.table_groups.keys().cloned().collect();
                        tables.sort();

                        for table in &tables {
                            let count = state.table_groups.get(table).map(|v| v.len()).unwrap_or(0);
                            let is_selected = state.selected_table.as_ref() == Some(table);

                            if ui
                                .selectable_label(is_selected, format!("{} ({})", table, count))
                                .clicked()
                            {
                                state.selected_table = if is_selected {
                                    None
                                } else {
                                    Some(table.clone())
                                };
                                state.show_details = None;
                            }
                        }

                        // 전체 보기
                        ui.separator();
                        let total_count = state.events.len();
                        let is_all_selected = state.selected_table.is_none();
                        if ui
                            .selectable_label(is_all_selected, format!("전체 ({})", total_count))
                            .clicked()
                        {
                            state.selected_table = None;
                            state.show_details = None;
                        }
                    });
                });

                ui.separator();

                // 오른쪽: 선택된 테이블의 SQL 목록
                ui.vertical(|ui| {
                    let title = if let Some(ref table) = state.selected_table {
                        format!(
                            "테이블: {} ({}개)",
                            table,
                            state.get_selected_table_events().len()
                        )
                    } else {
                        format!("전체 SQL 목록 ({}개)", state.events.len())
                    };
                    ui.heading(&title);

                    ScrollArea::vertical().show(ui, |ui| {
                        let event_indices = state.get_selected_table_events();

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
                                let sql_preview = if event.sql_text.len() > 200 {
                                    format!("{}...", &event.sql_text[..200])
                                } else {
                                    event.sql_text.clone()
                                };
                                ui.label(sql_preview);

                                // 상세 보기 버튼
                                if ui.button("상세 보기").clicked() {
                                    state.show_details = if state.show_details == Some(idx) {
                                        None
                                    } else {
                                        Some(idx)
                                    };
                                }

                                // 상세 정보
                                if state.show_details == Some(idx) {
                                    ui.separator();
                                    ui.group(|ui| {
                                        ui.label("전체 SQL:");
                                        ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                                            let mut sql_text = event.sql_text.clone();
                                            ui.add(
                                                TextEdit::multiline(&mut sql_text)
                                                    .desired_width(f32::INFINITY)
                                                    .interactive(false),
                                            );
                                        });
                                    });
                                }
                            });

                            ui.add_space(5.0);
                        }
                    });
                });
            });
        } else if state.is_capturing {
            ui.label("패킷 캡처 중... SQL 쿼리가 감지되면 여기에 표시됩니다.");
        } else {
            ui.label("시작 버튼을 눌러 네트워크 캡처를 시작하세요");
        }
    });
}
