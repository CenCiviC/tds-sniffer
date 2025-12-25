use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// SQL 이벤트
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlEvent {
    pub timestamp: DateTime<Utc>,
    pub flow_id: String,
    pub sql_text: String,
    pub tables: Vec<String>,
    pub operation: String,
    pub label: Option<String>,
    /// 원본 TDS 패킷 바이트 데이터 (hex 표시용)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<Vec<u8>>,
}

/// JSONL 출력기
pub struct JsonlWriter;

impl JsonlWriter {
    /// 이벤트를 JSONL 형식으로 파일에 쓰기
    pub fn write_events(
        events: &[SqlEvent],
        file_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = std::fs::File::create(file_path)?;

        for event in events {
            let json = serde_json::to_string(event)?;
            use std::io::Write;
            writeln!(file, "{}", json)?;
        }

        Ok(())
    }

    /// 이벤트를 JSONL 형식으로 읽기
    pub fn read_events(file_path: &str) -> Result<Vec<SqlEvent>, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(file_path)?;
        let mut events = Vec::new();

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let event: SqlEvent = serde_json::from_str(line)?;
            events.push(event);
        }

        Ok(events)
    }
}
