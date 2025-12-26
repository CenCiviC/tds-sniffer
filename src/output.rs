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
