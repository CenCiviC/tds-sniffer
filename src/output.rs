use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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

/// ============================================
/// SQL 파싱 유틸리티 함수들
/// ============================================
/// SQL 텍스트에서 테이블명 추출
/// FROM, UPDATE, INSERT INTO, JOIN 절에서 테이블명 찾기
/// 한글 테이블명도 지원 (예: dbo.TB_진료내역, DentWeb.dbo.TB_작업로그)
pub fn extract_tables_from_sql(sql_text: &str) -> Vec<String> {
    use regex::Regex;
    let mut tables = HashSet::new();

    // 테이블명 패턴: database.schema.table 또는 schema.table 또는 table
    // 한글, 영문, 숫자, 언더스코어, 점 허용
    // FROM, UPDATE, INSERT INTO, JOIN 뒤에 오는 테이블명 추출
    // 최대 2개의 점 허용 (database.schema.table 형식 지원)
    let patterns = vec![
        (
            r"(?i)\bFROM\s+([a-zA-Z_가-힣][a-zA-Z0-9_가-힣]*(?:\.[a-zA-Z_가-힣][a-zA-Z0-9_가-힣]*){0,2})",
            "FROM",
        ),
        (
            r"(?i)\bUPDATE\s+([a-zA-Z_가-힣][a-zA-Z0-9_가-힣]*(?:\.[a-zA-Z_가-힣][a-zA-Z0-9_가-힣]*){0,2})",
            "UPDATE",
        ),
        (
            r"(?i)\bINSERT\s+INTO\s+([a-zA-Z_가-힣][a-zA-Z0-9_가-힣]*(?:\.[a-zA-Z_가-힣][a-zA-Z0-9_가-힣]*){0,2})",
            "INSERT INTO",
        ),
        (
            r"(?i)\bJOIN\s+([a-zA-Z_가-힣][a-zA-Z0-9_가-힣]*(?:\.[a-zA-Z_가-힣][a-zA-Z0-9_가-힣]*){0,2})",
            "JOIN",
        ),
    ];

    for (pattern, _) in patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(sql_text) {
                if let Some(table) = cap.get(1) {
                    tables.insert(table.as_str().to_string());
                }
            }
        }
    }

    tables.into_iter().collect()
}

/// SQL 텍스트에서 모든 operation 추출
/// 한 쿼리에 여러 operation이 있을 수 있음
pub fn extract_operations(sql_text: &str) -> Vec<String> {
    let mut operations = HashSet::new();
    let upper_sql = sql_text.to_uppercase();

    // 각 operation 키워드 확인
    let keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "EXEC", "EXECUTE"];
    for keyword in keywords {
        if upper_sql.contains(keyword) {
            operations.insert(keyword.to_string());
        }
    }

    operations.into_iter().collect()
}

/// 테이블명에서 TB_ 다음 부분 추출
/// 예: "dbo.TB_PI치료계획세부내역" -> "PI치료계획세부내역"
pub fn extract_table_name(table: &str) -> String {
    // 스키마.테이블명 형식 처리
    let parts: Vec<&str> = table.split('.').collect();
    let table_part = if parts.len() > 1 {
        parts.last().unwrap_or(&table)
    } else {
        table
    };

    // TB_ 다음 부분 찾기
    if let Some(pos) = table_part.find("TB_") {
        table_part[pos + 3..].to_string()
    } else {
        table_part.to_string()
    }
}
