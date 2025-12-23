use log::debug;

/// TDS 패킷 타입
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TdsPacketType {
    SqlBatch = 1,
    RpcRequest = 3,
    Response = 4,
    Unknown(u8),
}

impl From<u8> for TdsPacketType {
    fn from(value: u8) -> Self {
        match value {
            1 => TdsPacketType::SqlBatch,
            3 => TdsPacketType::RpcRequest,
            4 => TdsPacketType::Response,
            _ => TdsPacketType::Unknown(value),
        }
    }
}

/// TDS 패킷 헤더
#[derive(Debug)]
pub struct TdsHeader {
    pub packet_type: TdsPacketType,
    pub status: u8,
    pub length: u16,
    pub spid: u16,
    pub packet_id: u8,
    pub window: u8,
}

/// TDS 파서
pub struct TdsParser;

impl TdsParser {
    /// TDS 헤더 파싱
    pub fn parse_header(data: &[u8]) -> Option<TdsHeader> {
        if data.len() < 8 {
            return None;
        }

        let packet_type = TdsPacketType::from(data[0]);
        let status = data[1];
        let length = u16::from_le_bytes([data[2], data[3]]);
        let spid = u16::from_le_bytes([data[4], data[5]]);
        let packet_id = data[6];
        let window = data[7];

        Some(TdsHeader {
            packet_type,
            status,
            length,
            spid,
            packet_id,
            window,
        })
    }

    /// TDS 패킷에서 SQL 텍스트 추출 (v1: 휴리스틱)
    pub fn extract_sql_heuristic(data: &[u8]) -> Option<String> {
        // UTF-16LE로 디코딩 시도
        // TDS 헤더를 건너뛰고 본문에서 SQL 찾기

        // 여러 위치에서 시도 (더 많은 오프셋 시도)
        let offsets = vec![
            0, 8, 10, 12, 14, 16, 18, 20, 30, 40, 50, 60, 70, 80, 90, 100,
        ];

        for &start_offset in &offsets {
            if start_offset >= data.len() {
                continue;
            }

            if let Some(sql) = Self::try_decode_utf16le(&data[start_offset..]) {
                if Self::looks_like_sql(&sql) {
                    debug!("휴리스틱으로 SQL 발견 (offset: {})", start_offset);
                    return Some(sql);
                }
            }
        }

        None
    }

    /// TDS 패킷에서 SQL 텍스트 추출 (v2: TDS 헤더 기반)
    pub fn extract_sql_from_tds(data: &[u8]) -> Option<String> {
        if data.len() < 8 {
            return None;
        }

        let header = Self::parse_header(data)?;

        // SQLBatch 또는 RPCRequest만 처리
        match header.packet_type {
            TdsPacketType::SqlBatch | TdsPacketType::RpcRequest => {
                // TDS 본문 파싱
                // SQLBatch: 헤더(8) + AllHeaders(가변) + SQL 텍스트
                // 간단한 구현: 헤더 이후부터 UTF-16LE 디코딩 시도

                let body_start = 8;
                if body_start >= data.len() {
                    return None;
                }

                // AllHeaders 길이 확인 (옵셔널)
                let offset = body_start;

                // SQLBatch의 경우 직접 SQL 텍스트가 올 수 있음
                // RPCRequest의 경우 프로시저 이름과 파라미터가 옴

                if let Some(sql) = Self::try_decode_utf16le(&data[offset..]) {
                    if Self::looks_like_sql(&sql) {
                        return Some(sql);
                    }
                }
            }
            _ => {
                debug!(
                    "SQLBatch/RPCRequest가 아닌 패킷 타입: {:?}",
                    header.packet_type
                );
            }
        }

        None
    }

    /// UTF-16LE 디코딩 시도
    fn try_decode_utf16le(data: &[u8]) -> Option<String> {
        if data.len() < 2 {
            return None;
        }

        // UTF-16LE로 디코딩
        let mut result = String::new();
        let mut i = 0;
        let mut valid_chars = 0;
        let mut invalid_chars = 0;

        while i + 1 < data.len() {
            let byte1 = data[i];
            let byte2 = data[i + 1];
            let code_point = u16::from_le_bytes([byte1, byte2]);

            // NULL 문자는 문자열 종료로 간주 (연속된 NULL은 무시)
            if code_point == 0 {
                if result.is_empty() {
                    i += 2;
                    continue; // 시작 부분의 NULL 건너뛰기
                } else {
                    break; // 문자열 중간의 NULL은 종료
                }
            }

            // 유효한 문자인지 확인
            if let Some(ch) = char::from_u32(code_point as u32) {
                // 제어 문자 처리 (일부는 허용)
                if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' && ch != ' ' {
                    invalid_chars += 1;
                    // 너무 많은 제어 문자는 실패로 간주
                    if invalid_chars > 5 && valid_chars < 20 {
                        return None;
                    }
                    // 일부 제어 문자는 건너뛰기
                    i += 2;
                    continue;
                }
                result.push(ch);
                valid_chars += 1;
            } else {
                // 유효하지 않은 문자
                invalid_chars += 1;
                if invalid_chars > 5 && valid_chars < 20 {
                    return None;
                }
            }

            i += 2;
        }

        // 최소 길이 확인 (너무 짧으면 무시)
        if result.trim().len() > 10 && valid_chars > invalid_chars {
            Some(result.trim().to_string())
        } else {
            None
        }
    }

    /// SQL처럼 보이는지 확인
    fn looks_like_sql(text: &str) -> bool {
        if text.trim().is_empty() {
            return false;
        }

        let upper = text.to_uppercase();
        let sql_keywords = [
            "SELECT", "INSERT", "UPDATE", "DELETE", "EXEC", "EXECUTE", "CREATE", "ALTER", "DROP",
            "FROM", "WHERE", "JOIN", "INNER", "OUTER", "LEFT", "RIGHT", "UNION", "ORDER", "GROUP",
            "BY", "HAVING", "AND", "OR", "NOT", "INTO", "SET", "VALUES", "TABLE", "DATABASE",
            "SCHEMA",
        ];

        // SQL 키워드가 포함되어 있고, 최소 길이 확인
        sql_keywords.iter().any(|&keyword| upper.contains(keyword)) && text.len() > 20
    }
}
