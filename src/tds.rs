use encoding_rs::UTF_16LE;
use log::debug;
use tds_protocol::packet::{PacketHeader, PacketType};

/// TDS 패킷 타입 (하위 호환성을 위한 래퍼)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TdsPacketType {
    SqlBatch = 1,
    RpcRequest = 3,
    Response = 4,
    Unknown(u8),
}

impl From<PacketType> for TdsPacketType {
    fn from(packet_type: PacketType) -> Self {
        match packet_type {
            PacketType::SqlBatch => TdsPacketType::SqlBatch,
            PacketType::Rpc => TdsPacketType::RpcRequest,
            PacketType::TabularResult => TdsPacketType::Response,
            _ => TdsPacketType::Unknown(packet_type as u8),
        }
    }
}

/// TDS 패킷 헤더 (하위 호환성을 위한 래퍼)
#[derive(Debug)]
pub struct TdsHeader {
    pub packet_type: TdsPacketType,
    pub status: u8,
    pub length: u16,
    pub spid: u16,
    pub packet_id: u8,
    pub window: u8,
}

impl From<PacketHeader> for TdsHeader {
    fn from(header: PacketHeader) -> Self {
        TdsHeader {
            packet_type: header.packet_type.into(),
            status: header.status.bits(),
            length: header.length,
            spid: header.spid,
            packet_id: header.packet_id,
            window: header.window,
        }
    }
}

/// TDS 파서
pub struct TdsParser;

impl TdsParser {
    /// ============================================
    /// 1단계: TDS 패킷 식별
    /// ============================================
    /// TCP 페이로드가 TDS 프로토콜 패킷인지 확인
    /// 첫 번째 바이트가 0x01 (SQL Batch) 또는 0x03 (RPC)인 패킷만 처리
    /// tds-protocol 라이브러리를 사용하여 헤더 파싱
    pub fn looks_like_tds(bytes: &[u8]) -> bool {
        // 최소 헤더 크기 확인 (TDS 헤더는 8바이트)
        if bytes.len() < 8 {
            return false;
        }

        // 첫 번째 바이트가 0x01 (SQL Batch) 또는 0x03 (RPC)인지 확인
        // SQL 추출에 필요한 패킷 타입만 필터링
        let packet_type_byte = bytes[0];
        if packet_type_byte != 0x01 && packet_type_byte != 0x03 {
            return false;
        }

        // tds-protocol 라이브러리를 사용하여 헤더 파싱
        let mut buf = &bytes[..8];
        let header = match PacketHeader::decode(&mut buf) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // SQL Batch (0x01) 또는 RPC (0x03) 패킷만 허용
        matches!(header.packet_type, PacketType::SqlBatch | PacketType::Rpc)
    }

    /// ============================================
    /// 2단계: TDS 헤더 파싱
    /// ============================================
    /// TDS 패킷 헤더를 파싱하여 패킷 정보 추출
    /// tds-protocol 라이브러리를 사용
    pub fn parse_header(data: &[u8]) -> Option<TdsHeader> {
        // 최소 헤더 크기 확인
        if data.len() < 8 {
            return None;
        }

        // tds-protocol 라이브러리를 사용하여 헤더 파싱
        let mut buf = &data[..8];
        match PacketHeader::decode(&mut buf) {
            Ok(header) => Some(header.into()),
            Err(_) => None,
        }
    }

    /// ============================================
    /// 3단계: TDS 패킷 본문 추출
    /// ============================================
    /// TDS 헤더를 제거하고 본문 데이터만 추출
    /// SQLBatch 패킷의 경우 AllHeaders 섹션도 고려
    pub fn extract_payload(data: &[u8]) -> Option<&[u8]> {
        if data.len() < 8 {
            return None;
        }

        // 헤더 파싱
        let header = Self::parse_header(data)?;

        // 패킷 길이 확인
        if data.len() < header.length as usize {
            // 패킷이 완전하지 않을 수 있음
            debug!("패킷이 완전하지 않음: {} < {}", data.len(), header.length);
        }

        // 본문 시작 위치 결정
        // SQLBatch (0x01)와 RPCRequest (0x03)의 경우 AllHeaders 섹션이 있을 수 있음
        let body_start = if (header.packet_type == TdsPacketType::SqlBatch
            || header.packet_type == TdsPacketType::RpcRequest)
            && data.len() >= 12
        {
            // AllHeaders TotalLength를 동적으로 읽기
            // TDS 헤더(8바이트) 뒤의 4바이트가 AllHeaders TotalLength (little-endian)
            let all_headers_total =
                u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;

            // AllHeaders가 있는 경우: 헤더(8) + AllHeaders TotalLength
            // AllHeaders가 없는 경우: all_headers_total이 0이거나 매우 작은 값
            if all_headers_total > 0
                && all_headers_total <= 65535
                && data.len() >= 8 + all_headers_total
            {
                8 + all_headers_total
            } else {
                // AllHeaders가 없거나 잘못된 경우: 헤더 바로 다음
                8
            }
        } else {
            // 일반적인 경우: 헤더 바로 다음
            8
        };

        if body_start >= data.len() {
            return None;
        }

        // 본문 데이터 반환 (패킷 길이를 초과하지 않도록)
        let end = (header.length as usize).min(data.len());
        if body_start < end {
            Some(&data[body_start..end])
        } else {
            None
        }
    }

    /// ============================================
    /// 4단계: TDS 데이터 디코딩
    /// ============================================
    /// TDS 패킷 데이터를 UTF-16LE로 디코딩
    /// TDS 프로토콜은 문자열을 UTF-16LE 인코딩으로 전송
    pub fn decode_utf16le(bytes: &[u8]) -> Option<String> {
        if bytes.is_empty() {
            return None;
        }

        // TDS 헤더가 있는 경우 제거
        let data = if bytes.len() > 8 && Self::looks_like_tds(bytes) {
            // tds-protocol을 사용하여 헤더 확인
            let mut buf = &bytes[..8];
            match PacketHeader::decode(&mut buf) {
                Ok(header) => {
                    // SQLBatch 패킷의 경우 AllHeaders 섹션 건너뛰기
                    if header.packet_type == PacketType::SqlBatch && bytes.len() >= 12 {
                        // AllHeaders TotalLength를 동적으로 읽기
                        let all_headers_total =
                            u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;

                        // AllHeaders가 있는 경우: 헤더(8) + AllHeaders TotalLength
                        if all_headers_total > 0
                            && all_headers_total <= 65535
                            && bytes.len() >= 8 + all_headers_total
                        {
                            &bytes[8 + all_headers_total..]
                        } else {
                            // AllHeaders가 없거나 잘못된 경우: 헤더 바로 다음
                            &bytes[8..]
                        }
                    } else {
                        &bytes[8..]
                    }
                }
                Err(_) => return None,
            }
        } else {
            bytes
        };

        if data.is_empty() {
            return None;
        }

        // UTF-16은 2바이트 단위이므로 홀수 길이 처리
        let data = if data.len() % 2 != 0 {
            &data[..data.len() - 1]
        } else {
            data
        };

        if data.is_empty() {
            return None;
        }

        // UTF-16LE 디코딩
        let (decoded, _, _had_errors) = UTF_16LE.decode(data);
        let result = decoded.into_owned();

        // 결과 검증: 너무 짧거나 제어 문자가 너무 많으면 무시
        let trimmed = result.trim();
        if trimmed.len() < 3 {
            return None;
        }

        // 출력 가능한 문자 비율 확인
        let printable_count = trimmed
            .chars()
            .filter(|c| !c.is_control() || c.is_whitespace())
            .count();

        if printable_count * 2 < trimmed.chars().count() {
            return None; // 제어 문자가 50% 이상이면 무시
        }

        Some(result)
    }

    /// ============================================
    /// 5단계: TDS 패킷에서 디코딩된 데이터 추출
    /// ============================================
    /// 전체 프로세스: 식별 → 파싱 → 본문 추출 → 디코딩
    /// 단일 패킷 처리 (하위 호환성)
    /// 첫 번째 바이트가 0x01 (SQL Batch) 또는 0x03 (RPC)인 패킷만 처리
    pub fn decode_tds_packet(data: &[u8]) -> Option<String> {
        // 1단계: TDS 패킷인지 확인
        // 첫 번째 바이트가 0x01 (SQL Batch) 또는 0x03 (RPC)인 패킷만 처리
        if !Self::looks_like_tds(data) {
            return None;
        }

        // 2단계: 헤더 파싱
        let header = Self::parse_header(data)?;

        // 3단계: 패킷 타입에 따라 다른 파싱 로직 적용
        match header.packet_type {
            TdsPacketType::RpcRequest => {
                // RPC 타입은 바이너리 프로토콜로 파싱
                Self::parse_rpc_packet(data)
            }
            _ => {
                // SQLBatch 등은 기존 로직 사용
                let payload = Self::extract_payload(data)?;
                Self::decode_utf16le(payload)
            }
        }
    }

    /// ============================================
    /// RPC 패킷 파싱 (0x03)
    /// ============================================
    /// RPCRequest 패킷을 바이너리 구조로 파싱하여 SQL 쿼리 추출
    /// TDS 7.2+ 기준, sp_executesql 패턴 지원
    fn parse_rpc_packet(data: &[u8]) -> Option<String> {
        if data.len() < 8 {
            return None;
        }

        let packet_length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < packet_length {
            return None;
        }

        let mut pos = 8; // TDS 헤더 건너뛰기

        // ALL_HEADERS 건너뛰기 (TDS 7.2+)
        if pos + 4 <= data.len() {
            let total_header_len =
                u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
                    as usize;

            if total_header_len > 0
                && total_header_len <= 65535
                && pos + total_header_len <= data.len()
            {
                pos += total_header_len;
            }
        }

        // ProcID vs ProcName 파싱
        if pos + 2 > data.len() {
            return None;
        }

        let proc_id_marker = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        if proc_id_marker == 0xFFFF {
            // ProcID 사용
            if pos + 2 > data.len() {
                return None;
            }
            let _proc_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            // proc_id == 0x000A는 sp_executesql
        } else {
            // ProcName 사용 (UTF-16LE 문자열)
            pos -= 2; // marker를 다시 읽어야 함
            if pos >= data.len() {
                return None;
            }
            let name_len = data[pos] as usize;
            pos += 1;

            if pos + name_len * 2 > data.len() {
                return None;
            }

            let name_bytes = &data[pos..pos + name_len * 2];
            let (name, _, _) = UTF_16LE.decode(name_bytes);
            debug!("RPC ProcName: {}", name);
            pos += name_len * 2;
        }

        // OptionFlags 건너뛰기 (2 bytes)
        if pos + 2 > data.len() {
            return None;
        }
        let _option_flags = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // 파라미터 반복 파싱
        let mut sql_parts = Vec::new();

        while pos < packet_length && pos < data.len() {
            // ParamName 파싱
            if pos >= data.len() {
                break;
            }
            let param_name_len = data[pos] as usize;
            pos += 1;

            if pos + param_name_len * 2 > data.len() {
                break;
            }

            let param_name_bytes = &data[pos..pos + param_name_len * 2];
            let (param_name, _, _) = UTF_16LE.decode(param_name_bytes);
            pos += param_name_len * 2;

            // StatusFlags 건너뛰기 (1 byte)
            if pos >= data.len() {
                break;
            }
            let _status_flags = data[pos];
            pos += 1;

            // TYPE_INFO 파싱
            if pos >= data.len() {
                break;
            }
            let type_id = data[pos];
            pos += 1;

            // 타입별 추가 바이트 처리 및 데이터 파싱
            match type_id {
                0xE7 => {
                    // NVARCHAR: maxLen(2) + collation(5)
                    if pos + 7 > data.len() {
                        break;
                    }
                    let _max_len = u16::from_le_bytes([data[pos], data[pos + 1]]);
                    pos += 7; // 2 + 5

                    // DataLength + Data 파싱
                    if pos + 2 > data.len() {
                        break;
                    }
                    let data_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;

                    if data_len == 0xFFFF {
                        // NULL
                        continue;
                    }

                    if pos + data_len > data.len() {
                        break;
                    }

                    let data_bytes = &data[pos..pos + data_len];
                    pos += data_len;

                    // NVARCHAR는 UTF-16LE로 디코딩
                    if data_bytes.len().is_multiple_of(2) {
                        let (decoded, _, _) = UTF_16LE.decode(data_bytes);
                        let trimmed = decoded.trim();
                        if !trimmed.is_empty() {
                            // @stmt 파라미터는 SQL 쿼리 본문
                            if param_name == "@stmt" || param_name == "@statement" {
                                sql_parts.insert(0, trimmed.to_string());
                            } else {
                                sql_parts.push(format!("{}={}", param_name, trimmed));
                            }
                        }
                    }
                }
                0xA7 => {
                    // VARCHAR: maxLen(2) + collation(5)
                    if pos + 7 > data.len() {
                        break;
                    }
                    let _max_len = u16::from_le_bytes([data[pos], data[pos + 1]]);
                    let _collation = &data[pos + 2..pos + 7];
                    pos += 7;

                    // DataLength + Data 파싱
                    if pos + 2 > data.len() {
                        break;
                    }
                    let data_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;

                    if data_len == 0xFFFF {
                        // NULL
                        continue;
                    }

                    if pos + data_len > data.len() {
                        break;
                    }

                    let data_bytes = &data[pos..pos + data_len];
                    pos += data_len;

                    // VARCHAR는 코드페이지로 디코딩 (일반적으로 CP949)
                    // 간단하게 Latin1 또는 UTF-8로 시도
                    if let Ok(decoded) = String::from_utf8(data_bytes.to_vec()) {
                        if !decoded.trim().is_empty() {
                            sql_parts.push(format!("{}={}", param_name, decoded));
                        }
                    }
                }
                0x26 => {
                    // INT: 추가 바이트 없음
                    // DataLength + Data 파싱
                    if pos + 2 > data.len() {
                        break;
                    }
                    let data_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;

                    if data_len == 0xFFFF {
                        // NULL
                        continue;
                    }

                    if pos + data_len > data.len() {
                        break;
                    }

                    if data_len == 4 {
                        let int_val = i32::from_le_bytes([
                            data[pos],
                            data[pos + 1],
                            data[pos + 2],
                            data[pos + 3],
                        ]);
                        sql_parts.push(format!("{}={}", param_name, int_val));
                    }
                    pos += data_len;
                }
                0x6A => {
                    // FLOAT: 추가 바이트 없음
                    // DataLength + Data 파싱
                    if pos + 2 > data.len() {
                        break;
                    }
                    let data_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;

                    if data_len == 0xFFFF {
                        // NULL
                        continue;
                    }

                    if pos + data_len > data.len() {
                        break;
                    }

                    if data_len == 8 {
                        let float_val = f64::from_le_bytes([
                            data[pos],
                            data[pos + 1],
                            data[pos + 2],
                            data[pos + 3],
                            data[pos + 4],
                            data[pos + 5],
                            data[pos + 6],
                            data[pos + 7],
                        ]);
                        sql_parts.push(format!("{}={}", param_name, float_val));
                    }
                    pos += data_len;
                }
                _ => {
                    // 알 수 없는 타입: DataLength만 읽고 건너뛰기
                    if pos + 2 > data.len() {
                        break;
                    }
                    let data_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;

                    if data_len == 0xFFFF {
                        // NULL
                        continue;
                    }

                    if pos + data_len > data.len() {
                        break;
                    }
                    pos += data_len;
                }
            }
        }

        // SQL 쿼리 조합
        if sql_parts.is_empty() {
            return None;
        }

        // @stmt가 있으면 그것을 메인으로, 나머지는 파라미터로
        let result = if sql_parts.len() > 1 && sql_parts[0].starts_with("SELECT")
            || sql_parts[0].starts_with("INSERT")
            || sql_parts[0].starts_with("UPDATE")
            || sql_parts[0].starts_with("DELETE")
            || sql_parts[0].starts_with("EXEC")
        {
            format!("{} -- {}", sql_parts[0], sql_parts[1..].join(", "))
        } else {
            sql_parts.join(" | ")
        };

        Some(result)
    }

    /// ============================================
    /// 6단계: 여러 TDS 패킷 프레이밍 및 디코딩
    /// ============================================
    /// 재조립된 TCP 스트림에서 여러 TDS 패킷이 연속으로 붙어있을 수 있음
    /// 각 패킷을 프레이밍하여 개별적으로 처리
    pub fn decode_tds_packets(data: &[u8]) -> Vec<String> {
        let (decoded, _) = Self::decode_tds_packets_with_raw(data);
        decoded
    }

    /// ============================================
    /// 6-2단계: 여러 TDS 패킷 프레이밍 및 디코딩 (원본 데이터 포함)
    /// ============================================
    /// 재조립된 TCP 스트림에서 여러 TDS 패킷이 연속으로 붙어있을 수 있음
    /// 각 패킷을 프레이밍하여 개별적으로 처리하고 원본 패킷 데이터도 반환
    /// 첫 번째 바이트가 0x01 (SQL Batch) 또는 0x03 (RPC)인 패킷만 처리
    pub fn decode_tds_packets_with_raw(data: &[u8]) -> (Vec<String>, Vec<Vec<u8>>) {
        let mut decoded_results = Vec::new();
        let mut raw_results = Vec::new();
        let mut buf = data;

        // 프레이밍 루프: 버퍼에 패킷이 있는 동안 반복
        while buf.len() >= 8 {
            // 0단계: 첫 번째 바이트가 0x01 (SQL Batch) 또는 0x03 (RPC)인지 확인
            let packet_type_byte = buf[0];
            if packet_type_byte != 0x01 && packet_type_byte != 0x03 {
                // SQL 추출에 필요한 패킷 타입이 아니면 건너뛰기
                // 다음 패킷을 찾기 위해 1바이트씩 이동
                buf = &buf[1..];
                continue;
            }

            // 1단계: 헤더 파싱
            let mut header_buf = &buf[..8];
            let header = match PacketHeader::decode(&mut header_buf) {
                Ok(h) => h,
                Err(_) => {
                    // 유효한 헤더가 아니면 1바이트씩 이동하여 다음 패킷 찾기
                    buf = &buf[1..];
                    continue;
                }
            };

            // 1-2단계: 패킷 타입 확인 (SQL Batch 또는 RPC만 처리)
            if !matches!(header.packet_type, PacketType::SqlBatch | PacketType::Rpc) {
                // SQL 추출에 필요한 패킷 타입이 아니면 건너뛰기
                let packet_length = header.length as usize;
                if buf.len() < packet_length {
                    break;
                }
                buf = &buf[packet_length..];
                continue;
            }

            let packet_length = header.length as usize;

            // 2단계: 패킷이 완전한지 확인
            if buf.len() < packet_length {
                // 패킷이 완전하지 않음 (더 기다려야 함)
                break;
            }

            // 3단계: 단일 패킷 추출
            let packet = &buf[..packet_length];
            let packet_bytes = packet.to_vec(); // 원본 패킷 복사

            // 4단계: 패킷 디코딩
            if let Some(decoded) = Self::decode_tds_packet(packet) {
                decoded_results.push(decoded);
                raw_results.push(packet_bytes);
            }

            // 5단계: 다음 패킷으로 이동
            buf = &buf[packet_length..];
        }

        (decoded_results, raw_results)
    }
}
