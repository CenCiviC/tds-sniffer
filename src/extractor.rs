use crate::output::SqlEvent;
use crate::tcp::{FlowId, TcpReassembler};
use crate::tds::TdsParser;
// log는 현재 사용하지 않음
use regex::Regex;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::mpsc;

/// SQL 추출기
pub struct Extractor {
    reassembler: TcpReassembler,
    use_tds_parsing: bool, // v1: false (휴리스틱), v2: true (TDS 파싱)
}

impl Extractor {
    pub fn new(use_tds_parsing: bool) -> Self {
        Self {
            reassembler: TcpReassembler::new(),
            use_tds_parsing,
        }
    }

    /// 네트워크 인터페이스 목록 가져오기
    pub fn list_interfaces() -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
        let devices = pcap::Device::list()?;

        Ok(devices
            .into_iter()
            .map(|d| {
                let desc = d
                    .desc
                    .unwrap_or_else(|| "No description".to_string());
                (d.name, desc)
            })
            .collect())
    }

    /// 실시간 네트워크 캡처 시작
    pub fn start_live_capture(
        &mut self,
        interface: &str,
        sender: mpsc::Sender<SqlEvent>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut cap = pcap::Capture::from_device(interface)?
            .promisc(true)
            .snaplen(65535)
            .open()?;

        let mut flow_timestamps: std::collections::HashMap<FlowId, f64> =
            std::collections::HashMap::new();

        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let timestamp =
                        packet.header.ts.tv_sec as f64 + (packet.header.ts.tv_usec as f64 / 1_000_000.0);

                    // Ethernet + IP + TCP 파싱
                    if let Some((flow_id, seq, data, is_client)) =
                        Self::parse_packet(packet.data, timestamp)
                    {
                        // 첫 번째 패킷의 타임스탬프 저장
                        flow_timestamps.entry(flow_id.clone()).or_insert(timestamp);

                        self.reassembler.add_packet(
                            flow_id.clone(),
                            if is_client {
                                flow_id.src_ip
                            } else {
                                flow_id.dst_ip
                            },
                            if is_client {
                                flow_id.src_port
                            } else {
                                flow_id.dst_port
                            },
                            seq,
                            data,
                            timestamp,
                        );

                        // 재조립된 스트림에서 SQL 추출 (실시간)
                        if let Some(client_data) = self.reassembler.get_client_data(&flow_id) {
                            if let Some(sql_text) = self.extract_sql(&client_data) {
                                let tables = Self::extract_tables(&sql_text);
                                let operation = Self::extract_operation(&sql_text);

                                // 플로우의 첫 번째 타임스탬프 사용
                                let timestamp_sec =
                                    flow_timestamps.get(&flow_id).copied().unwrap_or(0.0);
                                let timestamp = chrono::DateTime::from_timestamp(
                                    timestamp_sec as i64,
                                    ((timestamp_sec - timestamp_sec.floor()) * 1_000_000_000.0) as u32,
                                )
                                .unwrap_or_default();

                                let event = SqlEvent {
                                    timestamp,
                                    flow_id: format!(
                                        "{}:{}->{}:{}",
                                        flow_id.src_ip,
                                        flow_id.src_port,
                                        flow_id.dst_ip,
                                        flow_id.dst_port
                                    ),
                                    sql_text,
                                    tables,
                                    operation,
                                    label: None,
                                };

                                // 실시간으로 이벤트 전송
                                if sender.send(event).is_err() {
                                    break; // 수신자가 없으면 종료
                                }

                                // 재조립된 데이터를 처리했으므로 초기화 (다음 패킷을 위해)
                                // 주의: 간단한 구현이므로 완전한 재조립은 아님
                            }
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // 타임아웃은 정상 (계속 대기)
                    continue;
                }
                Err(e) => {
                    return Err(Box::new(e));
                }
            }
        }
        
        Ok(())
    }

    /// pcap 파일에서 SQL 이벤트 추출
    pub fn extract_from_pcap(
        &mut self,
        file_path: &str,
    ) -> Result<Vec<SqlEvent>, Box<dyn std::error::Error>> {
        let mut events = Vec::new();
        let mut flow_timestamps: std::collections::HashMap<FlowId, f64> =
            std::collections::HashMap::new();

        // pcap 크레이트 사용
        let mut cap = pcap::Capture::from_file(file_path)?;

        while let Ok(packet) = cap.next_packet() {
            let timestamp =
                packet.header.ts.tv_sec as f64 + (packet.header.ts.tv_usec as f64 / 1_000_000.0);

            // Ethernet + IP + TCP 파싱
            if let Some((flow_id, seq, data, is_client)) =
                Self::parse_packet(packet.data, timestamp)
            {
                // 첫 번째 패킷의 타임스탬프 저장
                flow_timestamps.entry(flow_id.clone()).or_insert(timestamp);

                self.reassembler.add_packet(
                    flow_id.clone(),
                    if is_client {
                        flow_id.src_ip
                    } else {
                        flow_id.dst_ip
                    },
                    if is_client {
                        flow_id.src_port
                    } else {
                        flow_id.dst_port
                    },
                    seq,
                    data,
                    timestamp,
                );
            }
        }

        // 재조립된 스트림에서 SQL 추출
        for flow_id in self.reassembler.get_flows() {
            if let Some(client_data) = self.reassembler.get_client_data(&flow_id) {
                if let Some(sql_text) = self.extract_sql(&client_data) {
                    let tables = Self::extract_tables(&sql_text);
                    let operation = Self::extract_operation(&sql_text);

                    // 플로우의 첫 번째 타임스탬프 사용
                    let timestamp_sec = flow_timestamps.get(&flow_id).copied().unwrap_or(0.0);
                    let timestamp = chrono::DateTime::from_timestamp(
                        timestamp_sec as i64,
                        ((timestamp_sec - timestamp_sec.floor()) * 1_000_000_000.0) as u32,
                    )
                    .unwrap_or_default();

                    events.push(SqlEvent {
                        timestamp,
                        flow_id: format!(
                            "{}:{}->{}:{}",
                            flow_id.src_ip, flow_id.src_port, flow_id.dst_ip, flow_id.dst_port
                        ),
                        sql_text,
                        tables,
                        operation,
                        label: None,
                    });
                }
            }
        }

        Ok(events)
    }

    /// 패킷 파싱 (간단한 구현)
    fn parse_packet(data: &[u8], _timestamp: f64) -> Option<(FlowId, u32, Vec<u8>, bool)> {
        // Ethernet 헤더 (14 bytes) 건너뛰기
        if data.len() < 14 {
            return None;
        }

        let ip_start = 14;
        if data.len() < ip_start + 20 {
            return None;
        }

        // IP 헤더 확인
        let version = (data[ip_start] >> 4) & 0x0F;
        if version != 4 {
            return None; // IPv4만 지원
        }

        let ip_header_len = ((data[ip_start] & 0x0F) * 4) as usize;
        let protocol = data[ip_start + 9];

        if protocol != 6 {
            return None; // TCP만 처리
        }

        // IP 주소 추출
        let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
            data[ip_start + 12],
            data[ip_start + 13],
            data[ip_start + 14],
            data[ip_start + 15],
        ));
        let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
            data[ip_start + 16],
            data[ip_start + 17],
            data[ip_start + 18],
            data[ip_start + 19],
        ));

        // TCP 헤더
        let tcp_start = ip_start + ip_header_len;
        if data.len() < tcp_start + 20 {
            return None;
        }

        let src_port = u16::from_be_bytes([data[tcp_start], data[tcp_start + 1]]);
        let dst_port = u16::from_be_bytes([data[tcp_start + 2], data[tcp_start + 3]]);

        // TDS 프로토콜 필터링: MSSQL 기본 포트 1433 또는 TDS 헤더 확인
        const MSSQL_PORT: u16 = 1433;
        let is_tds_port = src_port == MSSQL_PORT || dst_port == MSSQL_PORT;

        let seq = u32::from_be_bytes([
            data[tcp_start + 4],
            data[tcp_start + 5],
            data[tcp_start + 6],
            data[tcp_start + 7],
        ]);

        let tcp_header_len = ((data[tcp_start + 12] >> 4) * 4) as usize;
        let payload_start = tcp_start + tcp_header_len;

        if data.len() < payload_start {
            return None;
        }

        let payload = data[payload_start..].to_vec();

        // TDS 프로토콜 확인: 포트가 1433이거나, 페이로드가 TDS 헤더로 시작하는지 확인
        let is_tds = is_tds_port || Self::is_tds_packet(&payload);

        if !is_tds {
            return None; // TDS 프로토콜이 아니면 무시
        }

        let flow_id = FlowId::new(src_ip, src_port, dst_ip, dst_port);
        let is_client = flow_id.is_client_to_server(src_ip, src_port);

        Some((flow_id, seq, payload, is_client))
    }

    /// TDS 패킷인지 확인 (TDS 헤더 확인)
    fn is_tds_packet(payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
        }

        // TDS 패킷 타입 확인 (0x01=SQLBatch, 0x03=RPC, 0x04=Response 등)
        let packet_type = payload[0];
        matches!(
            packet_type,
            0x01 | 0x03
                | 0x04
                | 0x06
                | 0x07
                | 0x08
                | 0x0E
                | 0x0F
                | 0x10
                | 0x11
                | 0x12
                | 0x13
                | 0x14
                | 0x15
                | 0x16
                | 0x17
                | 0x18
        )
    }

    /// 재조립된 데이터에서 SQL 추출
    fn extract_sql(&self, data: &[u8]) -> Option<String> {
        if self.use_tds_parsing {
            TdsParser::extract_sql_from_tds(data)
        } else {
            TdsParser::extract_sql_heuristic(data)
        }
    }

    /// SQL에서 테이블명 추출
    fn extract_tables(sql: &str) -> Vec<String> {
        let mut tables = HashSet::new();

        // FROM, JOIN, UPDATE, INSERT INTO, DELETE FROM 등의 패턴 찾기
        // 한글 문자도 포함 ([\w\u{AC00}-\u{D7A3}]는 한글 포함)
        let patterns = vec![
            (
                r"(?i)\bFROM\s+([\w\u{AC00}-\u{D7A3}]+(?:\.[\w\u{AC00}-\u{D7A3}]+)*)",
                "FROM",
            ),
            (
                r"(?i)\bJOIN\s+([\w\u{AC00}-\u{D7A3}]+(?:\.[\w\u{AC00}-\u{D7A3}]+)*)",
                "JOIN",
            ),
            (
                r"(?i)\bUPDATE\s+([\w\u{AC00}-\u{D7A3}]+(?:\.[\w\u{AC00}-\u{D7A3}]+)*)",
                "UPDATE",
            ),
            (
                r"(?i)\bINTO\s+([\w\u{AC00}-\u{D7A3}]+(?:\.[\w\u{AC00}-\u{D7A3}]+)*)",
                "INTO",
            ),
            (
                r"(?i)\bDELETE\s+FROM\s+([\w\u{AC00}-\u{D7A3}]+(?:\.[\w\u{AC00}-\u{D7A3}]+)*)",
                "DELETE",
            ),
        ];

        for (pattern, _) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(sql) {
                    if let Some(table_match) = cap.get(1) {
                        let table = table_match.as_str().trim();
                        // 스키마.테이블 형식에서 테이블만 추출
                        if let Some(dot_pos) = table.rfind('.') {
                            let table_name = table[dot_pos + 1..].to_string();
                            if !table_name.is_empty() {
                                tables.insert(table_name);
                            }
                        } else {
                            if !table.is_empty() {
                                tables.insert(table.to_string());
                            }
                        }
                    }
                }
            }
        }

        let mut result: Vec<String> = tables.into_iter().collect();
        result.sort();
        result
    }

    /// SQL 작업 유형 추출
    fn extract_operation(sql: &str) -> String {
        let upper = sql.trim().to_uppercase();

        if upper.starts_with("SELECT") {
            "SELECT".to_string()
        } else if upper.starts_with("INSERT") {
            "INSERT".to_string()
        } else if upper.starts_with("UPDATE") {
            "UPDATE".to_string()
        } else if upper.starts_with("DELETE") {
            "DELETE".to_string()
        } else if upper.starts_with("EXEC") || upper.starts_with("EXECUTE") {
            "EXEC".to_string()
        } else if upper.starts_with("CREATE") {
            "CREATE".to_string()
        } else if upper.starts_with("ALTER") {
            "ALTER".to_string()
        } else if upper.starts_with("DROP") {
            "DROP".to_string()
        } else {
            "UNKNOWN".to_string()
        }
    }
}
