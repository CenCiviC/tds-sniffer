use crate::tcp::{FlowId, TcpReassembler};
use crate::tds::TdsParser;
use crate::SqlEvent;
use std::net::IpAddr;
use std::sync::mpsc;

/// TDS 패킷 추출기
/// TCP 스트림에서 TDS 프로토콜 패킷을 식별, 파싱, 재조립, 디코딩
pub struct Extractor {
    reassembler: TcpReassembler,
}

impl Extractor {
    pub fn new(_use_tds_parsing: bool) -> Self {
        Self {
            reassembler: TcpReassembler::new(),
        }
    }

    /// 네트워크 인터페이스 목록 가져오기
    pub fn list_interfaces() -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
        let devices = pcap::Device::list()?;

        Ok(devices
            .into_iter()
            .map(|d| {
                let desc = d.desc.unwrap_or_else(|| "No description".to_string());
                (d.name, desc)
            })
            .collect())
    }

    /// ============================================
    /// 실시간 네트워크 캡처 및 TDS 패킷 처리
    /// ============================================
    /// 단계별 처리:
    /// 1. 패킷 캡처 (Ethernet/IP/TCP 파싱)
    /// 2. TDS 패킷 식별
    /// 3. TCP 스트림 재조립
    /// 4. TDS 데이터 디코딩
    pub fn start_live_capture(
        &mut self,
        interface: &str,
        sender: mpsc::Sender<SqlEvent>,
        stop_rx: mpsc::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut cap = pcap::Capture::from_device(interface)?
            .promisc(true)
            .snaplen(65535) // 전체 패킷 캡처
            .timeout(100) // 100ms 타임아웃으로 중지 신호를 자주 확인
            .open()?;

        let mut flow_timestamps: std::collections::HashMap<FlowId, f64> =
            std::collections::HashMap::new();

        loop {
            // 중지 신호 확인
            if stop_rx.try_recv().is_ok() {
                break;
            }

            match cap.next_packet() {
                Ok(packet) => {
                    let timestamp = packet.header.ts.tv_sec as f64
                        + (packet.header.ts.tv_usec as f64 / 1_000_000.0);

                    // ============================================
                    // 1단계: 패킷 파싱 (Ethernet + IP + TCP)
                    // ============================================
                    if let Some((
                        flow_id,
                        seq,
                        data,
                        is_client,
                        actual_src_ip,
                        actual_src_port,
                        actual_dst_ip,
                        actual_dst_port,
                    )) = Self::parse_packet_all(packet.data, timestamp)
                    {
                        // 첫 번째 패킷의 타임스탬프 저장
                        flow_timestamps.entry(flow_id.clone()).or_insert(timestamp);

                        // ============================================
                        // 2단계: SQL Server 포트 필터링
                        // ============================================
                        // TCP 세그먼트가 쪼개져 있을 수 있으므로 재조립 전에 TDS 체크하지 않음
                        // 대신 포트 기반으로 필터링 (SQL Server 기본 포트: 1433)
                        // NOTE: 추가적으로 port 설정을 하고 있다면 추가해야할 수도 있음
                        let sql_server_ports = [1433, 1434, 1436]; // 1434는 SQL Browser
                        let is_sql_server_port = sql_server_ports.contains(&flow_id.src_port)
                            || sql_server_ports.contains(&flow_id.dst_port);

                        if !is_sql_server_port {
                            continue;
                        }

                        // ============================================
                        // 3단계: TCP 스트림 재조립
                        // ============================================
                        // TCP 시퀀스 번호를 기준으로 패킷 재조립
                        // 페이로드가 비어있지 않은 경우에만 재조립
                        if !data.is_empty() {
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

                        // ============================================
                        // 4단계: 재조립된 스트림에서 TDS 데이터 디코딩
                        // ============================================

                        // NOTE: Dentweb SQL Batch only exists at client to server flow
                        if is_client {
                            if let Some(client_data) = self.reassembler.get_client_data(&flow_id) {
                                // TDS 패킷인지 먼저 확인
                                if TdsParser::looks_like_tds(&client_data) {
                                    // 여러 TDS 패킷이 연속으로 붙어있을 수 있으므로 프레이밍 루프로 처리
                                    let (decoded_texts, raw_packets) =
                                        TdsParser::decode_tds_packets_with_raw(&client_data);

                                    for (decoded_text, raw_data) in
                                        decoded_texts.into_iter().zip(raw_packets.into_iter())
                                    {
                                        // 빈 텍스트나 너무 짧은 텍스트는 건너뛰기
                                        let trimmed = decoded_text.trim();
                                        if trimmed.len() < 3 {
                                            continue;
                                        }

                                        let timestamp_sec =
                                            flow_timestamps.get(&flow_id).copied().unwrap_or(0.0);
                                        let timestamp = chrono::DateTime::from_timestamp(
                                            timestamp_sec as i64,
                                            ((timestamp_sec - timestamp_sec.floor())
                                                * 1_000_000_000.0)
                                                as u32,
                                        )
                                        .unwrap_or_default();

                                        // 실제 패킷 정보
                                        let event = SqlEvent {
                                            timestamp,
                                            flow_id: format!(
                                                "{}:{}->{}:{}",
                                                actual_src_ip,
                                                actual_src_port,
                                                actual_dst_ip,
                                                actual_dst_port
                                            ),
                                            sql_text: trimmed.to_string(),
                                            tables: Vec::new(),
                                            operation: "TDS".to_string(),
                                            label: None,
                                            raw_data: Some(raw_data),
                                        };

                                        // 실시간으로 이벤트 전송
                                        if sender.send(event).is_err() {
                                            break; // 수신자가 없으면 종료
                                        }
                                    }
                                }
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

    /// ============================================
    /// 패킷 파싱: Ethernet + IP + TCP
    /// ============================================
    /// 모든 TCP 패킷을 처리 (TDS 필터링 없음)
    /// 반환값: (FlowId, 시퀀스 번호, 페이로드, 클라이언트→서버 여부, 실제 src_ip, 실제 src_port, 실제 dst_ip, 실제 dst_port)
    #[allow(clippy::type_complexity)]
    fn parse_packet_all(
        data: &[u8],
        _timestamp: f64,
    ) -> Option<(FlowId, u32, Vec<u8>, bool, IpAddr, u16, IpAddr, u16)> {
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

        // IP 헤더 길이 계산 (IHL * 4)
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

        // TCP 헤더 파싱
        let tcp_start = ip_start + ip_header_len;
        if data.len() < tcp_start + 20 {
            return None;
        }

        let src_port = u16::from_be_bytes([data[tcp_start], data[tcp_start + 1]]);
        let dst_port = u16::from_be_bytes([data[tcp_start + 2], data[tcp_start + 3]]);

        // TCP 시퀀스 번호 추출
        let seq = u32::from_be_bytes([
            data[tcp_start + 4],
            data[tcp_start + 5],
            data[tcp_start + 6],
            data[tcp_start + 7],
        ]);

        // TCP 헤더 길이 계산 (Data Offset * 4)
        let tcp_header_len = ((data[tcp_start + 12] >> 4) * 4) as usize;
        let payload_start = tcp_start + tcp_header_len;

        if data.len() < payload_start {
            return None;
        }

        // TCP 페이로드 추출
        let payload = data[payload_start..].to_vec();

        // Flow ID 생성 및 방향 확인
        let flow_id = FlowId::new(src_ip, src_port, dst_ip, dst_port);
        let is_client = flow_id.is_client_to_server(src_ip, src_port);

        // 실제 패킷 방향 정보도 함께 반환 (GUI 표시용)
        Some((
            flow_id, seq, payload, is_client, src_ip, src_port, dst_ip, dst_port,
        ))
    }
}
