use std::collections::HashMap;
use std::net::IpAddr;

/// TCP 플로우 식별자
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowId {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl FlowId {
    /// 플로우 ID 생성 (항상 작은 IP:포트를 먼저 정렬)
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        if (src_ip, src_port) <= (dst_ip, dst_port) {
            Self {
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            }
        } else {
            Self {
                src_ip: dst_ip,
                src_port: dst_port,
                dst_ip: src_ip,
                dst_port: src_port,
            }
        }
    }

    /// 패킷이 클라이언트→서버 방향인지 확인
    pub fn is_client_to_server(&self, src_ip: IpAddr, src_port: u16) -> bool {
        src_ip == self.src_ip && src_port == self.src_port
    }
}

/// TCP 세그먼트
#[derive(Debug, Clone)]
pub struct TcpSegment {
    pub seq: u32,
    pub data: Vec<u8>,
    pub timestamp: f64,
}

/// TCP 스트림 재조립기
pub struct TcpReassembler {
    flows: HashMap<FlowId, TcpStream>,
}

/// TCP 스트림 상태
struct TcpStream {
    client_segments: Vec<TcpSegment>,
    server_segments: Vec<TcpSegment>,
    #[allow(dead_code)]
    client_next_seq: Option<u32>,
    #[allow(dead_code)]
    server_next_seq: Option<u32>,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    /// TCP 패킷 추가
    pub fn add_packet(
        &mut self,
        flow_id: FlowId,
        src_ip: IpAddr,
        src_port: u16,
        seq: u32,
        data: Vec<u8>,
        timestamp: f64,
    ) {
        let is_client = flow_id.is_client_to_server(src_ip, src_port);
        let stream = self.flows.entry(flow_id).or_insert_with(|| TcpStream {
            client_segments: Vec::new(),
            server_segments: Vec::new(),
            client_next_seq: None,
            server_next_seq: None,
        });

        let segment = TcpSegment {
            seq,
            data,
            timestamp,
        };

        if is_client {
            stream.client_segments.push(segment);
        } else {
            stream.server_segments.push(segment);
        }
    }

    /// 재조립된 클라이언트→서버 데이터 가져오기
    pub fn get_client_data(&self, flow_id: &FlowId) -> Option<Vec<u8>> {
        self.flows
            .get(flow_id)
            .and_then(|stream| Self::reassemble_segments(&stream.client_segments))
    }

    /// 재조립된 서버→클라이언트 데이터 가져오기
    pub fn get_server_data(&self, flow_id: &FlowId) -> Option<Vec<u8>> {
        self.flows
            .get(flow_id)
            .and_then(|stream| Self::reassemble_segments(&stream.server_segments))
    }

    /// 세그먼트 재조립
    fn reassemble_segments(segments: &[TcpSegment]) -> Option<Vec<u8>> {
        if segments.is_empty() {
            return None;
        }

        // 시퀀스 번호로 정렬
        let mut sorted: Vec<_> = segments.iter().collect();
        sorted.sort_by_key(|s| s.seq);

        let mut result = Vec::new();
        let mut expected_seq = sorted[0].seq;

        for segment in sorted {
            // 중복 제거: 이미 처리된 시퀀스 범위 체크
            if segment.seq < expected_seq {
                // 겹치는 경우 처리
                let overlap = expected_seq - segment.seq;
                if overlap < segment.data.len() as u32 {
                    let start = overlap as usize;
                    result.extend_from_slice(&segment.data[start..]);
                    expected_seq = segment.seq + segment.data.len() as u32;
                }
            } else if segment.seq == expected_seq {
                // 연속된 데이터
                result.extend_from_slice(&segment.data);
                expected_seq += segment.data.len() as u32;
            } else if segment.seq > expected_seq {
                // 순서가 바뀐 경우: 빈 공간이 있으면 건너뛰기
                // (패킷 손실 또는 순서 변경 - 일단 현재까지의 데이터 반환)
                // 실제로는 더 기다려야 할 수도 있지만, 간단한 구현을 위해 건너뛰기
                break;
            }
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    /// 모든 플로우 ID 가져오기
    pub fn get_flows(&self) -> Vec<FlowId> {
        self.flows.keys().cloned().collect()
    }
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}
