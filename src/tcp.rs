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
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }

    /// Check if the flow is client to server
    pub fn is_client_to_server(&self, src_ip: IpAddr, src_port: u16) -> bool {
        src_ip == self.src_ip && src_port == self.src_port
    }
}

/// TCP Segment
#[derive(Debug, Clone)]
pub struct TcpSegment {
    pub seq: u32,
    pub data: Vec<u8>,
    pub timestamp: f64,
}

/// TCP Reassembler
pub struct TcpReassembler {
    flows: HashMap<FlowId, TcpStream>,
}

/// TCP Stream State
struct TcpStream {
    client_segments: Vec<TcpSegment>,
    server_segments: Vec<TcpSegment>,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    /// Add TCP packet
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

    /// Get reassembled client to server data
    pub fn get_client_data(&self, flow_id: &FlowId) -> Option<Vec<u8>> {
        self.flows
            .get(flow_id)
            .and_then(|stream| Self::reassemble_segments(&stream.client_segments))
    }

    /// Get reassembled server to client data
    pub fn get_server_data(&self, flow_id: &FlowId) -> Option<Vec<u8>> {
        self.flows
            .get(flow_id)
            .and_then(|stream| Self::reassemble_segments(&stream.server_segments))
    }

    /// Reassemble segments
    fn reassemble_segments(segments: &[TcpSegment]) -> Option<Vec<u8>> {
        if segments.is_empty() {
            return None;
        }

        let mut sorted: Vec<_> = segments.iter().collect();
        sorted.sort_by_key(|s| s.seq);

        let mut result = Vec::new();
        let mut expected_seq = sorted[0].seq;

        for segment in sorted {
            // Check if the segment is already processed
            if segment.seq < expected_seq {
                let overlap = expected_seq - segment.seq;
                if overlap < segment.data.len() as u32 {
                    let start = overlap as usize;
                    result.extend_from_slice(&segment.data[start..]);
                    expected_seq = segment.seq + segment.data.len() as u32;
                }
            } else if segment.seq == expected_seq {
                // Continuous data
                result.extend_from_slice(&segment.data);
                expected_seq += segment.data.len() as u32;
            } else if segment.seq > expected_seq {
                // 순서가 바뀐 경우: 빈 공간이 있으면 건너뛰기
                // (패킷 손실 또는 순서 변경 - 일단 현재까지의 데이터 반환)
                break;
            }
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    /// Get all flow IDs
    pub fn get_flows(&self) -> Vec<FlowId> {
        self.flows.keys().cloned().collect()
    }
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}
