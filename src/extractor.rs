use crate::tcp::{Consumed, Direction, Endpoint, FlowId, TcpReassembler};
use crate::tds::TdsAssembler;
use crate::SqlEvent;
use chrono::{DateTime, Utc};
use log::{debug, warn};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc;

/// 이보다 짧은 디코딩 결과는 SQL로 보지 않는다.
const MIN_SQL_LEN: usize = 3;

/// 아직 TDS 프레임을 하나도 인식하지 못한 버퍼를 이만큼까지는 그대로 둔다.
///
/// 순서가 뒤바뀌어 패킷의 뒷부분이 먼저 도착했을 수 있으므로, 곧바로
/// 재동기화하며 버리지 않고 앞 세그먼트를 기다린다. TDS 패킷 길이 필드가
/// `u16`이라 한 패킷은 이 값을 넘을 수 없다.
const MAX_UNSYNCED_BYTES: usize = 64 * 1024;

/// 캡처 루프가 중지 신호를 확인하는 주기(ms).
const CAPTURE_TIMEOUT_MS: i32 = 100;

const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_PROTO_TCP: u8 = 6;
const MIN_IP_HEADER_LEN: usize = 20;
const MIN_TCP_HEADER_LEN: usize = 20;

/// 패킷 캡처 중 발생할 수 있는 오류.
#[derive(Debug)]
pub enum CaptureError {
    /// 인터페이스 열기/읽기 실패.
    Pcap(pcap::Error),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pcap(e) => write!(f, "패킷 캡처 오류: {e}"),
        }
    }
}

impl std::error::Error for CaptureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pcap(e) => Some(e),
        }
    }
}

impl From<pcap::Error> for CaptureError {
    fn from(e: pcap::Error) -> Self {
        Self::Pcap(e)
    }
}

/// 이더넷 프레임에서 뽑아낸 TCP 세그먼트.
///
/// `payload`는 캡처 버퍼를 **빌린다**. 재조립기에 넣기로 결정하는 순간까지
/// 복사가 일어나지 않는다.
#[derive(Debug)]
pub struct ParsedPacket<'a> {
    pub src: Endpoint,
    pub dst: Endpoint,
    pub seq: u32,
    pub payload: &'a [u8],
}

/// 이더넷 프레임 하나를 파싱한다 (Ethernet II + IPv4 + TCP).
///
/// 관심 없는 프레임이면 `None`. 링크 계층은 이더넷으로 가정한다.
#[must_use]
pub fn parse_packet(frame: &[u8]) -> Option<ParsedPacket<'_>> {
    // --- Ethernet II ---
    if frame.len() < ETHERNET_HEADER_LEN + MIN_IP_HEADER_LEN {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = &frame[ETHERNET_HEADER_LEN..];

    // --- IPv4 ---
    if ip[0] >> 4 != 4 {
        return None;
    }
    let ip_header_len = (ip[0] & 0x0F) as usize * 4;
    if !(MIN_IP_HEADER_LEN..=ip.len()).contains(&ip_header_len) {
        return None;
    }
    if ip[9] != IP_PROTO_TCP {
        return None;
    }
    // 첫 조각이 아닌 IP 조각에는 TCP 헤더가 없다. 그대로 파싱하면 페이로드
    // 앞부분을 헤더로 착각해 엉뚱한 플로우의 시퀀스 공간에 쓰레기를 넣는다.
    let fragment_offset = u16::from_be_bytes([ip[6] & 0x1F, ip[7]]);
    if fragment_offset != 0 {
        return None;
    }

    // IP total length로 잘라내야 한다. 이더넷 최소 프레임(60바이트) 패딩이
    // TCP 페이로드로 딸려 들어가면 TDS 프레이밍이 깨진다.
    let ip_total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let ip_end = if (ip_header_len..=ip.len()).contains(&ip_total_len) {
        ip_total_len
    } else {
        ip.len()
    };

    let src_ip = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));

    // --- TCP ---
    let tcp = ip.get(ip_header_len..ip_end)?;
    if tcp.len() < MIN_TCP_HEADER_LEN {
        return None;
    }
    let tcp_header_len = (tcp[12] >> 4) as usize * 4;
    if !(MIN_TCP_HEADER_LEN..=tcp.len()).contains(&tcp_header_len) {
        return None;
    }

    Some(ParsedPacket {
        src: Endpoint::new(src_ip, u16::from_be_bytes([tcp[0], tcp[1]])),
        dst: Endpoint::new(dst_ip, u16::from_be_bytes([tcp[2], tcp[3]])),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        payload: &tcp[tcp_header_len..],
    })
}

/// pcap 헤더의 `timeval`을 UTC 시각으로 변환한다.
///
/// `timeval` 필드 폭은 플랫폼마다 다르다(Windows의 `long`은 32비트,
/// macOS/Linux는 64비트). 개발은 macOS에서 하고 실행은 Windows에서 하므로
/// 양쪽을 모두 흡수하도록 `try_from`을 쓴다 — 한쪽 플랫폼에서는 이 변환이
/// 항등이라 clippy가 불필요하다고 보지만, 다른 쪽에서는 필요하다.
#[allow(
    clippy::useless_conversion,
    clippy::unnecessary_fallible_conversions,
    reason = "timeval 필드 폭이 대상 플랫폼마다 달라 양쪽을 모두 지원해야 한다"
)]
fn capture_time(header: &pcap::PacketHeader) -> DateTime<Utc> {
    let ts = header.ts;
    to_datetime(
        i64::try_from(ts.tv_sec).unwrap_or_default(),
        i64::try_from(ts.tv_usec).unwrap_or_default(),
    )
}

/// 초/마이크로초를 UTC 시각으로 변환한다.
///
/// 초/마이크로초를 정수인 채로 다룬다. 예전처럼 `f64`를 거치면 1970년 기준
/// 초 단위 값이 f64 가수(52비트)를 넘어 마이크로초 정밀도가 깨진다.
fn to_datetime(seconds: i64, micros: i64) -> DateTime<Utc> {
    let nanos = u32::try_from(micros).unwrap_or(0).saturating_mul(1_000);
    DateTime::from_timestamp(seconds, nanos).unwrap_or_else(Utc::now)
}

/// 실시간 네트워크 캡처에서 MSSQL SQL 이벤트를 뽑아내는 추출기.
#[derive(Debug, Default)]
pub struct Extractor {
    /// 플로우별 바이트 재조립 버퍼와 TDS 메시지 조립 상태를 함께 소유한다.
    reassembler: TcpReassembler<TdsAssembler>,
}

impl Extractor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 사용 가능한 네트워크 인터페이스 (이름, 설명) 목록.
    ///
    /// # Errors
    /// pcap이 장치 목록을 열지 못하면 실패한다.
    pub fn list_interfaces() -> Result<Vec<(String, String)>, CaptureError> {
        Ok(pcap::Device::list()?
            .into_iter()
            .map(|d| {
                let desc = d.desc.unwrap_or_else(|| "No description".to_string());
                (d.name, desc)
            })
            .collect())
    }

    /// 인터페이스를 열어 중지 신호가 올 때까지 SQL 이벤트를 캡처한다.
    ///
    /// 이 메서드는 I/O 루프만 담당한다. 실제 처리는 [`Self::process_frame`]에 있어
    /// pcap 없이도 파이프라인 전체를 테스트할 수 있다.
    ///
    /// # Errors
    /// 인터페이스를 열지 못하거나 캡처 도중 pcap 오류가 나면 실패한다.
    pub fn start_live_capture(
        &mut self,
        interface: &str,
        sender: &mpsc::Sender<SqlEvent>,
        stop_rx: &mpsc::Receiver<()>,
    ) -> Result<(), CaptureError> {
        let mut cap = pcap::Capture::from_device(interface)?
            .promisc(true)
            .snaplen(65535)
            .timeout(CAPTURE_TIMEOUT_MS)
            .open()?;

        loop {
            if stop_rx.try_recv().is_ok() {
                debug!("중지 신호 수신, 캡처 종료");
                return Ok(());
            }

            let frame = match cap.next_packet() {
                Ok(p) => p,
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(e.into()),
            };

            let now = capture_time(frame.header);
            for event in self.process_frame(frame.data, now) {
                if sender.send(event).is_err() {
                    warn!("수신자가 사라짐, 캡처 종료");
                    return Ok(());
                }
            }
        }
    }

    /// 이더넷 프레임 하나를 처리해 완성된 SQL 이벤트를 돌려준다.
    ///
    /// 처리 흐름: 프레임 파싱 → 플로우 분류 → TCP 재조립 → TDS 프레이밍 → 이벤트 생성.
    /// 관심 없는 프레임은 조기 반환으로 걸러 중첩을 만들지 않는다.
    pub fn process_frame(&mut self, frame: &[u8], now: DateTime<Utc>) -> Vec<SqlEvent> {
        let Some(packet) = parse_packet(frame) else {
            return Vec::new();
        };
        let Some((flow, direction)) = FlowId::classify(packet.src, packet.dst) else {
            return Vec::new(); // MSSQL 포트가 아니면 플로우가 만들어지지 않는다
        };
        if direction != Direction::ClientToServer || packet.payload.is_empty() {
            return Vec::new(); // SQL 요청은 클라이언트→서버 방향에만 있다
        }

        self.reassembler.push(flow, packet.seq, packet.payload, now);

        // 재조립 버퍼를 빌려서 파싱하고, 실제로 프레이밍된 만큼만 소비한다.
        let events = self
            .reassembler
            .drain_client(&flow, |assembler, buffer| {
                // 조립 상태가 플로우에 남으므로, 흡수한 패킷은 곧바로 소비된다.
                // 예전에는 메시지가 끝날 때까지 앞부분을 붙들고 있어서 세그먼트가
                // 올 때마다 지금까지의 패킷을 전부 다시 파싱했다 (O(n^2)).
                let scan = assembler.feed(buffer);
                let events: Vec<SqlEvent> = scan
                    .messages
                    .into_iter()
                    .filter(|m| m.sql.len() >= MIN_SQL_LEN)
                    // 파서가 이미 다듬은 String을 그대로 이동시킨다.
                    .map(|m| SqlEvent::new(now, flow, m.sql, m.raw.into_owned()))
                    .collect();

                let consumed = if scan.framed {
                    Consumed::synced(scan.consumed)
                } else if scan.gave_up || buffer.len() > MAX_UNSYNCED_BYTES {
                    // 한 패킷보다 큰데도 프레임을 못 찾았다. 진짜 쓰레기다.
                    Consumed::unsynced(scan.consumed)
                } else {
                    // 아직 판단하기 이르다. 앞 세그먼트가 올 수 있으니 남겨 둔다.
                    Consumed::nothing()
                };
                (events, consumed)
            })
            .unwrap_or_default();

        self.reassembler.evict_idle(now);
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ethernet + IPv4 + TCP 프레임을 조립한다. `pad_to`로 이더넷 패딩을 흉내낸다.
    pub(super) fn frame(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        payload: &[u8],
        pad_to: usize,
    ) -> Vec<u8> {
        let ip_total = u16::try_from(MIN_IP_HEADER_LEN + MIN_TCP_HEADER_LEN + payload.len())
            .expect("테스트 페이로드는 작다");

        let mut f = Vec::new();
        f.extend_from_slice(&[0xFF; 6]); // dst MAC
        f.extend_from_slice(&[0xAA; 6]); // src MAC
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

        // IPv4
        f.push(0x45); // version 4, IHL 5
        f.push(0); // DSCP/ECN
        f.extend_from_slice(&ip_total.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0]); // id, flags/frag
        f.push(64); // TTL
        f.push(IP_PROTO_TCP);
        f.extend_from_slice(&[0, 0]); // checksum
        f.extend_from_slice(&[192, 168, 0, 10]); // src
        f.extend_from_slice(&[192, 168, 0, 20]); // dst

        // TCP
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&seq.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0]); // ack
        f.push(5 << 4); // data offset 5
        f.push(0x18); // PSH|ACK
        f.extend_from_slice(&[0xFF, 0xFF]); // window
        f.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent

        f.extend_from_slice(payload);
        f.resize(f.len().max(pad_to), 0); // 이더넷 최소 프레임 패딩
        f
    }

    #[test]
    fn parses_ethernet_ipv4_tcp() {
        let f = frame(50000, 1433, 42, b"hello", 0);
        let p = parse_packet(&f).expect("유효한 프레임");
        assert_eq!(p.src.port, 50000);
        assert_eq!(p.dst.port, 1433);
        assert_eq!(p.seq, 42);
        assert_eq!(p.payload, b"hello");
    }

    /// 60바이트 미만 프레임은 NIC가 0으로 채운다. IP total length로 잘라내지 않으면
    /// 이 패딩이 TCP 페이로드로 딸려 들어가 TDS 프레이밍을 오염시킨다.
    #[test]
    fn ethernet_padding_is_trimmed() {
        let f = frame(50000, 1433, 1, b"ab", 60);
        assert_eq!(f.len(), 60, "패딩된 프레임이어야 한다");
        let p = parse_packet(&f).expect("유효한 프레임");
        assert_eq!(p.payload, b"ab", "패딩이 페이로드에 섞이면 안 된다");
    }

    #[test]
    fn rejects_non_ipv4_ethertype() {
        let mut f = frame(50000, 1433, 1, b"x", 0);
        f[12..14].copy_from_slice(&0x86DDu16.to_be_bytes()); // IPv6
        assert!(parse_packet(&f).is_none());
    }

    #[test]
    fn rejects_truncated_frames() {
        let f = frame(50000, 1433, 1, b"payload", 0);
        for n in 0..f.len() {
            let _ = parse_packet(&f[..n]); // 패닉이 없어야 한다
        }
    }

    #[test]
    fn rejects_bogus_header_lengths() {
        let mut f = frame(50000, 1433, 1, b"x", 0);
        f[ETHERNET_HEADER_LEN] = 0x40; // IHL = 0
        assert!(parse_packet(&f).is_none());

        let mut f = frame(50000, 1433, 1, b"x", 0);
        f[ETHERNET_HEADER_LEN + MIN_IP_HEADER_LEN + 12] = 0xF0; // data offset 15 (60바이트)
        assert!(parse_packet(&f).is_none());
    }

    #[test]
    fn non_sql_ports_produce_no_flow() {
        let f = frame(50000, 80, 1, b"GET / HTTP/1.1", 0);
        let p = parse_packet(&f).unwrap();
        assert!(FlowId::classify(p.src, p.dst).is_none());
    }

    // ---------- 재조립 ↔ 프레이밍 이음매 ----------
    //
    // 이 크레이트의 핵심 주장은 "TCP 세그먼트로 쪼개진 TDS 패킷을 재조립해
    // 정확히 한 번만 프레이밍한다"이다. tcp/tds는 각각 따로 테스트되지만
    // 두 계약이 만나는 지점은 여기서만 검증된다.

    /// `ALL_HEADERS` + UTF-16LE SQL을 담은 `SQLBatch` 패킷.
    fn sql_batch_packet(sql: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&22u32.to_le_bytes()); // ALL_HEADERS TotalLength
        body.extend_from_slice(&18u32.to_le_bytes());
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(&[0u8; 8]);
        body.extend_from_slice(&1u32.to_le_bytes());
        for unit in sql.encode_utf16() {
            body.extend_from_slice(&unit.to_le_bytes());
        }

        let total = u16::try_from(8 + body.len()).expect("테스트 패킷은 작다");
        let mut packet = vec![0x01, 0x01];
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&[1, 0]);
        packet.extend_from_slice(&body);
        packet
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[test]
    fn a_whole_tds_packet_in_one_frame_yields_one_event() {
        let sql = "SELECT * FROM dbo.TB_Users WHERE id = 1";
        let mut extractor = Extractor::new();
        let events =
            extractor.process_frame(&frame(50000, 1433, 1, &sql_batch_packet(sql), 0), now());

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sql(), sql);
        assert_eq!(events[0].tables(), ["dbo.TB_Users"]);
        assert_eq!(events[0].flow().server.port, 1433);
    }

    /// TDS 패킷이 두 TCP 세그먼트로 쪼개져 오면, 첫 세그먼트에서는 아무 이벤트도
    /// 나오지 않고 두 번째에서 정확히 하나가 나와야 한다. 여기서 소비 길이 계약이
    /// 어긋나면 같은 SQL이 두 번 나오거나 영영 나오지 않는다.
    #[test]
    fn a_tds_packet_split_across_segments_is_reassembled_exactly_once() {
        let sql = "SELECT * FROM dbo.TB_Users WHERE id = 1";
        let packet = sql_batch_packet(sql);
        let split = packet.len() / 2;

        let mut extractor = Extractor::new();
        let first = extractor.process_frame(&frame(50000, 1433, 100, &packet[..split], 0), now());
        assert!(first.is_empty(), "미완성 패킷에서 이벤트가 나오면 안 된다");

        let seq = 100 + u32::try_from(split).unwrap();
        let second = extractor.process_frame(&frame(50000, 1433, seq, &packet[split..], 0), now());
        assert_eq!(second.len(), 1, "완성되면 정확히 하나");
        assert_eq!(second[0].sql(), sql);
    }

    /// 이미 프레이밍한 바이트를 다시 파싱하면 안 된다. 원본은 매 패킷마다 스트림
    /// 전체를 다시 디코딩해서 같은 SQL을 계속 다시 내보냈다.
    #[test]
    fn already_framed_bytes_are_not_reparsed() {
        let mut extractor = Extractor::new();
        let first = sql_batch_packet("SELECT 1 FROM dbo.TB_A");
        let second = sql_batch_packet("SELECT 2 FROM dbo.TB_B");

        let a = extractor.process_frame(&frame(50000, 1433, 1, &first, 0), now());
        assert_eq!(a.len(), 1);

        let seq = 1 + u32::try_from(first.len()).unwrap();
        let b = extractor.process_frame(&frame(50000, 1433, seq, &second, 0), now());
        assert_eq!(b.len(), 1, "이전 패킷이 다시 나오면 안 된다");
        assert_eq!(b[0].sql(), "SELECT 2 FROM dbo.TB_B");
    }

    /// 순서가 뒤바뀐 세그먼트도 빈틈이 메워지면 조립되어야 한다.
    #[test]
    fn out_of_order_segments_still_produce_the_event() {
        let sql = "SELECT * FROM dbo.TB_Users";
        let packet = sql_batch_packet(sql);
        let split = packet.len() / 2;
        let seq = 100 + u32::try_from(split).unwrap();

        let mut extractor = Extractor::new();
        // 뒷부분이 먼저 도착한다.
        assert!(extractor
            .process_frame(&frame(50000, 1433, seq, &packet[split..], 0), now())
            .is_empty());
        let events = extractor.process_frame(&frame(50000, 1433, 100, &packet[..split], 0), now());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sql(), sql);
    }

    /// 서버→클라이언트 방향에는 SQL 요청이 없다.
    #[test]
    fn server_to_client_frames_are_ignored() {
        let mut extractor = Extractor::new();
        let packet = sql_batch_packet("SELECT 1 FROM dbo.TB_A");
        let events = extractor.process_frame(&frame(1433, 50000, 1, &packet, 0), now());
        assert!(events.is_empty());
    }

    /// MSSQL 포트가 아닌 트래픽은 아예 플로우를 만들지 않는다.
    #[test]
    fn non_sql_traffic_creates_no_flow() {
        let mut extractor = Extractor::new();
        let packet = sql_batch_packet("SELECT 1 FROM dbo.TB_A");
        assert!(extractor
            .process_frame(&frame(50000, 8080, 1, &packet, 0), now())
            .is_empty());
    }

    /// f64를 거치면 잃어버리던 마이크로초 정밀도가 그대로 보존되어야 한다.
    #[test]
    fn timestamp_conversion_keeps_microsecond_precision() {
        let dt = to_datetime(1_700_000_000, 123_456);
        assert_eq!(dt.timestamp(), 1_700_000_000);
        assert_eq!(dt.timestamp_subsec_micros(), 123_456);
    }
}

#[cfg(test)]
mod fragment_tests {
    use super::*;

    /// 첫 조각이 아닌 IP 조각에는 TCP 헤더가 없다. 그대로 파싱하면 페이로드
    /// 앞부분을 헤더로 착각해 엉뚱한 플로우의 시퀀스 공간에 쓰레기를 넣는다.
    #[test]
    fn non_first_ip_fragments_are_ignored() {
        let mut f = tests::frame(50000, 1433, 1, b"payload", 0);
        // fragment offset = 185 (바이트 오프셋 1480)
        let offset: u16 = 185;
        f[ETHERNET_HEADER_LEN + 6] = (offset >> 8) as u8;
        f[ETHERNET_HEADER_LEN + 7] = (offset & 0xFF) as u8;
        assert!(parse_packet(&f).is_none());
    }

    /// 첫 조각(오프셋 0)과 More-Fragments 비트만 선 프레임은 그대로 처리한다.
    #[test]
    fn the_first_fragment_is_still_parsed() {
        let mut f = tests::frame(50000, 1433, 1, b"payload", 0);
        f[ETHERNET_HEADER_LEN + 6] = 0x20; // MF 비트, 오프셋 0
        assert!(parse_packet(&f).is_some());
    }
}
