use encoding_rs::{EUC_KR, UTF_16LE};
use log::trace;
use std::borrow::Cow;
use std::fmt;
use tds_protocol::packet::{PacketHeader, PacketType, PACKET_HEADER_SIZE};

/// `ALL_HEADERS` 블록의 `TotalLength는` 자기 자신(4바이트)을 포함한다.
const ALL_HEADERS_MIN: u32 = 4;
const ALL_HEADERS_MAX: u32 = 65535;

/// 사람이 읽을 만한 결과로 인정할 최소 길이(바이트).
const MIN_TEXT_LEN: usize = 3;

/// 하나의 논리 메시지가 여러 패킷에 걸칠 때 모을 수 있는 최대 바이트.
/// 이 값을 넘으면 프레이밍이 어긋난 것으로 보고 메시지를 버린다.
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// PLP 값 하나가 가질 수 있는 최대 바이트.
const MAX_PLP_BYTES: usize = 4 * 1024 * 1024;

/// PLP 총길이 자리에 오는 "길이를 모름" 표식.
const PLP_UNKNOWN_LENGTH: u64 = 0xFFFF_FFFF_FFFF_FFFE;
/// PLP 총길이 자리에 오는 NULL 표식.
const PLP_NULL: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// PLP 값 하나에 미리 잡아 둘 최대 용량.
///
/// 총길이는 패킷이 주장하는 값이라 신뢰할 수 없다. 그대로 예약하면 `4 MiB`를
/// 주장하고 곧바로 종료하는 파라미터를 수천 개 담은 52 KB 패킷 하나가
/// 기가바이트 단위의 할당을 유발해 캡처 스레드를 마비시킨다.
const PLP_RESERVE_LIMIT: usize = 64 * 1024;

/// TDS 파싱 실패 원인.
///
/// 이전에는 모든 실패가 `None` 하나로 뭉개져서 "왜 SQL이 안 잡히는지" 알 수 없었다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TdsError {
    /// 버퍼가 부족하다. 더 많은 세그먼트를 기다려야 한다.
    Truncated { need: usize, have: usize },
    /// 8바이트 헤더가 유효한 TDS 헤더가 아니다.
    BadHeader,
    /// 헤더의 length 필드가 헤더 크기보다 작다 (프레이밍 불가).
    BadLength(u16),
    /// SQL 추출 대상이 아닌 패킷 종류.
    NotARequest(PacketType),
    /// 디코딩은 됐지만 사람이 읽을 SQL로 보기 어렵다.
    NotReadableText,
    /// RPC 패킷에서 파라미터를 하나도 얻지 못했다.
    NoRpcParameters,
    /// 해석할 줄 모르는 TDS 데이터 타입. 이후 파라미터는 신뢰할 수 없다.
    UnsupportedType(u8),
    /// 값 길이가 상한을 넘었다.
    ValueTooLarge(usize),
}

impl fmt::Display for TdsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "버퍼 부족: {need}바이트 필요, {have}바이트 보유")
            }
            Self::BadHeader => f.write_str("유효한 TDS 헤더가 아님"),
            Self::BadLength(len) => write!(f, "헤더 length 필드가 비정상: {len}"),
            Self::NotARequest(t) => write!(f, "요청 패킷이 아님: {t:?}"),
            Self::NotReadableText => f.write_str("읽을 수 있는 텍스트가 아님"),
            Self::NoRpcParameters => f.write_str("RPC 파라미터 없음"),
            Self::UnsupportedType(id) => write!(f, "지원하지 않는 TDS 타입: {id:#04x}"),
            Self::ValueTooLarge(n) => write!(f, "값이 너무 큼: {n}바이트"),
        }
    }
}

impl std::error::Error for TdsError {}

/// 바이트 슬라이스 위를 전진하는 커서.
///
/// 경계 검사를 **여기 한 곳**에 모은다. 파서 본문에서 `pos + N > len` 검사를
/// 20번 넘게 반복하던 코드가 사라지고, 검사 하나를 빠뜨려 패닉이 나는 경로도 없다.
/// 반환 슬라이스는 입력 수명을 그대로 물려받아 복사가 일어나지 않는다.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    const fn need(&self, n: usize) -> Result<(), TdsError> {
        if self.remaining() < n {
            return Err(TdsError::Truncated {
                need: n,
                have: self.remaining(),
            });
        }
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TdsError> {
        self.need(n)?;
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn skip(&mut self, n: usize) -> Result<(), TdsError> {
        self.take(n).map(|_| ())
    }

    fn u8(&mut self) -> Result<u8, TdsError> {
        Ok(self.take(1)?[0])
    }

    fn u16_le(&mut self) -> Result<u16, TdsError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32_le(&mut self) -> Result<u32, TdsError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64_le(&mut self) -> Result<u64, TdsError> {
        let b = self.take(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(b);
        Ok(u64::from_le_bytes(buf))
    }

    /// 소비하지 않고 앞의 u32(LE)를 들여다본다.
    fn peek_u32_le(&self) -> Result<u32, TdsError> {
        self.need(4)?;
        let b = &self.data[self.pos..self.pos + 4];
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// UTF-16 코드 유닛 `units`개를 읽어 문자열로 만든다.
    fn utf16le(&mut self, units: usize) -> Result<String, TdsError> {
        let bytes = self.take(units * 2)?;
        Ok(UTF_16LE.decode(bytes).0.into_owned())
    }
}

/// 값의 길이를 읽는 방식. `TYPE_INFO를` 해석한 결과다.
///
/// 예전에는 모든 타입을 "2바이트 길이 접두사"로 가정해서, INTN(`0x26`) 같은
/// 1바이트 접두사 타입을 만나면 파라미터 스트림 전체가 어긋났다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LengthKind {
    /// 길이 접두사 없이 고정 길이.
    Fixed(usize),
    /// 1바이트 길이 접두사. `0xFF`는 NULL.
    Byte,
    /// 2바이트 길이 접두사. `0xFFFF`는 NULL.
    Short,
    /// PLP(부분 길이 접두사) 인코딩. `varchar(max)`/`nvarchar(max)`가 쓴다.
    PartiallyLengthPrefixed,
}

/// 재조립 버퍼 한 번 훑기의 결과.
#[derive(Debug)]
pub struct StreamScan<'a> {
    /// 완결되어 디코딩된 메시지들.
    pub messages: Vec<DecodedPacket<'a>>,
    /// 버퍼에서 제거해도 되는 바이트 수.
    pub consumed: usize,
    /// 이 플로우는 TDS가 아니라고 판단했다. 호출자는 바이트를 붙들지 말고 버려야 한다.
    pub gave_up: bool,
    /// 유효한 TDS 프레임을 하나라도 **인식**했는가 (디코딩 성공 여부와 무관).
    ///
    /// 아직 하나도 인식하지 못했다면 소비한 바이트는 재동기화 과정에서 버린
    /// 쓰레기다. 이 구분이 없으면 재조립기가 "이미 파싱한 구간"과 "아직 스트림의
    /// 시작을 못 찾은 상태"를 혼동해, 뒤늦게 도착한 앞 세그먼트를 버린다.
    pub framed: bool,
}

/// 재조립된 스트림에서 잘라낸 TDS 요청 메시지 하나.
///
/// 단일 패킷 메시지(대부분)에서는 `raw`가 입력 버퍼를 **빌린다**. 여러 패킷에
/// 걸친 메시지일 때만 이어붙인 사본을 소유한다.
#[derive(Debug)]
pub struct DecodedPacket<'a> {
    pub sql: String,
    pub raw: Cow<'a, [u8]>,
}

/// 여러 패킷에 걸쳐 조립 중인 논리 메시지.
#[derive(Debug)]
struct PartialMessage {
    packet_type: PacketType,
    /// `ALL_HEADERS`를 제거한 본문을 이어붙인 것.
    body: Vec<u8>,
    /// 원본 패킷들을 그대로 이어붙인 것.
    raw: Vec<u8>,
}

impl PartialMessage {
    const fn new(packet_type: PacketType) -> Self {
        Self {
            packet_type,
            body: Vec::new(),
            raw: Vec::new(),
        }
    }
}

/// 한 플로우의 TDS 메시지 조립 상태.
///
/// 여러 패킷에 걸친 메시지를 **호출 사이에 걸쳐** 들고 있는다. 이 상태가 없으면
/// 메시지가 끝날 때까지 그 앞부분을 소비할 수 없어서, TCP 세그먼트가 도착할
/// 때마다 지금까지의 패킷 전부를 다시 파싱하고 다시 복사하게 된다 — 메시지
/// 크기에 대해 제곱으로 늘어나는 비용이라 4 MiB 배치 하나가 캡처 스레드를
/// 수백 ms 멈춰 세우고, 그 사이 커널 링 버퍼가 넘쳐 패킷이 유실된다.
#[derive(Debug, Default)]
pub struct TdsAssembler {
    partial: Option<PartialMessage>,
    /// 프레임을 한 번도 인식하지 못한 채 **버린** 누적 바이트.
    ///
    /// 훑은 바이트가 아니라 재동기화로 버린 바이트만 센다. 프레이밍이 안 된
    /// 버퍼는 다음 패킷에서 다시 훑기 때문에, 훑은 양을 세면 같은 바이트가
    /// 반복 계산되어 멀쩡한 플로우도 금방 한도에 닿는다.
    unrecognized_bytes: usize,
    /// 직전 `feed`가 프레임 경계에서 정확히 끝났는가.
    ///
    /// 연쇄 판정을 호출 안에서만 하면, TCP 세그먼트 하나에 패킷 하나가 담기는
    /// 흔한 경우에 정상 플로우가 영영 corroborate되지 않는다.
    ends_on_frame_boundary: bool,
    /// 이 플로우는 TDS가 아니다.
    ///
    /// 연결이 암호화를 협상하면 그 뒤 클라이언트→서버 바이트는 TLS 레코드이고
    /// TDS 헤더는 암호문 안에 있다. 첫 바이트 `0x17`은 유효한 패킷 종류가 아니라
    /// 프레임을 영영 찾지 못하는데, 그동안 매 패킷마다 버퍼 전체를 1바이트씩
    /// 다시 훑게 된다. 한 번 판단하고 나면 값싸게 흘려보낸다.
    gave_up: bool,
}

/// 프레임을 하나도 인식하지 못한 채 이만큼을 훑으면 TDS가 아니라고 본다.
const GIVE_UP_AFTER_BYTES: usize = 1024 * 1024;

/// 헤더가 주장할 수 있는 최대 패킷 길이.
///
/// MS-TDS의 패킷 크기 협상 범위는 512..32767이다. `length` 필드는 `u16`이라
/// 65535까지 표현되지만, 규격을 넘는 값을 받아주면 무작위 바이트가 우연히
/// 헤더처럼 보일 확률이 두 배가 되고, 그렇게 잘못 잡은 '프레임'이 한 번에
/// 평균 32 KB씩 삼켜서 포기 판정이 한참 늦어진다.
const MAX_PACKET_LENGTH: usize = 32767;

impl TdsAssembler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 조립 중인 메시지가 붙들고 있는 바이트 수 (진단·테스트용).
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.partial
            .as_ref()
            .map_or(0, |m| m.body.len() + m.raw.len())
    }

    /// 재조립된 바이트를 먹여 완결된 메시지를 얻는다.
    ///
    /// 흡수한 바이트는 곧바로 소비 가능으로 보고한다(조립 상태가 여기 남으므로).
    /// 아직 도착하지 않은 패킷의 앞부분만 버퍼에 남는다.
    pub fn feed<'a>(&mut self, data: &'a [u8]) -> StreamScan<'a> {
        if self.gave_up {
            // 이 플로우는 TDS가 아니다. 훑지 않고 그대로 흘려보낸다.
            return StreamScan {
                messages: Vec::new(),
                consumed: data.len(),
                framed: false,
                gave_up: true,
            };
        }

        let mut messages = Vec::new();
        let mut consumed = 0usize;
        let mut cursor = 0usize;
        let mut framed = false;
        // 재동기화로 실제로 버린 바이트.
        let mut discarded = 0usize;
        // 아직 이어짐이 확인되지 않은 프레임이 삼킨 바이트.
        let mut unverified = 0usize;
        // 앞 프레임이 끝난 위치. 다음 헤더가 여기서 시작하면 프레임이 이어진 것이다.
        // 직전 호출이 경계에서 끝났다면 이번 버퍼의 0번이 바로 그 경계다.
        let mut last_frame_end = self.ends_on_frame_boundary.then_some(0usize);
        // 이어지는 프레임을 봤는가 (포기 판정용).
        let mut corroborated = false;

        while data.len() - cursor >= PACKET_HEADER_SIZE {
            let rest = &data[cursor..];

            let header = match TdsParser::parse_header(rest) {
                // length < 8이면 전진할 수 없다. 이 검사가 없으면 무한 루프가 된다.
                // 규격을 넘는 길이는 헤더로 인정하지 않는다.
                Ok(h)
                    if (PACKET_HEADER_SIZE..=MAX_PACKET_LENGTH).contains(&(h.length as usize)) =>
                {
                    h
                }
                _ => {
                    // 유효한 헤더가 아니다: 조립 중이던 메시지를 버리고 1바이트 재동기화.
                    self.partial = None;
                    cursor += 1;
                    consumed = cursor;
                    discarded += 1;
                    continue;
                }
            };

            let length = header.length as usize;
            if rest.len() < length {
                // 몸통이 덜 왔다. 다음 세그먼트를 기다린다.
                //
                // 여기서 `framed`를 세우면 안 된다. 무작위 바이트도 ~186바이트마다
                // 한 번은 유효한 헤더로 파싱되므로, 검증되지 않은 헤더 하나로
                // 스트림을 '동기화됨'으로 승격시키면 뒤늦게 도착한 앞 세그먼트를
                // 재전송으로 오인해 버리게 된다.
                break;
            }
            let packet = &rest[..length];

            // 프레임 경계가 이어지는지 본다. 앞 패킷이 끝난 바로 그 자리에서
            // 또 유효한 헤더가 나왔다면 우연일 확률이 급격히 낮아진다.
            // 포기 판정은 이 '연쇄' 신호로만 초기화한다 — 단발 헤더로 초기화하면
            // 암호화 트래픽처럼 우연한 헤더가 계속 나오는 플로우를 영영 못 걸러낸다.
            if last_frame_end == Some(cursor) {
                corroborated = true;
            } else {
                // 이어짐이 확인되지 않은 프레임이다. 우연히 헤더처럼 보인
                // 바이트가 통째로 삼킨 것일 수 있으므로 포기 예산에 청구한다.
                unverified += length;
            }

            // 완전한 패킷을 하나 처리했다. 요청이 아니어도(PreLogin/LOGIN7 등)
            // 유효한 TDS 프레임을 인식한 것은 맞으므로, 호출자가 여기까지의
            // 진행을 소비해도 된다.
            framed = true;

            // 요청이 아닌 패킷(PreLogin/LOGIN7 등)도 위에서 이미 인식으로 셌다.
            if !matches!(header.packet_type, PacketType::SqlBatch | PacketType::Rpc) {
                self.partial = None;
                cursor += length;
                consumed = cursor;
                last_frame_end = Some(cursor);
                continue;
            }

            let is_last = header.is_end_of_message();

            // 흔한 경우: 한 패킷으로 끝나는 메시지. 복사 없이 바로 처리한다.
            if is_last && self.partial.is_none() {
                let body = payload_after_all_headers(&packet[PACKET_HEADER_SIZE..]);
                match TdsParser::decode_body(header.packet_type, body) {
                    Ok(sql) => messages.push(DecodedPacket {
                        sql,
                        raw: Cow::Borrowed(packet),
                    }),
                    Err(e) => trace!("패킷 디코딩 실패({length}바이트): {e}"),
                }
                cursor += length;
                consumed = cursor;
                last_frame_end = Some(cursor);
                continue;
            }

            self.absorb(header.packet_type, packet);
            cursor += length;
            last_frame_end = Some(cursor);
            // 바이트를 이 조립기가 흡수했으므로 버퍼에서 지워도 된다.
            consumed = cursor;

            if is_last {
                if let Some(msg) = self.partial.take() {
                    match TdsParser::decode_body(msg.packet_type, &msg.body) {
                        Ok(sql) => messages.push(DecodedPacket {
                            sql,
                            raw: Cow::Owned(msg.raw),
                        }),
                        Err(e) => trace!("멀티패킷 메시지 디코딩 실패: {e}"),
                    }
                }
            } else if self.partial.as_ref().is_some_and(|m| {
                // `raw`도 함께 본다. 본문이 빈 패킷(헤더만 있는 8바이트 조각)이
                // 계속 오면 `body`는 0인 채로 `raw`만 회선 속도로 자란다.
                m.body.len() > MAX_MESSAGE_BYTES || m.raw.len() > MAX_MESSAGE_BYTES
            }) {
                trace!("메시지가 {MAX_MESSAGE_BYTES}바이트를 넘어 폐기");
                self.partial = None;
            }
        }

        // 스캔이 프레임 경계에서 끝났는지 기억해 다음 호출의 연쇄 판정에 쓴다.
        // 프레임을 하나도 못 찾았으면 경계도 없다.
        self.ends_on_frame_boundary = framed && last_frame_end == Some(cursor);
        self.note_scan(corroborated, discarded + unverified);
        if self.gave_up {
            consumed = data.len();
        }

        StreamScan {
            messages,
            consumed,
            framed,
            gave_up: self.gave_up,
        }
    }

    /// 여러 패킷에 걸친 메시지에 패킷 하나를 이어붙인다.
    fn absorb(&mut self, packet_type: PacketType, packet: &[u8]) {
        let msg = self
            .partial
            .get_or_insert_with(|| PartialMessage::new(packet_type));
        // 메시지 도중에 종류가 바뀌면 앞의 것은 버린다.
        if msg.packet_type != packet_type {
            *msg = PartialMessage::new(packet_type);
        }
        let payload = &packet[PACKET_HEADER_SIZE..];
        // ALL_HEADERS는 메시지의 첫 패킷에만 붙는다.
        let payload = if msg.body.is_empty() {
            payload_after_all_headers(payload)
        } else {
            payload
        };
        msg.body.extend_from_slice(payload);
        msg.raw.extend_from_slice(packet);
    }

    /// 이번 스캔 결과를 반영해 "이 플로우는 TDS가 아니다" 판단을 갱신한다.
    ///
    /// `corroborated`는 '프레임이 이어졌다'는 뜻이다. 단발 헤더로는 초기화하지
    /// 않는다 — 무작위 바이트도 유효한 헤더처럼 보이는 일이 잦기 때문이다.
    /// 반대로 `discarded`가 0이면(= 유효 헤더를 보고 몸통을 기다리는 중이면)
    /// 아무것도 누적되지 않으므로 정상 플로우는 절대 포기되지 않는다.
    fn note_scan(&mut self, corroborated: bool, charged: usize) {
        if corroborated {
            self.unrecognized_bytes = 0;
            return;
        }
        self.unrecognized_bytes = self.unrecognized_bytes.saturating_add(charged);
        if self.unrecognized_bytes > GIVE_UP_AFTER_BYTES {
            trace!("TDS 프레임을 찾지 못해 이 플로우를 포기한다");
            self.gave_up = true;
        }
    }
}

/// TDS 요청 패킷 파서.
pub struct TdsParser;

impl TdsParser {
    /// 완결된 버퍼 하나를 한 번에 훑는다.
    ///
    /// 조립 상태를 남기지 않으므로 **완전한 버퍼**에만 쓴다. 스트리밍 입력은
    /// [`TdsAssembler`]를 플로우별로 유지해야 한다.
    #[must_use]
    pub fn decode_stream(data: &[u8]) -> StreamScan<'_> {
        TdsAssembler::new().feed(data)
    }

    /// 8바이트 TDS 헤더를 파싱한다.
    ///
    /// # Errors
    /// 버퍼가 8바이트 미만이거나 타입/상태 바이트가 유효하지 않으면 실패한다.
    pub fn parse_header(data: &[u8]) -> Result<PacketHeader, TdsError> {
        if data.len() < PACKET_HEADER_SIZE {
            return Err(TdsError::Truncated {
                need: PACKET_HEADER_SIZE,
                have: data.len(),
            });
        }
        let mut buf = &data[..PACKET_HEADER_SIZE];
        PacketHeader::decode(&mut buf).map_err(|_| TdsError::BadHeader)
    }

    /// 완전한 요청 패킷 하나에서 SQL 텍스트를 뽑는다.
    ///
    /// 단일 패킷 메시지용 편의 함수다. 스트림 처리는 [`Self::decode_stream`]이 한다.
    ///
    /// # Errors
    /// 헤더가 잘못됐거나, 요청 패킷이 아니거나, 읽을 수 있는 SQL을 못 얻으면 실패한다.
    pub fn decode_packet(packet: &[u8]) -> Result<String, TdsError> {
        let header = Self::parse_header(packet)?;
        let length = header.length as usize;
        if length < PACKET_HEADER_SIZE {
            return Err(TdsError::BadLength(header.length));
        }
        // 헤더가 주장하는 길이를 넘어서 읽지 않는다.
        let end = length.min(packet.len());
        let body = payload_after_all_headers(&packet[PACKET_HEADER_SIZE..end]);
        Self::decode_body(header.packet_type, body)
    }

    /// `ALL_HEADERS가` 제거된 메시지 본문을 디코딩한다.
    fn decode_body(packet_type: PacketType, body: &[u8]) -> Result<String, TdsError> {
        match packet_type {
            PacketType::SqlBatch => decode_sql_batch(body),
            PacketType::Rpc => decode_rpc(&mut Cursor::new(body)),
            other => Err(TdsError::NotARequest(other)),
        }
    }
}

/// SQLBatch/RPC 앞에 붙는 `ALL_HEADERS` 블록을 건너뛴다 (TDS 7.2+).
///
/// 블록이 없거나 값이 비상식적이면 입력을 그대로 돌려준다. 이 로직이 예전에는
/// 세 곳에 복사돼 있었다.
fn payload_after_all_headers(payload: &[u8]) -> &[u8] {
    let cur = Cursor::new(payload);
    let Ok(total) = cur.peek_u32_le() else {
        return payload;
    };
    if (ALL_HEADERS_MIN..=ALL_HEADERS_MAX).contains(&total) && payload.len() >= total as usize {
        &payload[total as usize..]
    } else {
        payload
    }
}

/// `SQLBatch` 본문은 UTF-16LE로 인코딩된 SQL 텍스트 그 자체다.
fn decode_sql_batch(body: &[u8]) -> Result<String, TdsError> {
    // UTF-16은 2바이트 단위이므로 홀수 꼬리는 버린다.
    let even = body.len() - body.len() % 2;
    if even == 0 {
        return Err(TdsError::NotReadableText);
    }
    validate_text(UTF_16LE.decode(&body[..even]).0.into_owned())
}

/// RPC 요청에서 SQL과 파라미터를 뽑는다 (`sp_executesql` 패턴 지원).
fn decode_rpc(cur: &mut Cursor<'_>) -> Result<String, TdsError> {
    // ProcID(0xFFFF 마커 + ID) 또는 ProcName(US_VARCHAR).
    let marker = cur.u16_le()?;
    if marker == 0xFFFF {
        let proc_id = cur.u16_le()?; // 0x000A == sp_executesql
        trace!("RPC ProcID: {proc_id:#06x}");
    } else {
        // 마커가 아니었다면 그 2바이트가 곧 이름 길이(문자 수)다.
        // 로그를 켜지 않았다면 이름을 문자열로 만들 이유가 없다.
        if log::log_enabled!(log::Level::Trace) {
            trace!("RPC ProcName: {}", cur.utf16le(marker as usize)?);
        } else {
            cur.skip(marker as usize * 2)?;
        }
    }

    cur.skip(2)?; // OptionFlags

    let mut statement: Option<String> = None;
    let mut params: Vec<String> = Vec::new();

    while cur.remaining() > 0 {
        match decode_rpc_parameter(cur) {
            Ok(Some(param)) => {
                if param.is_statement && statement.is_none() {
                    statement = Some(param.value);
                } else {
                    params.push(format!("{}={}", param.name, param.value));
                }
            }
            Ok(None) => {} // NULL이거나 표시할 것이 없는 값
            Err(TdsError::Truncated { have: 0, .. }) => break, // 정상 종료
            Err(e) => {
                // 실패 원인을 삼키지 않는다. 여기서 멈추면 이후 파라미터는
                // 커서가 어긋났을 수 있으므로 신뢰할 수 없다.
                trace!("RPC 파라미터 파싱 중단: {e}");
                break;
            }
        }
    }

    // 원본에는 `a && b || c || d` 우선순위 버그가 있었다. `&&`가 `||`보다 강하게
    // 결합해 파라미터가 없는 INSERT 등에 " -- " 꼬리가 붙었다. 이제는 문장을
    // 선두 키워드로 추측하지 않고 `@stmt` 파라미터 이름으로 식별한다.
    match (statement, params.is_empty()) {
        (Some(sql), true) => Ok(sql),
        (Some(sql), false) => Ok(format!("{sql} -- {}", params.join(", "))),
        (None, false) => Ok(params.join(" | ")),
        (None, true) => Err(TdsError::NoRpcParameters),
    }
}

/// 렌더링된 RPC 파라미터 하나.
struct RpcParam {
    name: String,
    value: String,
    is_statement: bool,
}

/// RPC 파라미터 하나를 읽는다. 값이 NULL이거나 표시할 것이 없으면 `Ok(None)`.
fn decode_rpc_parameter(cur: &mut Cursor<'_>) -> Result<Option<RpcParam>, TdsError> {
    let name_units = cur.u8()? as usize;
    let name = cur.utf16le(name_units)?;
    cur.skip(1)?; // StatusFlags

    let type_id = cur.u8()?;
    let kind = read_type_info(cur, type_id)?;
    let Some(bytes) = read_value(cur, kind)? else {
        return Ok(None); // NULL
    };

    // 이름 처리는 타입 분기 바깥에서 한 번만 한다. 예전에는 NVARCHAR 분기만
    // `@stmt`를 인식해서, VARCHAR로 온 문장은 `@stmt=SELECT ...` 꼴이 되어
    // 뒤의 선두 키워드 검사에 걸리지 않았다.
    let is_statement = name == "@stmt" || name == "@statement";
    Ok(render_value(type_id, &bytes)
        .map(|value| RpcParam {
            name,
            value,
            is_statement,
        })
        .filter(|p| !p.value.is_empty()))
}

/// `TYPE_INFO를` 읽어 값 길이를 어떻게 해석할지 결정한다 (MS-TDS 2.2.5.4/2.2.5.5).
///
/// 모르는 타입에는 [`TdsError::UnsupportedType`]을 돌려준다. 예전처럼 0바이트를
/// 건너뛰고 넘어가면 이후 파라미터 전부가 어긋난 채로 조용히 파싱된다.
fn read_type_info(cur: &mut Cursor<'_>, type_id: u8) -> Result<LengthKind, TdsError> {
    Ok(match type_id {
        // --- 고정 길이 (TYPE_INFO 없음, 길이 접두사 없음) ---
        0x1F => LengthKind::Fixed(0),                      // NULL
        0x30 | 0x32 => LengthKind::Fixed(1),               // INT1, BIT
        0x34 => LengthKind::Fixed(2),                      // INT2
        0x38 | 0x3A | 0x3B | 0x7A => LengthKind::Fixed(4), // INT4, DATETIM4, FLT4, MONEY4
        0x3C | 0x3D | 0x3E | 0x7F => LengthKind::Fixed(8), // MONEY, DATETIME, FLT8, INT8

        // --- BYTELEN 계열: TYPE_INFO 없음 ---
        0x28 => LengthKind::Byte, // DATEN

        // --- BYTELEN 계열: maxLength(1) ---
        0x24 | 0x26 | 0x68 | 0x6D | 0x6E | 0x6F => {
            cur.skip(1)?; // GUID, INTN, BITN, FLTN, MONEYN, DATETIMN
            LengthKind::Byte
        }
        // --- BYTELEN 계열: scale(1) ---
        0x29..=0x2B => {
            cur.skip(1)?; // TIMEN, DATETIME2N, DATETIMEOFFSETN
            LengthKind::Byte
        }
        // --- BYTELEN 계열: maxLength(1) + precision(1) + scale(1) ---
        0x6A | 0x6C => {
            cur.skip(3)?; // DECIMALN, NUMERICN
            LengthKind::Byte
        }

        // --- USHORTLEN 계열: maxLength(2) [+ collation(5)] ---
        // maxLength가 0xFFFF면 MAX 타입이라 값이 PLP로 온다.
        0xA5 | 0xAD => short_or_plp(cur, false)?, // BIGVARBINARY, BIGBINARY
        0xA7 | 0xAF | 0xE7 | 0xEF => short_or_plp(cur, true)?, // (N)VARCHAR, (N)CHAR

        other => return Err(TdsError::UnsupportedType(other)),
    })
}

/// `maxLength`(2바이트)와 선택적 collation(5바이트)을 읽고 길이 종류를 정한다.
fn short_or_plp(cur: &mut Cursor<'_>, has_collation: bool) -> Result<LengthKind, TdsError> {
    let max_length = cur.u16_le()?;
    if has_collation {
        cur.skip(5)?;
    }
    Ok(if max_length == 0xFFFF {
        LengthKind::PartiallyLengthPrefixed
    } else {
        LengthKind::Short
    })
}

/// 값 바이트를 읽는다. NULL이면 `Ok(None)`.
fn read_value<'a>(
    cur: &mut Cursor<'a>,
    kind: LengthKind,
) -> Result<Option<Cow<'a, [u8]>>, TdsError> {
    Ok(match kind {
        LengthKind::Fixed(0) => None,
        LengthKind::Fixed(n) => Some(Cow::Borrowed(cur.take(n)?)),
        LengthKind::Byte => {
            let len = cur.u8()?;
            if len == 0xFF {
                None
            } else {
                Some(Cow::Borrowed(cur.take(len as usize)?))
            }
        }
        LengthKind::Short => {
            let len = cur.u16_le()?;
            if len == 0xFFFF {
                None
            } else {
                Some(Cow::Borrowed(cur.take(len as usize)?))
            }
        }
        LengthKind::PartiallyLengthPrefixed => read_plp(cur)?.map(Cow::Owned),
    })
}

/// PLP(Partially Length-prefixed) 값을 읽는다.
///
/// `varchar(max)` / `nvarchar(max)` 값이 이 형식으로 온다. 드라이버는 4000자를
/// 넘는 `sp_executesql @stmt`에 이걸 쓰므로, 이 경로가 막히면 긴 쿼리가 통째로
/// 사라진다. 예전 코드는 총길이 앞 2바이트만 보고 NULL로 오인했다.
fn read_plp(cur: &mut Cursor<'_>) -> Result<Option<Vec<u8>>, TdsError> {
    let total = cur.u64_le()?;
    if total == PLP_NULL {
        return Ok(None);
    }

    let mut out = match usize::try_from(total) {
        Ok(n) if total != PLP_UNKNOWN_LENGTH && n <= MAX_PLP_BYTES => {
            // 주장하는 길이를 그대로 예약하지 않는다. 실제 청크가 오는 만큼 자란다.
            Vec::with_capacity(n.min(PLP_RESERVE_LIMIT))
        }
        Ok(n) if total != PLP_UNKNOWN_LENGTH => return Err(TdsError::ValueTooLarge(n)),
        _ => Vec::new(), // 길이를 모르는 경우
    };

    // 청크: ULONG 길이 + 데이터, 길이 0이 종료 표식.
    loop {
        let chunk_len = cur.u32_le()? as usize;
        if chunk_len == 0 {
            break;
        }
        // 32비트 타깃에서 `chunk_len`(최대 4 GiB-1)을 그냥 더하면 넘친다.
        let total_so_far = out.len().saturating_add(chunk_len);
        if total_so_far > MAX_PLP_BYTES {
            return Err(TdsError::ValueTooLarge(total_so_far));
        }
        out.extend_from_slice(cur.take(chunk_len)?);
    }
    Ok(Some(out))
}

/// 값 바이트를 표시용 문자열로 만든다. 표시할 것이 없으면 `None`.
fn render_value(type_id: u8, bytes: &[u8]) -> Option<String> {
    let mut text = match type_id {
        // 유니코드 문자열
        0xE7 | 0xEF => {
            let even = bytes.len() - bytes.len() % 2;
            UTF_16LE.decode(&bytes[..even]).0.into_owned()
        }
        // 코드페이지 문자열. UTF-8로 읽히면 그대로, 아니면 CP949(EUC-KR)로 시도한다.
        0xA7 | 0xAF => std::str::from_utf8(bytes)
            .map_or_else(|_| EUC_KR.decode(bytes).0.into_owned(), ToString::to_string),
        // 정수 계열 (INT1/INT2/INT4/INT8/INTN/BIT/BITN)
        0x30 | 0x32 | 0x34 | 0x38 | 0x7F | 0x26 | 0x68 => render_int(bytes)?,
        // 부동소수 (FLT4/FLT8/FLTN)
        0x3B | 0x3E | 0x6D => render_float(bytes)?,
        // 그 밖(날짜, 소수, 바이너리 등)은 hex로 보여준다.
        _ => {
            if bytes.is_empty() {
                return None;
            }
            let mut hex = String::with_capacity(2 + bytes.len() * 2);
            hex.push_str("0x");
            for byte in bytes {
                use fmt::Write as _;
                let _ = write!(hex, "{byte:02x}");
            }
            hex
        }
    };

    // `validate_text`와 같은 제자리 다듬기. nvarchar(max) @stmt를 한 번 더
    // 복사하지 않기 위해서다.
    trim_in_place(&mut text);
    (!text.is_empty()).then_some(text)
}

/// 앞뒤 공백을 새 할당 없이 제자리에서 잘라낸다.
///
/// 뒤를 먼저 자르고 나서 앞을 계산해야 한다. 전부 공백인 문자열에서 두 값을
/// 따로 구하면 `start > end`가 되어 슬라이싱이 패닉한다.
fn trim_in_place(text: &mut String) {
    text.truncate(text.trim_end().len());
    let start = text.len() - text.trim_start().len();
    text.drain(..start);
}

fn render_int(bytes: &[u8]) -> Option<String> {
    let value = match bytes.len() {
        // TDS의 1바이트 정수(TINYINT/BIT)는 부호가 없다.
        1 => i64::from(bytes[0]),
        2 => i64::from(i16::from_le_bytes([bytes[0], bytes[1]])),
        4 => i64::from(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        8 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(bytes);
            i64::from_le_bytes(b)
        }
        _ => return None,
    };
    Some(value.to_string())
}

fn render_float(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => {
            let mut b = [0u8; 4];
            b.copy_from_slice(bytes);
            Some(f32::from_le_bytes(b).to_string())
        }
        8 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(bytes);
            Some(f64::from_le_bytes(b).to_string())
        }
        _ => None,
    }
}

/// 디코딩 결과가 사람이 읽을 SQL로 보이는지 검사하고, 통과하면 다듬어 돌려준다.
///
/// 다듬기를 여기서 끝내므로 호출자가 다시 `trim`할 필요가 없다.
fn validate_text(mut text: String) -> Result<String, TdsError> {
    // 검사 전에 다듬는다. 예전에는 `start`와 `end`를 따로 구해 `&text[start..end]`로
    // 잘랐는데, 전부 공백인 입력에서는 `start > end`가 되어 패닉했다.
    // (UTF-16LE로 U+200A 하나만 담은 SQLBatch 패킷이면 재현된다.)
    trim_in_place(&mut text);

    if text.len() < MIN_TEXT_LEN {
        return Err(TdsError::NotReadableText);
    }
    let total = text.chars().count();
    let printable = text
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .count();
    // 제어 문자가 절반을 넘으면 텍스트가 아니라고 본다.
    if printable * 2 < total {
        return Err(TdsError::NotReadableText);
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 테스트용 TDS 패킷 조립기.
    pub(super) struct PacketBuilder {
        body: Vec<u8>,
    }

    impl PacketBuilder {
        pub(super) fn new() -> Self {
            Self { body: Vec::new() }
        }

        /// 트랜잭션 서술자 하나를 담은 최소 `ALL_HEADERS` 블록 (총 22바이트).
        pub(super) fn all_headers(mut self) -> Self {
            self.body.extend_from_slice(&22u32.to_le_bytes()); // TotalLength
            self.body.extend_from_slice(&18u32.to_le_bytes()); // HeaderLength
            self.body.extend_from_slice(&2u16.to_le_bytes()); // Type = txn descriptor
            self.body.extend_from_slice(&[0u8; 8]); // TransactionDescriptor
            self.body.extend_from_slice(&1u32.to_le_bytes()); // OutstandingRequestCount
            self
        }

        pub(super) fn utf16(mut self, s: &str) -> Self {
            for unit in s.encode_utf16() {
                self.body.extend_from_slice(&unit.to_le_bytes());
            }
            self
        }

        fn bytes(mut self, b: &[u8]) -> Self {
            self.body.extend_from_slice(b);
            self
        }

        pub(super) fn build(self, packet_type: u8) -> Vec<u8> {
            self.build_with_status(packet_type, 0x01) // END_OF_MESSAGE
        }

        fn build_with_status(self, packet_type: u8, status: u8) -> Vec<u8> {
            let total = u16::try_from(PACKET_HEADER_SIZE + self.body.len())
                .expect("테스트 패킷은 64KiB 미만이다");
            let mut out = Vec::with_capacity(total as usize);
            out.push(packet_type);
            out.push(status);
            out.extend_from_slice(&total.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes()); // spid
            out.push(1); // packet id
            out.push(0); // window
            out.extend_from_slice(&self.body);
            out
        }
    }

    fn utf16_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn sql_batch(sql: &str) -> Vec<u8> {
        PacketBuilder::new().all_headers().utf16(sql).build(0x01)
    }

    // ---------------- SQLBatch ----------------

    #[test]
    fn decodes_sql_batch() {
        let sql = "SELECT * FROM dbo.TB_Users WHERE id = 1";
        assert_eq!(TdsParser::decode_packet(&sql_batch(sql)).unwrap(), sql);
    }

    #[test]
    fn decodes_korean_sql_batch() {
        let sql = "SELECT * FROM DentWeb.dbo.TB_진료내역";
        assert_eq!(TdsParser::decode_packet(&sql_batch(sql)).unwrap(), sql);
    }

    #[test]
    fn surrounding_whitespace_is_trimmed_once_by_the_parser() {
        let packet = sql_batch("   SELECT 1 FROM dbo.TB_A  \r\n");
        assert_eq!(
            TdsParser::decode_packet(&packet).unwrap(),
            "SELECT 1 FROM dbo.TB_A"
        );
    }

    #[test]
    fn rejects_binary_noise_as_text() {
        let packet = PacketBuilder::new()
            .all_headers()
            .bytes(&[0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00])
            .build(0x01);
        assert_eq!(
            TdsParser::decode_packet(&packet),
            Err(TdsError::NotReadableText)
        );
    }

    // ---------------- 프레이밍 ----------------

    #[test]
    fn frames_back_to_back_packets() {
        let mut stream = sql_batch("SELECT 1 FROM dbo.TB_A");
        stream.extend_from_slice(&sql_batch("UPDATE dbo.TB_B SET x = 2"));

        let scan = TdsParser::decode_stream(&stream);
        let (packets, consumed) = (scan.messages, scan.consumed);
        assert_eq!(packets.len(), 2);
        assert_eq!(consumed, stream.len());
        assert_eq!(packets[0].sql, "SELECT 1 FROM dbo.TB_A");
        assert_eq!(packets[1].sql, "UPDATE dbo.TB_B SET x = 2");
    }

    #[test]
    fn incomplete_packet_is_not_consumed() {
        let packet = sql_batch("SELECT * FROM dbo.TB_Users");
        let scan = TdsParser::decode_stream(&packet[..packet.len() - 6]);
        let (packets, consumed) = (scan.messages, scan.consumed);
        assert!(packets.is_empty());
        assert_eq!(consumed, 0, "미완성 패킷은 소비하면 안 된다");

        let scan = TdsParser::decode_stream(&packet);
        let (packets, consumed) = (scan.messages, scan.consumed);
        assert_eq!(packets.len(), 1);
        assert_eq!(consumed, packet.len());
    }

    /// length 필드가 8 미만이면 전진량이 0이 되어 원본 코드가 무한 루프에 빠졌다.
    #[test]
    fn zero_length_header_does_not_hang() {
        let malformed = [0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
        let scan = TdsParser::decode_stream(&malformed);
        let (packets, consumed) = (scan.messages, scan.consumed);
        assert!(packets.is_empty());
        assert!(consumed > 0, "재동기화를 위해 반드시 전진해야 한다");
    }

    #[test]
    fn resyncs_past_garbage() {
        let mut stream = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x99, 0x88];
        stream.extend_from_slice(&sql_batch("SELECT * FROM dbo.TB_Users"));

        let scan = TdsParser::decode_stream(&stream);
        let (packets, consumed) = (scan.messages, scan.consumed);
        assert_eq!(packets.len(), 1, "쓰레기 뒤의 패킷을 찾아야 한다");
        assert_eq!(consumed, stream.len());
    }

    #[test]
    fn skips_non_request_packets() {
        let response = PacketBuilder::new().bytes(&[0u8; 16]).build(0x04);
        let mut stream = response;
        stream.extend_from_slice(&sql_batch("SELECT 1 FROM dbo.TB_A"));

        let scan = TdsParser::decode_stream(&stream);
        let (packets, consumed) = (scan.messages, scan.consumed);
        assert_eq!(packets.len(), 1);
        assert_eq!(consumed, stream.len());
    }

    #[test]
    fn single_packet_message_borrows_its_raw_bytes() {
        let packet = sql_batch("SELECT * FROM dbo.TB_Users");
        let packets = TdsParser::decode_stream(&packet).messages;
        assert_eq!(packets[0].raw.as_ref(), packet.as_slice());
        assert!(
            matches!(packets[0].raw, Cow::Borrowed(_)),
            "단일 패킷은 복사 없이 빌려야 한다"
        );
    }

    // ---------------- 멀티패킷 메시지 ----------------

    /// 협상된 패킷 크기를 넘는 쿼리는 여러 패킷으로 쪼개져 마지막에만 EOM이 붙는다.
    /// 패킷마다 따로 디코딩하면 하나의 긴 쿼리가 잘린 조각 두 개로 기록된다.
    #[test]
    fn reassembles_a_message_split_across_packets() {
        let sql = format!("SELECT '{}' FROM dbo.TB_Users", "x".repeat(3000));
        let half = sql.len() / 2;

        // 첫 패킷: ALL_HEADERS + 앞 절반, EOM 없음
        let first = PacketBuilder::new()
            .all_headers()
            .utf16(&sql[..half])
            .build_with_status(0x01, 0x00);
        // 이어지는 패킷: ALL_HEADERS 없이 나머지, EOM
        let second = PacketBuilder::new()
            .utf16(&sql[half..])
            .build_with_status(0x01, 0x01);

        let mut stream = first;
        stream.extend_from_slice(&second);

        let scan = TdsParser::decode_stream(&stream);
        let (packets, consumed) = (scan.messages, scan.consumed);
        assert_eq!(packets.len(), 1, "논리 메시지 하나여야 한다");
        assert_eq!(packets[0].sql, sql);
        assert_eq!(consumed, stream.len());
        assert!(
            matches!(packets[0].raw, Cow::Owned(_)),
            "멀티패킷은 이어붙인 사본을 소유한다"
        );
    }

    /// 조립기가 흡수한 패킷은 곧바로 소비 가능하다. 상태가 조립기에 남으므로
    /// 재조립 버퍼가 메시지 전체를 붙들고 있을 필요가 없다.
    #[test]
    fn an_assembler_absorbs_packets_as_they_arrive() {
        let sql = format!("SELECT '{}' FROM dbo.TB_Users", "y".repeat(3000));
        let half = sql.len() / 2;
        let first = PacketBuilder::new()
            .all_headers()
            .utf16(&sql[..half])
            .build_with_status(0x01, 0x00);
        let second = PacketBuilder::new()
            .utf16(&sql[half..])
            .build_with_status(0x01, 0x01);

        let mut assembler = TdsAssembler::new();

        let scan = assembler.feed(&first);
        assert!(scan.messages.is_empty(), "아직 메시지가 완결되지 않았다");
        assert_eq!(scan.consumed, first.len(), "흡수한 바이트는 소비 가능하다");
        assert!(scan.framed);

        let scan = assembler.feed(&second);
        assert_eq!(scan.messages.len(), 1);
        assert_eq!(scan.messages[0].sql, sql);
        assert_eq!(scan.consumed, second.len());
    }

    /// 미완성 패킷(헤더가 주장하는 길이에 못 미치는 꼬리)은 소비하지 않는다.
    #[test]
    fn a_partial_packet_tail_is_not_consumed() {
        let packet = sql_batch("SELECT * FROM dbo.TB_Users");
        let mut assembler = TdsAssembler::new();

        let cut = packet.len() - 6;
        let scan = assembler.feed(&packet[..cut]);
        assert!(scan.messages.is_empty());
        assert_eq!(scan.consumed, 0, "패킷 경계 전까지만 소비한다");

        let scan = assembler.feed(&packet);
        assert_eq!(scan.messages.len(), 1);
        assert_eq!(scan.consumed, packet.len());
    }

    /// 각 바이트는 정확히 한 번만 복사되어야 한다. 예전에는 메시지가 끝날 때까지
    /// 앞부분을 소비하지 못해, 세그먼트가 올 때마다 지금까지의 패킷을 전부 다시
    /// 파싱하고 다시 복사했다 — 메시지 크기의 제곱.
    #[test]
    fn a_long_message_is_absorbed_in_linear_work() {
        let sql = format!("SELECT '{}' FROM dbo.TB_Users", "z".repeat(40_000));
        let chunk_chars = 1000;
        let chars: Vec<char> = sql.chars().collect();
        let chunks: Vec<String> = chars
            .chunks(chunk_chars)
            .map(|c| c.iter().collect())
            .collect();

        let mut assembler = TdsAssembler::new();
        let mut total_consumed = 0usize;
        let mut total_fed = 0usize;
        let mut decoded = None;

        for (i, chunk) in chunks.iter().enumerate() {
            let last = i == chunks.len() - 1;
            let status = u8::from(last);
            let packet = if i == 0 {
                PacketBuilder::new()
                    .all_headers()
                    .utf16(chunk)
                    .build_with_status(0x01, status)
            } else {
                PacketBuilder::new()
                    .utf16(chunk)
                    .build_with_status(0x01, status)
            };

            total_fed += packet.len();
            let scan = assembler.feed(&packet);
            total_consumed += scan.consumed;
            if let Some(m) = scan.messages.into_iter().next() {
                decoded = Some(m.sql);
            }
        }

        assert_eq!(decoded.as_deref(), Some(sql.as_str()));
        assert_eq!(
            total_consumed, total_fed,
            "먹인 바이트는 전부 그 자리에서 소비되어야 한다 (재파싱 없음)"
        );
    }

    // ---------------- RPC ----------------

    /// `sp_executesql` 헤더 (`ProcID` 마커 + ID + `OptionFlags`).
    fn rpc_head() -> PacketBuilder {
        PacketBuilder::new()
            .all_headers()
            .bytes(&0xFFFFu16.to_le_bytes())
            .bytes(&0x000Au16.to_le_bytes())
            .bytes(&0u16.to_le_bytes())
    }

    fn param_head(b: PacketBuilder, name: &str) -> PacketBuilder {
        b.bytes(&[u8::try_from(name.chars().count()).unwrap()])
            .utf16(name)
            .bytes(&[0]) // StatusFlags
    }

    /// NVARCHAR(n) 파라미터: maxLength(2) + collation(5) + USHORT 길이 + 데이터.
    fn nvarchar(b: PacketBuilder, name: &str, value: &str) -> PacketBuilder {
        let data = utf16_bytes(value);
        param_head(b, name)
            .bytes(&[0xE7])
            .bytes(&8000u16.to_le_bytes())
            .bytes(&[0u8; 5])
            .bytes(&u16::try_from(data.len()).unwrap().to_le_bytes())
            .bytes(&data)
    }

    /// INTN 파라미터: maxLength(1) + BYTELEN 길이 + 데이터.
    /// 예전 코드는 `TYPE_INFO를` 0바이트로 보고 길이를 u16으로 읽어 스트림을 어긋냈다.
    fn intn(b: PacketBuilder, name: &str, value: i32) -> PacketBuilder {
        param_head(b, name)
            .bytes(&[0x26])
            .bytes(&[4]) // maxLength
            .bytes(&[4]) // 데이터 길이
            .bytes(&value.to_le_bytes())
    }

    /// NVARCHAR(MAX) 파라미터: maxLength 0xFFFF + PLP 인코딩 값.
    fn nvarchar_max(b: PacketBuilder, name: &str, value: &str) -> PacketBuilder {
        let data = utf16_bytes(value);
        let mut b = param_head(b, name)
            .bytes(&[0xE7])
            .bytes(&0xFFFFu16.to_le_bytes())
            .bytes(&[0u8; 5])
            .bytes(&(data.len() as u64).to_le_bytes());
        // 두 청크로 쪼개 청크 처리도 함께 검증한다.
        let split = (data.len() / 2) & !1;
        for chunk in [&data[..split], &data[split..]] {
            b = b
                .bytes(&u32::try_from(chunk.len()).unwrap().to_le_bytes())
                .bytes(chunk);
        }
        b.bytes(&0u32.to_le_bytes()) // 종료 표식
    }

    #[test]
    fn decodes_rpc_sp_executesql() {
        let sql = "SELECT * FROM dbo.TB_Users WHERE id = @id";
        let packet = nvarchar(rpc_head(), "@stmt", sql).build(0x03);
        assert_eq!(TdsParser::decode_packet(&packet).unwrap(), sql);
    }

    /// 원본의 `&&`/`||` 우선순위 버그는 파라미터가 없어도 " -- " 꼬리를 붙였다.
    #[test]
    fn single_statement_rpc_has_no_trailing_separator() {
        let sql = "INSERT INTO dbo.TB_Log VALUES (1)";
        let packet = nvarchar(rpc_head(), "@stmt", sql).build(0x03);
        let decoded = TdsParser::decode_packet(&packet).unwrap();
        assert_eq!(decoded, sql);
        assert!(
            !decoded.contains(" -- "),
            "꼬리가 붙으면 안 된다: {decoded}"
        );
    }

    /// INTN(0x26)은 `TYPE_INFO` 1바이트 + BYTELEN 길이다. 이걸 틀리면 뒤따르는
    /// 파라미터가 전부 어긋나 조용히 사라진다 — .NET `SqlClient의` 기본 int 파라미터다.
    #[test]
    fn decodes_int_parameter_without_desynchronizing_the_stream() {
        let sql = "SELECT * FROM dbo.TB_Users WHERE id = @id AND name = @name";
        let mut b = nvarchar(rpc_head(), "@stmt", sql);
        b = intn(b, "@id", 42);
        b = nvarchar(b, "@name", "kim");

        let decoded = TdsParser::decode_packet(&b.build(0x03)).unwrap();
        assert_eq!(
            decoded,
            format!("{sql} -- @id=42, @name=kim"),
            "INT 뒤의 파라미터까지 온전히 읽혀야 한다"
        );
    }

    /// nvarchar(max)는 PLP로 온다. 드라이버는 4000자를 넘는 @stmt에 이걸 쓴다.
    /// 예전 코드는 총길이 앞 2바이트(0xFFFF)를 NULL로 오인해 쿼리를 통째로 버렸다.
    #[test]
    fn decodes_plp_nvarchar_max_statement() {
        let sql = format!("SELECT '{}' FROM dbo.TB_Users", "z".repeat(5000));
        let packet = nvarchar_max(rpc_head(), "@stmt", &sql).build(0x03);
        assert_eq!(TdsParser::decode_packet(&packet).unwrap(), sql);
    }

    #[test]
    fn null_parameters_are_skipped() {
        let sql = "SELECT * FROM dbo.TB_Users WHERE id = @id";
        let b = nvarchar(rpc_head(), "@stmt", sql);
        // NULL INTN
        let b = param_head(b, "@id")
            .bytes(&[0x26])
            .bytes(&[4])
            .bytes(&[0xFF]);
        assert_eq!(TdsParser::decode_packet(&b.build(0x03)).unwrap(), sql);
    }

    /// `@stmt`가 코드페이지 문자열(VARCHAR)로 와도 문장으로 인식해야 한다.
    /// 예전에는 NVARCHAR 분기만 `@stmt`를 알아서 `@stmt=SELECT ...` 꼴이 됐다.
    #[test]
    fn statement_is_recognized_regardless_of_string_type() {
        let sql = "SELECT * FROM dbo.TB_Users";
        let b = param_head(rpc_head(), "@stmt")
            .bytes(&[0xA7])
            .bytes(&8000u16.to_le_bytes())
            .bytes(&[0u8; 5])
            .bytes(&u16::try_from(sql.len()).unwrap().to_le_bytes())
            .bytes(sql.as_bytes());
        assert_eq!(TdsParser::decode_packet(&b.build(0x03)).unwrap(), sql);
    }

    #[test]
    fn unsupported_type_stops_parsing_instead_of_desynchronizing() {
        let sql = "SELECT * FROM dbo.TB_Users";
        let b = nvarchar(rpc_head(), "@stmt", sql);
        // 0xF1(XML)은 해석하지 않는다.
        let b = param_head(b, "@doc").bytes(&[0xF1]).bytes(&[0u8; 8]);
        // 문장은 살아남고, 어긋난 쓰레기가 붙지 않아야 한다.
        assert_eq!(TdsParser::decode_packet(&b.build(0x03)).unwrap(), sql);
    }

    #[test]
    fn rpc_without_parameters_is_an_error() {
        let packet = rpc_head().build(0x03);
        assert_eq!(
            TdsParser::decode_packet(&packet),
            Err(TdsError::NoRpcParameters)
        );
    }

    // ---------------- 견고성 ----------------

    /// 전부 공백인 `SQLBatch` 본문에서 `start > end`가 되어 슬라이싱이 패닉했다.
    /// 재동기화 경로로도 도달하므로 암호화된 1433 트래픽이 계속 유발할 수 있었다.
    #[test]
    fn whitespace_only_batch_is_rejected_not_panicked() {
        for text in ["  ", "\u{200a}", "\t\r\n", "\u{3000}\u{3000}"] {
            let packet = PacketBuilder::new().all_headers().utf16(text).build(0x01);
            assert_eq!(
                TdsParser::decode_packet(&packet),
                Err(TdsError::NotReadableText),
                "입력 {text:?}"
            );
            // 라이브 캡처 경로도 같은 문자열을 지나간다.
            let scan = TdsParser::decode_stream(&packet);
            assert!(scan.messages.is_empty());
            assert_eq!(scan.consumed, packet.len());
        }
    }

    /// 리뷰 퍼징이 찾아낸 최소 재현 패킷 (본문이 U+200A 하나).
    #[test]
    fn fuzzer_minimal_whitespace_packet_does_not_panic() {
        let packet = [0x01, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x0a, 0x20];
        let scan = TdsParser::decode_stream(&packet);
        assert!(scan.messages.is_empty());
    }

    /// 요청이 아닌 패킷도 유효한 프레임을 인식한 것이다. `framed`를 세지 않으면
    /// 로그인 핸드셰이크 동안 호출자가 진행 상황을 버려 같은 바이트를 계속 재파싱한다.
    #[test]
    fn recognized_non_request_packets_count_as_framed() {
        let prelogin = PacketBuilder::new().bytes(&[0u8; 16]).build(0x12);
        let scan = TdsParser::decode_stream(&prelogin);
        assert!(scan.messages.is_empty());
        assert_eq!(scan.consumed, prelogin.len());
        assert!(scan.framed, "프레임을 인식했으면 framed여야 한다");
    }

    #[test]
    fn garbage_alone_is_not_framed() {
        let scan = TdsParser::decode_stream(&[0xAA; 32]);
        assert!(!scan.framed);
    }

    #[test]
    fn cursor_never_panics_on_truncated_input() {
        let mut b = nvarchar(rpc_head(), "@stmt", "SELECT * FROM dbo.TB_Users");
        b = intn(b, "@id", 7);
        let packet = b.build(0x03);
        for n in 0..packet.len() {
            let _ = TdsParser::decode_stream(&packet[..n]);
            let _ = TdsParser::decode_packet(&packet[..n]);
        }
    }

    #[test]
    fn decode_stream_never_reports_more_than_it_was_given() {
        let inputs = [
            sql_batch("SELECT 1 FROM dbo.TB_A"),
            vec![0x01; 64],
            vec![0xFF; 64],
            nvarchar_max(rpc_head(), "@stmt", "SELECT 1 FROM dbo.TB_A").build(0x03),
        ];
        for input in inputs {
            for n in 0..input.len() {
                let consumed = TdsParser::decode_stream(&input[..n]).consumed;
                assert!(consumed <= n, "consumed({consumed}) > len({n})");
            }
        }
    }
}

#[cfg(test)]
mod round4_tests {
    use super::*;

    /// 본문이 빈 패킷(헤더 8바이트만)이 EOM 없이 계속 오면, `body`는 0인 채로
    /// `raw`만 회선 속도로 자랐다. 상한이 `body`만 보고 있었기 때문이다.
    #[test]
    fn header_only_continuation_packets_cannot_grow_raw_without_bound() {
        // status=0x00 (EOM 아님), length=8 (본문 없음)
        let packet = [0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00];
        let mut assembler = TdsAssembler::new();

        let mut stream = Vec::new();
        for _ in 0..200_000 {
            stream.extend_from_slice(&packet);
        }
        let scan = assembler.feed(&stream);
        assert!(scan.messages.is_empty());
        assert_eq!(scan.consumed, stream.len());
        assert!(
            assembler.retained_bytes() <= MAX_MESSAGE_BYTES,
            "조립 중 원본이 {}바이트까지 자랐다",
            assembler.retained_bytes()
        );
    }

    /// PLP 총길이는 패킷이 주장하는 값이라 신뢰할 수 없다. 그대로 예약하면
    /// `4 MiB`를 주장하고 곧바로 끝내는 파라미터 수천 개가 캡처 스레드를 마비시킨다.
    #[test]
    fn a_lying_plp_length_does_not_preallocate() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(4u64 * 1024 * 1024).to_le_bytes()); // 총길이 주장
        buf.extend_from_slice(&4u32.to_le_bytes()); // 청크 4바이트
        buf.extend_from_slice(b"ABCD");
        buf.extend_from_slice(&0u32.to_le_bytes()); // 종료

        let mut cur = Cursor::new(&buf);
        let value = read_plp(&mut cur).unwrap().expect("NULL이 아니다");
        assert_eq!(value, b"ABCD");
        assert!(
            value.capacity() <= PLP_RESERVE_LIMIT,
            "주장한 길이만큼 미리 잡으면 안 된다: {}",
            value.capacity()
        );
    }
}

#[cfg(test)]
mod round7_tests {
    use super::tests::PacketBuilder;
    use super::*;

    /// 암호화를 협상한 연결은 그 뒤 클라이언트→서버 바이트가 TLS 레코드이고
    /// TDS 헤더는 암호문 안에 있다. 프레임을 영영 못 찾는데 매 패킷 버퍼 전체를
    /// 1바이트씩 다시 훑으면, 그 연결 하나가 캡처 스레드를 계속 갉아먹는다.
    #[test]
    fn a_flow_that_never_frames_is_given_up_on() {
        let mut assembler = TdsAssembler::new();
        // 0x17 = TLS Application Data. 유효한 TDS 패킷 종류가 아니다.
        let tls_record = vec![0x17; 8 * 1024];

        let mut gave_up_after = None;
        for round in 0..1000 {
            let scan = assembler.feed(&tls_record);
            assert!(scan.messages.is_empty());
            if scan.gave_up {
                gave_up_after = Some(round);
                assert_eq!(
                    scan.consumed,
                    tls_record.len(),
                    "포기했으면 붙들지 말고 흘려보내야 한다"
                );
                break;
            }
        }
        assert!(gave_up_after.is_some(), "언젠가는 포기해야 한다");
    }

    /// 반대로 정상 TDS 플로우는 절대 포기하면 안 된다.
    #[test]
    fn a_valid_tds_flow_is_never_given_up_on() {
        let mut assembler = TdsAssembler::new();
        let packet = PacketBuilder::new()
            .all_headers()
            .utf16("SELECT * FROM dbo.TB_Users")
            .build(0x01);

        for _ in 0..1000 {
            let scan = assembler.feed(&packet);
            assert!(!scan.gave_up);
            assert_eq!(scan.messages.len(), 1);
        }
    }

    /// 쓰레기가 조금 섞여도 곧 프레임을 찾으면 포기 카운터가 초기화되어야 한다.
    #[test]
    fn recognizing_a_frame_resets_the_give_up_counter() {
        let mut assembler = TdsAssembler::new();
        let packet = PacketBuilder::new()
            .all_headers()
            .utf16("SELECT 1 FROM dbo.TB_A")
            .build(0x01);

        for _ in 0..200 {
            assembler.feed(&[0xAA; 4096]);
            let scan = assembler.feed(&packet);
            assert!(scan.framed);
            assert!(!scan.gave_up, "정상 프레임이 섞이면 포기하지 않는다");
        }
    }
}

#[cfg(test)]
mod round8_tests {
    use super::tests::PacketBuilder;
    use super::*;

    /// 몸통이 덜 온 패킷도 유효한 프레임 경계를 인식한 것이다. 이를 인식으로
    /// 세지 않으면, 큰 패킷을 기다리는 정상 플로우가 재스캔 누적만으로 "TDS가
    /// 아니다"로 판정되어 남은 커넥션 내내 SQL을 하나도 내놓지 못했다.
    #[test]
    fn a_flow_stalled_on_a_partial_packet_is_never_given_up_on() {
        let packet = PacketBuilder::new()
            .all_headers()
            .utf16(&"SELECT * FROM dbo.TB_Users WHERE x = 1 ".repeat(60))
            .build(0x01);
        let partial = &packet[..packet.len() / 2];

        let mut assembler = TdsAssembler::new();
        // 같은 미완성 버퍼가 패킷마다 다시 훑인다 (빈틈 뒤에 멈춘 스트림).
        for _ in 0..5000 {
            let scan = assembler.feed(partial);
            // 미완성 패킷은 일부러 `framed`가 아니다 — 검증되지 않은 헤더 하나로
            // TCP 스트림을 '동기화됨'으로 승격시키면 안 되기 때문이다.
            assert!(!scan.framed);
            assert_eq!(scan.consumed, 0, "미완성 패킷은 소비하지 않는다");
            // 그래도 버린 바이트가 없으므로 포기 카운터는 오르지 않아야 한다.
            assert!(!scan.gave_up, "정상 플로우를 포기하면 안 된다");
        }

        // 나머지가 도착하면 SQL이 나와야 한다.
        let scan = assembler.feed(&packet);
        assert_eq!(scan.messages.len(), 1);
        assert!(scan.messages[0].sql.starts_with("SELECT"));
    }

    /// 반면 프레임을 전혀 못 찾는 플로우(TLS 등)는 여전히 포기해야 한다.
    #[test]
    fn a_flow_that_only_produces_garbage_is_still_given_up_on() {
        let mut assembler = TdsAssembler::new();
        let tls_record = vec![0x17; 8 * 1024];
        let mut gave_up = false;
        for _ in 0..1000 {
            if assembler.feed(&tls_record).gave_up {
                gave_up = true;
                break;
            }
        }
        assert!(gave_up, "쓰레기만 오는 플로우는 포기해야 한다");
    }
}

#[cfg(test)]
mod round9_tests {
    use super::tests::PacketBuilder;
    use super::*;

    /// 재현 가능한 의사난수. 암호문처럼 고르게 퍼진 바이트를 만든다.
    struct Xorshift(u64);

    impl Xorshift {
        fn fill(&mut self, buf: &mut [u8]) {
            for byte in buf {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *byte = self.0.to_le_bytes()[3];
            }
        }
    }

    /// 무작위 바이트도 ~186바이트마다 한 번은 유효한 TDS 헤더로 파싱된다.
    /// 단발 헤더를 '인식'으로 세면 포기 판정이 무력해져, 암호화된 연결이
    /// 커넥션 내내 재스캔을 반복하며 쓰레기 SQL을 뱉는다.
    #[test]
    fn a_pseudorandom_flow_is_given_up_on_within_a_bounded_amount_of_data() {
        let mut rng = Xorshift(0x2545_F491_4F6C_DD1D);
        let mut assembler = TdsAssembler::new();
        let mut chunk = vec![0u8; 1460];

        let mut fed = 0usize;
        let mut gave_up = false;
        while fed < 16 * 1024 * 1024 {
            rng.fill(&mut chunk);
            let scan = assembler.feed(&chunk);
            fed += chunk.len();
            if scan.gave_up {
                gave_up = true;
                break;
            }
        }
        assert!(
            gave_up,
            "의사난수 {fed}바이트를 먹고도 포기하지 않았다 (우연한 헤더에 속고 있다)"
        );
        // 우연한 프레임이 삼킨 바이트를 청구하지 않으면 이 값이 명목 한도의
        // 수십 배로 늘어난다 (측정: 90 MB). 예산에 맞물려 있는지 고정해 둔다.
        assert!(
            fed <= 4 * GIVE_UP_AFTER_BYTES,
            "포기까지 {fed}바이트가 필요했다 — 예산({GIVE_UP_AFTER_BYTES})과 너무 벌어졌다"
        );
    }

    /// 세그먼트 하나에 패킷 하나가 담기는 흔한 경우에도 프레임 연쇄가 인정되어야
    /// 한다. 연쇄를 `feed` 호출 안에서만 보면 정상 플로우가 영영 corroborate되지
    /// 않아, 우연한 프레임 바이트를 예산에 청구할 수 없게 된다.
    #[test]
    fn frame_chaining_is_recognized_across_feed_calls() {
        let mut assembler = TdsAssembler::new();
        let packet = PacketBuilder::new()
            .all_headers()
            .utf16("SELECT * FROM dbo.TB_Users")
            .build(0x01);

        // 첫 호출은 이어짐을 확인할 수 없다.
        let scan = assembler.feed(&packet);
        assert_eq!(scan.messages.len(), 1);
        assert!(assembler.unrecognized_bytes > 0, "첫 프레임은 미확인이다");

        // 두 번째부터는 경계가 이어지므로 예산이 초기화되어야 한다.
        let scan = assembler.feed(&packet);
        assert_eq!(scan.messages.len(), 1);
        assert_eq!(
            assembler.unrecognized_bytes, 0,
            "호출 경계를 넘어 프레임이 이어진 것을 인정해야 한다"
        );
    }

    /// 규격(512..32767)을 넘는 길이를 주장하는 헤더는 받아주지 않는다.
    #[test]
    fn an_out_of_spec_packet_length_is_not_a_header() {
        let mut malformed = vec![0x01, 0x01];
        malformed.extend_from_slice(&0xFFFFu16.to_be_bytes()); // length = 65535
        malformed.extend_from_slice(&[0, 0, 1, 0]);
        malformed.extend_from_slice(&[0xEE; 64]);

        let scan = TdsAssembler::new().feed(&malformed);
        assert!(scan.messages.is_empty());
        assert!(!scan.framed, "규격 밖 길이는 프레임으로 인정하지 않는다");
        assert!(scan.consumed > 0, "재동기화를 위해 전진해야 한다");
    }

    /// 반대로 프레임이 이어지는 정상 스트림은 아무리 길어도 포기하지 않는다.
    #[test]
    fn a_long_valid_stream_is_never_given_up_on() {
        let mut assembler = TdsAssembler::new();
        let mut stream = Vec::new();
        for i in 0..8 {
            stream.extend_from_slice(
                &PacketBuilder::new()
                    .all_headers()
                    .utf16(&format!("SELECT {i} FROM dbo.TB_Users"))
                    .build(0x01),
            );
        }
        for _ in 0..2000 {
            let scan = assembler.feed(&stream);
            assert_eq!(scan.messages.len(), 8);
            assert!(!scan.gave_up);
        }
    }

    /// 검증되지 않은 헤더 하나로 TCP 스트림을 '동기화됨'으로 승격시키면,
    /// 뒤늦게 도착한 앞 세그먼트를 재전송으로 오인해 메시지 머리를 잃는다.
    #[test]
    fn an_incomplete_packet_does_not_report_a_frame() {
        let packet = PacketBuilder::new()
            .all_headers()
            .utf16("SELECT * FROM dbo.TB_Users")
            .build(0x01);
        let scan = TdsAssembler::new().feed(&packet[..packet.len() - 4]);
        assert!(!scan.framed);
        assert_eq!(scan.consumed, 0);
    }
}
