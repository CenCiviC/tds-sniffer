use chrono::{DateTime, Utc};
use log::debug;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;

/// MSSQL이 사용하는 잘 알려진 포트. 1434는 SQL Browser.
pub const SQL_SERVER_PORTS: [u16; 3] = [1433, 1434, 1436];

/// 재조립 버퍼 하나가 보관할 수 있는 최대 바이트.
/// 유효한 TDS 프레임이 나오지 않아 버퍼가 계속 자라는 경우를 막는다.
const MAX_STREAM_BYTES: usize = 4 * 1024 * 1024;

/// 순서가 어긋난 세그먼트를 보관할 최대 바이트.
///
/// **개수**로 제한하면 안 된다. 빈틈이 열린 동안 도착하는 세그먼트는 전부
/// 여기 쌓이는데, 개수 상한에 걸려 가장 나중 것부터 버리면 이미 캡처한(그리고
/// 다시 오지 않을) 데이터를 회선 속도로 흘려보내게 된다.
const MAX_PENDING_BYTES: usize = 2 * 1024 * 1024;

/// 보관 대기열이 이 개수에 닿으면 포화로 본다.
///
/// 바이트 예산만으로는 개수를 못 막는다. 1바이트짜리 세그먼트는 예산을 1만
/// 쓰지만 실제로는 맵 노드와 힙 할당까지 70바이트 가까이 차지하고, 개수가
/// 많아지면 빈틈을 건너뛸 때의 맵 재구축 비용이 패킷당 수십 ms까지 오른다.
const MAX_PENDING_SEGMENTS: usize = 4096;

/// 빈틈을 건너뛴 뒤에도 이만큼 남아 있으면 '이어붙일 수 없는 조각'으로 보고 폐기한다.
///
/// 포화 지점보다 **낮아야** 한다. 같으면 건너뛰기가 항목을 하나만 줄여도 폐기가
/// 걸리지 않아, 패킷마다 대기열 전체를 다시 만드는 상태에 갇힌다.
const PENDING_FRAGMENT_LIMIT: usize = MAX_PENDING_SEGMENTS / 2;

/// 이보다 멀리 앞선 시퀀스 오프셋은 재전송(래핑된 음수)이거나 잘못된 값으로 본다.
const MAX_SEQ_AHEAD: u32 = 8 * 1024 * 1024;

/// 동시에 추적할 최대 플로우 수.
///
/// 포트를 흩뿌리는 트래픽(또는 스푸핑)이 플로우를 무한정 만들어 내는 것을 막는다.
const MAX_FLOWS: usize = 4096;

/// 이 시간(초) 동안 패킷이 없는 플로우는 축출한다.
const IDLE_TIMEOUT_SECS: i64 = 120;

/// 빈틈이 이 시간(초) 동안 메워지지 않으면 포기하고 건너뛴다.
///
/// 캡처 지점에서 패킷이 유실되면(바쁜 링크에서 pcap 버퍼 오버플로) 그 바이트는
/// 서버에는 도착했으므로 재전송되지 않는다. 기다리기만 하면 그 플로우는 남은
/// 커넥션 수명 내내 아무 SQL도 내놓지 못한다.
const GAP_TIMEOUT_SECS: i64 = 5;

/// 축출 검사 주기(초).
const SWEEP_INTERVAL_SECS: i64 = 10;

/// 버퍼 길이를 시퀀스 오프셋 폭으로 변환한다.
///
/// 버퍼는 `MAX_STREAM_BYTES`(4 MiB)로 제한되므로 항상 `u32`에 들어간다.
/// 포화 변환이라 32비트/64비트 어디서도 잘리지 않는다.
fn seq_len(bytes: usize) -> u32 {
    u32::try_from(bytes).unwrap_or(u32::MAX)
}

/// TCP 종단점 (IP + 포트).
///
/// 모든 필드가 `Copy`이므로 이 타입도 `Copy`다. `.clone()`을 부를 이유가 없다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl Endpoint {
    #[must_use]
    pub const fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }

    /// 이 종단점이 MSSQL 서버 포트를 쓰고 있는가.
    #[must_use]
    pub fn is_sql_server(self) -> bool {
        SQL_SERVER_PORTS.contains(&self.port)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

/// 관찰된 패킷의 진행 방향.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// 방향과 무관하게 하나의 TCP 커넥션을 가리키는 **정규화된** 식별자.
///
/// 생성자가 [`Direction`]을 함께 돌려주므로, "정규화되지 않은 `FlowId`"라는
/// 잘못된 상태를 만들 수 없다. 양방향 패킷이 같은 키로 모인다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowId {
    pub client: Endpoint,
    pub server: Endpoint,
}

impl FlowId {
    /// 관찰된 (출발지, 목적지)에서 정규화된 플로우와 그 패킷의 방향을 판정한다.
    ///
    /// 서버는 MSSQL 포트를 쓰는 쪽으로 정한다. 양쪽 다 아니면 우리가 관심 있는
    /// 트래픽이 아니므로 `None`을 돌려준다 — 포트 필터링이 타입 안으로 들어온 셈이다.
    #[must_use]
    pub fn classify(src: Endpoint, dst: Endpoint) -> Option<(Self, Direction)> {
        match (src.is_sql_server(), dst.is_sql_server()) {
            // 목적지가 서버 → 클라이언트가 보낸 패킷.
            // 양쪽 다 SQL 포트인 드문 경우도 여기로 보내 키를 결정적으로 유지한다.
            (_, true) => Some((
                Self {
                    client: src,
                    server: dst,
                },
                Direction::ClientToServer,
            )),
            // 출발지만 서버 → 서버가 보낸 패킷
            (true, false) => Some((
                Self {
                    client: dst,
                    server: src,
                },
                Direction::ServerToClient,
            )),
            (false, false) => None,
        }
    }
}

impl fmt::Display for FlowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}->{}", self.client, self.server)
    }
}

/// 파서가 재조립 버퍼를 훑고 나서 돌려주는 소비 보고.
///
/// 바이트 수만으로는 "프로토콜을 인식하고 처리한 것"과 "재동기화하느라 버린 것"을
/// 구분할 수 없다. 그 구분이 없으면 재조립기는 순서가 뒤바뀐 첫 세그먼트를
/// 되돌릴 수 있는지 판단하지 못한다.
#[derive(Debug, Clone, Copy)]
pub struct Consumed {
    bytes: usize,
    synced: bool,
}

impl Consumed {
    /// 아무것도 소비하지 않았다.
    #[must_use]
    pub const fn nothing() -> Self {
        Self {
            bytes: 0,
            synced: false,
        }
    }

    /// 프레임을 인식하고 `bytes`만큼 처리했다.
    #[must_use]
    pub const fn synced(bytes: usize) -> Self {
        Self {
            bytes,
            synced: true,
        }
    }

    /// 프레임을 인식하지 못한 채 `bytes`만큼 버렸다 (재동기화).
    #[must_use]
    pub const fn unsynced(bytes: usize) -> Self {
        Self {
            bytes,
            synced: false,
        }
    }
}

/// 한 방향(클라이언트→서버) 바이트 스트림의 재조립 버퍼.
///
/// `data[0]`의 시퀀스 번호가 `base`다. 소비된 바이트는 앞에서 잘라내고 `base`를
/// 그만큼 전진시키므로, 버퍼에는 **아직 파싱되지 않은 바이트만** 남는다.
#[derive(Debug)]
struct ClientStream {
    base: u32,
    data: Vec<u8>,
    /// `base` 기준 오프셋 -> 아직 붙일 수 없는 세그먼트.
    pending: BTreeMap<u32, Vec<u8>>,
    /// `pending`이 들고 있는 총 바이트.
    pending_bytes: usize,
    last_seen: DateTime<Utc>,
    /// 파서가 이 스트림에서 프로토콜 프레임을 인식한 적이 있는가.
    ///
    /// 인식 전이라면 `base`보다 앞선 세그먼트가 와도 아직 되돌릴 수 있다.
    /// 인식한 뒤라면 그 경계 이전은 확정이므로, 앞선 세그먼트는 재전송이다.
    synced: bool,
    /// `data`가 마지막으로 자란 시각.
    ///
    /// 축출 판단에는 `last_seen`을 쓰지 않는다. 메울 수 없는 빈틈이 생기면
    /// 세그먼트는 계속 도착해 `last_seen`을 갱신하지만 스트림은 전진하지 못해,
    /// 유휴 축출로도 회수되지 않는 영구 블랙홀이 된다.
    last_progress: DateTime<Utc>,
    /// 바이트 스트림에 불연속이 생겼는가.
    ///
    /// 포트 재사용, 메울 수 없는 빈틈 건너뛰기, 버퍼 상한 초과로 앞부분을 버리면
    /// 그 전후의 바이트는 이어지지 않는다. 상위 파서가 반쪽 메시지를 들고 있다면
    /// 그것은 이제 무의미하므로, 다음 파싱 전에 반드시 초기화해야 한다.
    /// 그러지 않으면 이전 커넥션의 조각이 새 데이터와 이어붙어 SQL이 오염된다.
    desynced: bool,
    /// 현재 기다리고 있는 빈틈: (빈틈이 끝나는 **절대 시퀀스**, 처음 본 시각).
    ///
    /// 상대 오프셋으로 식별하면 `base`가 움직였을 때 서로 다른 빈틈이 같은
    /// 오프셋을 갖게 되어, 새 빈틈이 이미 만료된 빈틈의 시각을 물려받는다.
    /// 그러면 아직 도착 중인 바이트를 유예 없이 버리게 된다.
    ///
    /// 빈틈을 포기할지는 **이 빈틈의 나이**로 판단해야 한다. "스트림이 마지막으로
    /// 자란 시각"으로 재면 잠시 쉬었던 클라이언트가 보낸 첫 순서 뒤바뀜 세그먼트가
    /// 곧바로 포기 대상이 되어, 뒤늦게 도착할 앞부분을 영영 버리게 된다.
    gap: Option<(u32, DateTime<Utc>)>,
}

impl ClientStream {
    const fn new(seq: u32, now: DateTime<Utc>) -> Self {
        Self {
            base: seq,
            data: Vec::new(),
            pending: BTreeMap::new(),
            pending_bytes: 0,
            last_seen: now,
            synced: false,
            last_progress: now,
            desynced: false,
            gap: None,
        }
    }

    /// 세그먼트를 스트림에 병합한다.
    ///
    /// 연속이면 바로 이어붙이고, 앞부분이 겹치면 겹친 만큼 잘라내며, 빈틈이
    /// 있으면 `pending`에 넣어 두었다가 빈틈이 메워질 때 이어붙인다.
    fn push(&mut self, seq: u32, payload: &[u8], now: DateTime<Utc>) {
        // 오프셋은 시퀀스 공간에서 계산하므로 끝까지 u32로 다룬다.
        let offset = seq.wrapping_sub(self.base);

        if offset > MAX_SEQ_AHEAD {
            // base보다 뒤이거나(래핑된 음수) 터무니없이 앞선 시퀀스다.
            let behind = offset.wrapping_neg();

            if !self.synced && behind <= MAX_SEQ_AHEAD {
                // 아직 프레임을 하나도 인식하지 못했다면 처음 본 세그먼트가
                // 스트림의 시작이 아니었을 뿐이다(순서 뒤바뀜). base를 뒤로 물린다.
                //
                // 이 검사는 아래 "겹치는 재전송" 처리보다 **먼저** 와야 한다.
                // 순서가 뒤바뀐 데다 앞부분이 겹쳐서 도착하면, 겹침 처리로 넘어가
                // 아직 본 적 없는 머리(=TDS 헤더)를 잘라 버리기 때문이다.
                self.rebase_backward(seq);
                self.push(seq, payload, now);
                return;
            }

            if (behind as usize) < payload.len() {
                // 이미 소비한 구간과 겹치는 재전송. 새로운 꼬리만 이어붙인다.
                // 통째로 버리면 이후 세그먼트와 영구적인 빈틈이 생긴다.
                self.last_seen = now;
                let fresh = &payload[behind as usize..];
                let already_have = self.data.len();
                if already_have < fresh.len() {
                    self.data.extend_from_slice(&fresh[already_have..]);
                    // 이 경로로만 전진하는 스트림도 살아 있는 것이다.
                    self.last_progress = now;
                }
                self.drain_pending();
                self.enforce_limits(now);
                return;
            }

            if behind > MAX_SEQ_AHEAD {
                // 어느 방향으로도 창을 벗어났다 = 이 4-tuple을 재사용하는 새 커넥션.
                // 여기서 재동기화하지 않으면 이 플로우는 영영 데이터를 받지 못하고,
                // last_seen이 계속 갱신되므로 유휴 축출로도 회수되지 않는다.
                self.rebase(seq, now);
                self.push(seq, payload, now);
            }
            // 그 밖(이미 소비한 구간의 순수 재전송)은 버려도 안전하다.
            return;
        }

        self.last_seen = now;

        if offset <= seq_len(self.data.len()) {
            let already_have = self.data.len() - offset as usize;
            if already_have < payload.len() {
                self.data.extend_from_slice(&payload[already_have..]);
                self.last_progress = now;
            }
            self.drain_pending();
        } else {
            self.stash(offset, payload);
            self.refresh_gap(now);
            self.skip_stale_gap(now);
        }

        self.enforce_limits(now);
    }

    /// 오래 메워지지 않는 빈틈을 건너뛴다.
    ///
    /// 캡처 지점에서 세그먼트가 유실되면 그 바이트는 서버에는 도착했으므로
    /// 재전송되지 않는다. 계속 기다리면 이 플로우는 남은 커넥션 수명 내내
    /// 아무것도 내놓지 못한다. 빈틈 너머로 base를 밀어 파서가 재동기화하게 한다.
    fn skip_stale_gap(&mut self, now: DateTime<Utc>) {
        // 이 빈틈이 생긴 지 얼마나 됐는지로 판단한다.
        if self
            .gap
            .is_some_and(|(_, since)| (now - since).num_seconds() >= GAP_TIMEOUT_SECS)
        {
            self.skip_gap(now);
        }
    }

    /// 기다리던 빈틈을 포기하고 그 너머로 base를 민다.
    fn skip_gap(&mut self, now: DateTime<Utc>) {
        let Some((gap_seq, _)) = self.gap else {
            return;
        };
        let next = gap_seq.wrapping_sub(self.base);
        let skip = next as usize;
        debug!("메워지지 않는 빈틈 {skip}바이트를 건너뛴다");

        // 빈틈 앞의 미완성 바이트는 더 이상 쓸모가 없다.
        self.data.clear();
        self.base = self.base.wrapping_add(next);
        self.pending = std::mem::take(&mut self.pending)
            .into_iter()
            .filter_map(|(offset, seg)| offset.checked_sub(next).map(|o| (o, seg)))
            .collect();
        self.recount_pending();
        // 빈틈을 건너뛰었으니 프레이밍은 처음부터 다시 찾아야 한다.
        self.synced = false;
        self.desynced = true;
        self.last_progress = now;
        self.drain_pending();
        self.refresh_gap(now);
    }

    /// 기다리는 빈틈을 갱신한다. 빈틈이 바뀌면 타이머도 새로 시작한다.
    fn refresh_gap(&mut self, now: DateTime<Utc>) {
        match self.pending.first_key_value() {
            None => self.gap = None,
            Some((&lowest, _)) => {
                let absolute = self.base.wrapping_add(lowest);
                if !matches!(self.gap, Some((seq, _)) if seq == absolute) {
                    self.gap = Some((absolute, now));
                }
            }
        }
    }

    /// 포트를 재사용하는 새 커넥션으로 보고 버퍼를 초기화한다.
    fn rebase(&mut self, seq: u32, now: DateTime<Utc>) {
        debug!("플로우 재동기화: base {} -> {seq}", self.base);
        self.base = seq;
        self.data.clear();
        self.pending.clear();
        self.pending_bytes = 0;
        self.synced = false;
        self.desynced = true;
        self.last_seen = now;
        self.last_progress = now;
    }

    /// `base`를 더 앞선 시퀀스로 물리고, 기존 데이터를 그만큼 뒤로 옮긴다.
    ///
    /// 스트림의 첫 세그먼트가 순서상 첫 번째라는 보장은 없다. 뒷부분이 먼저
    /// 도착하면 그 자리를 base로 잡게 되는데, 그때 앞부분을 버리면 메시지가
    /// 영영 조립되지 않는다.
    fn rebase_backward(&mut self, new_base: u32) {
        let shift = self.base.wrapping_sub(new_base);
        debug_assert!(shift > 0);

        let mut moved: BTreeMap<u32, Vec<u8>> = std::mem::take(&mut self.pending)
            .into_iter()
            .filter_map(|(offset, seg)| offset.checked_add(shift).map(|o| (o, seg)))
            .collect();
        if !self.data.is_empty() {
            moved.insert(shift, std::mem::take(&mut self.data));
        }
        self.pending = moved;
        self.recount_pending();
        self.base = new_base;
    }

    /// 빈틈 뒤의 세그먼트를 보관한다. 같은 오프셋이면 더 긴 쪽을 남긴다.
    fn stash(&mut self, offset: u32, payload: &[u8]) {
        if self
            .pending
            .get(&offset)
            .is_some_and(|existing| existing.len() >= payload.len())
        {
            return;
        }
        self.pending_bytes += payload.len();
        if let Some(old) = self.pending.insert(offset, payload.to_vec()) {
            self.pending_bytes -= old.len();
        }
    }

    /// 보관 바이트 수를 다시 센다. 맵을 통째로 다시 만든 뒤에 쓴다.
    fn recount_pending(&mut self) {
        self.pending_bytes = self.pending.values().map(Vec::len).sum();
    }

    /// 이제 연속이 된 보관 세그먼트들을 순서대로 이어붙인다.
    fn drain_pending(&mut self) {
        let before = self.data.len();
        while let Some((&offset, _)) = self.pending.first_key_value() {
            if offset as usize > self.data.len() {
                break;
            }
            // 위 조건 덕분에 항목이 존재함이 보장된다.
            let segment = self
                .pending
                .remove(&offset)
                .expect("first_key_value가 방금 돌려준 키");
            self.pending_bytes -= segment.len();
            let already_have = self.data.len() - offset as usize;
            if already_have < segment.len() {
                self.data.extend_from_slice(&segment[already_have..]);
            }
        }
        if self.data.len() > before {
            self.last_progress = self.last_seen;
        }
        self.refresh_gap(self.last_seen);
    }

    /// 메모리 상한 적용. 넘치면 오래된 앞부분을 버리고 재동기화한다.
    fn enforce_limits(&mut self, now: DateTime<Utc>) {
        if self.data.len() > MAX_STREAM_BYTES {
            // 파서의 보고 타입(`Consumed`)을 위조하지 않는다. 여기서 버리는 것은
            // 파싱한 결과가 아니라 상한을 넘긴 앞부분이다.
            let drop_len = self.data.len() - MAX_STREAM_BYTES / 2;
            self.discard_front(drop_len);
            // 앞부분을 잘라냈으니 프레이밍 경계는 신뢰할 수 없다.
            self.synced = false;
            self.desynced = true;
        }
        // 보관 공간이 꽉 찼다. 새로 도착한 데이터를 버리는 대신, 기다리던
        // 빈틈을 포기한다 — 그 바이트는 서버에는 이미 도착했으므로 다시 오지
        // 않는다. 버려야 한다면 오래된 쪽을 버리는 것이 맞다.
        //
        // 한 번에 하나만 건너뛴다. `skip_gap`은 `data.clear()`로 시작하므로,
        // 연달아 부르면 직전 호출이 이어붙인 정상 데이터를 파서가 보기도 전에
        // 지운다. 빈틈이 여러 개 겹쳐 있으면 다음 패킷에서 이어서 처리된다.
        if self.pending_saturated() {
            self.skip_gap(now);
        }

        // 건너뛴 뒤에도 항목이 많이 남았다면 이어붙일 수 없는 조각만 쌓인 것이다.
        // 계속 안고 가면 패킷마다 맵을 통째로 다시 만들게 되므로(패킷당 수십 ms)
        // 버리고 프레이밍을 처음부터 다시 찾는다.
        //
        // 판단은 **항목 수**로만 한다. 바이트 압박은 큰 연속 구간 하나로도
        // 생기는데, 그건 건너뛰기가 공짜로 흡수해 줄 수 있는 정상 데이터다.
        if self.pending.len() > PENDING_FRAGMENT_LIMIT {
            debug!("이어붙일 수 없는 조각이 쌓여 대기열을 폐기하고 재동기화한다");
            self.pending.clear();
            self.pending_bytes = 0;
            self.gap = None;
            self.synced = false;
            self.desynced = true;
        }
    }

    /// 보관 대기열이 바이트나 개수 어느 쪽으로든 상한에 닿았는가.
    fn pending_saturated(&self) -> bool {
        self.pending_bytes > MAX_PENDING_BYTES || self.pending.len() >= MAX_PENDING_SEGMENTS
    }

    /// 아직 파싱되지 않은 바이트를 **빌려서** 돌려준다. 복사가 없다.
    fn unconsumed(&self) -> &[u8] {
        &self.data
    }

    /// 불연속이 있었는지 확인하고 표식을 지운다.
    fn take_desync(&mut self) -> bool {
        std::mem::take(&mut self.desynced)
    }

    /// 앞의 `n` 바이트를 소비 완료로 표시하고 버퍼에서 제거한다.
    fn consume(&mut self, consumed: Consumed) {
        // 프레임을 인식했다면 이 지점 이전은 확정이다. 그 전에는 되돌릴 수 있다.
        self.synced |= consumed.synced;
        self.discard_front(consumed.bytes);
    }

    /// 앞의 `n` 바이트를 버리고 `base`와 보관 오프셋을 그만큼 전진시킨다.
    ///
    /// 알려진 한계: 보관 오프셋이 `base` 기준이라 `base`가 움직일 때마다 맵을
    /// 다시 만든다. 항목 수가 `MAX_PENDING_SEGMENTS`로 유계이므로 비용도 유계지만,
    /// 큰 대기열이 유지된 채 소비가 계속되는 (인위적으로 만들어야 하는) 상황에서는
    /// 패킷당 수십 µs가 든다. 없애려면 보관 키를 절대 시퀀스 기준으로 바꾸고
    /// 별도의 `pending_base`를 두어야 한다 — 래핑 처리가 얽혀 지금은 두지 않았다.
    fn discard_front(&mut self, n: usize) {
        let n = n.min(self.data.len());
        if n == 0 {
            return;
        }
        self.data.drain(..n);
        let shift = seq_len(n);
        // 빈틈은 절대 시퀀스로 들고 있으므로 `base`가 움직여도 손댈 필요가 없다.
        self.base = self.base.wrapping_add(shift);

        // 보관 중인 오프셋도 새 base 기준으로 옮긴다.
        if !self.pending.is_empty() {
            self.pending = std::mem::take(&mut self.pending)
                .into_iter()
                .filter_map(|(offset, seg)| offset.checked_sub(shift).map(|o| (o, seg)))
                .collect();
            self.recount_pending();
        }
    }
}

/// 한 플로우가 소유하는 것: 바이트 재조립 버퍼와 상위 파서의 상태.
#[derive(Debug)]
struct Flow<S> {
    stream: ClientStream,
    parser: S,
}

/// 플로우별 TCP 스트림 재조립기.
///
/// 클라이언트→서버 방향만 보관한다. 서버 응답은 SQL 추출에 쓰이지 않으므로
/// 아예 버퍼링하지 않는다 — 쓰지 않을 데이터를 위한 필드를 두지 않는다.
///
/// 상위 프로토콜의 플로우별 상태 `S`도 함께 소유한다. 플로우의 생성·축출
/// 시점이 곧 그 상태의 수명이므로, 별도의 맵을 두고 동기화할 필요가 없다.
#[derive(Debug)]
pub struct TcpReassembler<S = ()> {
    flows: HashMap<FlowId, Flow<S>>,
    last_sweep: Option<DateTime<Utc>>,
}

impl<S> Default for TcpReassembler<S> {
    fn default() -> Self {
        Self {
            flows: HashMap::new(),
            last_sweep: None,
        }
    }
}

impl<S: Default> TcpReassembler<S> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 클라이언트→서버 세그먼트를 추가한다.
    pub fn push(&mut self, flow: FlowId, seq: u32, payload: &[u8], now: DateTime<Utc>) {
        if payload.is_empty() {
            return;
        }
        if self.flows.len() >= MAX_FLOWS && !self.flows.contains_key(&flow) {
            // 상한에 닿았다. 먼저 조용한 플로우를 정리해 보고, 그래도 자리가
            // 없으면 새 플로우를 받지 않는다 — 메모리가 무한정 늘어나는 것보다는
            // 낫다. 스로틀이 걸린 `evict_idle`을 쓴다. 매번 전체 순회를 돌면
            // 포트를 흩뿌리는 트래픽이 패킷당 O(플로우 수)를 강제할 수 있다.
            self.evict_idle(now);
            if self.flows.len() >= MAX_FLOWS {
                debug!("플로우 상한({MAX_FLOWS}) 도달, 새 플로우를 무시한다");
                return;
            }
        }
        self.flows
            .entry(flow)
            .or_insert_with(|| Flow {
                stream: ClientStream::new(seq, now),
                parser: S::default(),
            })
            .stream
            .push(seq, payload, now);
    }

    /// 재조립된 바이트를 `parse`에 빌려주고, 반환된 소비 길이만큼 버퍼를 전진시킨다.
    ///
    /// 소유권 설계의 핵심: 호출자는 버퍼를 복사해 갈 필요가 없고, 재조립기는
    /// "얼마나 소비됐는지"를 반드시 돌려받으므로 같은 바이트를 두 번 파싱하지 않는다.
    pub fn drain_client<T>(
        &mut self,
        flow: &FlowId,
        parse: impl FnOnce(&mut S, &[u8]) -> (T, Consumed),
    ) -> Option<T> {
        let entry = self.flows.get_mut(flow)?;
        // 바이트 스트림이 끊겼다면 상위 파서가 들고 있던 조립 상태는 무효다.
        if entry.stream.take_desync() {
            entry.parser = S::default();
        }
        // `&mut entry.parser`와 `&entry.stream`은 서로 다른 필드라 함께 빌릴 수 있다.
        let (result, consumed) = parse(&mut entry.parser, entry.stream.unconsumed());
        entry.stream.consume(consumed);
        Some(result)
    }

    /// 오래 조용한 플로우를 정리한다. 호출은 저렴하도록 스로틀링된다.
    pub fn evict_idle(&mut self, now: DateTime<Utc>) {
        if let Some(last) = self.last_sweep {
            // 절댓값으로 비교한다. 시계가 뒤로 조정되어 미래 타임스탬프가 한 번
            // 들어오면, 단순 뺄셈은 그 뒤로 계속 음수가 되어 청소가 멈춘다.
            if (now - last).num_seconds().abs() < SWEEP_INTERVAL_SECS {
                return;
            }
        }
        self.sweep(now);
    }

    /// 조용하거나 전진하지 못하는 플로우를 정리한다.
    fn sweep(&mut self, now: DateTime<Utc>) {
        self.last_sweep = Some(now);
        self.flows.retain(|_, flow| {
            // 진행 시각 기준으로 판단한다. 메울 수 없는 빈틈에 걸린 플로우는
            // 세그먼트가 계속 도착해 `last_seen`은 갱신되지만 전진하지 못한다.
            let idle = (now - flow.stream.last_seen).num_seconds();
            let stalled = (now - flow.stream.last_progress).num_seconds();
            idle < IDLE_TIMEOUT_SECS && stalled < IDLE_TIMEOUT_SECS
        });
    }

    /// 현재 추적 중인 플로우 수 (진단용).
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;
    use std::net::Ipv4Addr;

    /// 테스트용 고정 기준 시각.
    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn ep(last_octet: u8, port: u16) -> Endpoint {
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)), port)
    }

    /// 같은 커넥션의 양방향 패킷은 반드시 같은 키로 정규화되어야 한다.
    #[test]
    fn classify_normalizes_both_directions_to_one_flow() {
        let client = ep(1, 50000);
        let server = ep(2, 1433);

        let (out_flow, out_dir) = FlowId::classify(client, server).expect("SQL 포트 존재");
        let (in_flow, in_dir) = FlowId::classify(server, client).expect("SQL 포트 존재");

        assert_eq!(out_flow, in_flow, "양방향이 같은 플로우여야 한다");
        assert_eq!(out_dir, Direction::ClientToServer);
        assert_eq!(in_dir, Direction::ServerToClient);
        assert_eq!(out_flow.client, client);
        assert_eq!(out_flow.server, server);
    }

    #[test]
    fn classify_rejects_non_sql_traffic() {
        assert!(FlowId::classify(ep(1, 12345), ep(2, 80)).is_none());
    }

    #[test]
    fn in_order_segments_concatenate() {
        let mut s = ClientStream::new(1000, t0());
        s.push(1000, b"abc", t0());
        s.push(1003, b"def", t0());
        assert_eq!(s.unconsumed(), b"abcdef");
    }

    #[test]
    fn out_of_order_segments_are_held_then_joined() {
        let mut s = ClientStream::new(1000, t0());
        s.push(1006, b"ghi", t0()); // 빈틈 뒤 세그먼트
        assert_eq!(s.unconsumed(), b"", "빈틈이 있으면 아직 붙이지 않는다");
        s.push(1000, b"abc", t0());
        assert_eq!(s.unconsumed(), b"abc");
        s.push(1003, b"def", t0()); // 빈틈이 메워짐
        assert_eq!(s.unconsumed(), b"abcdefghi");
    }

    #[test]
    fn overlapping_retransmit_is_deduplicated() {
        let mut s = ClientStream::new(1000, t0());
        s.push(1000, b"abcdef", t0());
        s.push(1003, b"defghi", t0()); // 앞 3바이트가 겹침
        assert_eq!(s.unconsumed(), b"abcdefghi");
    }

    #[test]
    fn pure_retransmit_of_consumed_bytes_is_ignored() {
        let mut s = ClientStream::new(1000, t0());
        s.push(1000, b"abcdef", t0());
        s.consume(Consumed::synced(6));
        s.push(1000, b"abcdef", t0()); // 이미 소비한 구간
        assert_eq!(s.unconsumed(), b"", "소비한 바이트를 되살리면 안 된다");
    }

    #[test]
    fn consume_advances_base_and_keeps_remainder() {
        let mut s = ClientStream::new(1000, t0());
        s.push(1000, b"abcdef", t0());
        s.consume(Consumed::synced(4));
        assert_eq!(s.unconsumed(), b"ef");
        assert_eq!(s.base, 1004);
        s.push(1006, b"gh", t0()); // 새 base 기준으로 연속
        assert_eq!(s.unconsumed(), b"efgh");
    }

    /// 시퀀스 번호는 2^32에서 되돌아온다. 순진한 `sort_by_key(|s| s.seq)`는
    /// 여기서 스트림 순서를 뒤집는다.
    #[test]
    fn sequence_wraparound_is_handled() {
        let base = u32::MAX - 2; // 3바이트 뒤에 래핑
        let mut s = ClientStream::new(base, t0());
        s.push(base, b"abc", t0());
        s.push(base.wrapping_add(3), b"def", t0());
        assert_eq!(s.unconsumed(), b"abcdef");
    }

    #[test]
    fn drain_client_consumes_only_what_parser_reports() {
        let flow = FlowId::classify(ep(1, 50000), ep(2, 1433)).unwrap().0;
        let mut r = TcpReassembler::<()>::new();
        r.push(flow, 100, b"HELLOWORLD", t0());

        let seen = r
            .drain_client(&flow, |(): &mut (), buf: &[u8]| {
                (buf.to_vec(), Consumed::synced(5))
            })
            .expect("플로우 존재");
        assert_eq!(seen, b"HELLOWORLD");

        // 5바이트만 소비했으므로 나머지만 다시 보여야 한다.
        let seen = r
            .drain_client(&flow, |(): &mut (), buf: &[u8]| {
                (buf.to_vec(), Consumed::nothing())
            })
            .unwrap();
        assert_eq!(seen, b"WORLD", "같은 바이트를 두 번 파싱하면 안 된다");
    }

    #[test]
    fn idle_flows_are_evicted() {
        let flow = FlowId::classify(ep(1, 50000), ep(2, 1433)).unwrap().0;
        let mut r = TcpReassembler::<()>::new();
        r.push(flow, 1, b"x", t0());
        assert_eq!(r.flow_count(), 1);

        r.evict_idle(t0() + TimeDelta::seconds(IDLE_TIMEOUT_SECS + SWEEP_INTERVAL_SECS + 1));
        assert_eq!(r.flow_count(), 0, "조용한 플로우는 정리되어야 한다");
    }

    #[test]
    fn stream_buffer_is_bounded() {
        let mut s = ClientStream::new(0, t0());
        let chunk = vec![0u8; 64 * 1024];
        let mut seq = 0u32;
        for _ in 0..128 {
            s.push(seq, &chunk, t0());
            seq = seq.wrapping_add(seq_len(chunk.len()));
        }
        assert!(
            s.unconsumed().len() <= MAX_STREAM_BYTES,
            "버퍼가 무한히 자라면 안 된다: {}",
            s.unconsumed().len()
        );
    }
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    use chrono::TimeDelta;
    use std::net::{IpAddr, Ipv4Addr};

    fn ep(last_octet: u8, port: u16) -> Endpoint {
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)), port)
    }

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    /// 클라이언트가 임시 포트를 재사용하면 새 커넥션의 ISN이 옛 base에서 아주
    /// 멀리 떨어진다. 이를 버리기만 하면 해당 4-tuple은 영영 죽고, `last_seen`이
    /// 계속 갱신되므로 유휴 축출로도 회수되지 않는다.
    #[test]
    fn port_reuse_with_a_new_isn_resynchronizes_instead_of_blackholing() {
        let flow = FlowId::classify(ep(1, 50000), ep(2, 1433)).unwrap().0;
        let mut r = TcpReassembler::<()>::new();

        r.push(flow, 1000, b"first-connection", t0());
        assert_eq!(
            r.drain_client(&flow, |(): &mut (), b: &[u8]| (
                b.to_vec(),
                Consumed::synced(b.len())
            ))
            .unwrap(),
            b"first-connection"
        );

        // 같은 4-tuple, 완전히 다른 ISN으로 새 커넥션이 시작된다.
        let later = t0() + TimeDelta::seconds(1);
        r.push(flow, 0x8000_0000, b"second-connection", later);
        assert_eq!(
            r.drain_client(&flow, |(): &mut (), b: &[u8]| (
                b.to_vec(),
                Consumed::synced(b.len())
            ))
            .unwrap(),
            b"second-connection",
            "포트 재사용 후에도 데이터를 받아야 한다"
        );
    }

    /// 재전송이 소비 경계에 걸쳐 있으면(TSO 병합 등) 통째로 버리면 안 된다.
    /// 새 꼬리를 잃어 영구적인 빈틈이 생긴다.
    #[test]
    fn retransmit_straddling_the_consumed_boundary_keeps_its_new_tail() {
        let flow = FlowId::classify(ep(1, 50000), ep(2, 1433)).unwrap().0;
        let mut r = TcpReassembler::<()>::new();

        r.push(flow, 1000, b"ABCDEF", t0());
        r.drain_client(&flow, |(): &mut (), _: &[u8]| ((), Consumed::synced(4)))
            .unwrap(); // base = 1004, 남은 것 "EF"

        // 1000부터 다시 보내면서 4바이트가 더 붙었다.
        r.push(flow, 1000, b"ABCDEFGHIJ", t0());
        r.push(flow, 1010, b"KLM", t0());

        let seen = r
            .drain_client(&flow, |(): &mut (), b: &[u8]| {
                (b.to_vec(), Consumed::nothing())
            })
            .unwrap();
        assert_eq!(
            seen, b"EFGHIJKLM",
            "겹치는 앞부분만 버리고 새 꼬리는 이어야 한다"
        );
    }

    /// 이미 소비한 구간의 순수 재전송은 조용히 버려야 한다.
    #[test]
    fn pure_retransmit_below_base_is_still_ignored() {
        let flow = FlowId::classify(ep(1, 50000), ep(2, 1433)).unwrap().0;
        let mut r = TcpReassembler::<()>::new();

        r.push(flow, 1000, b"ABCDEF", t0());
        r.drain_client(&flow, |(): &mut (), _: &[u8]| ((), Consumed::synced(6)))
            .unwrap(); // 전부 소비
        r.push(flow, 1000, b"ABCDEF", t0()); // 순수 재전송

        let seen = r
            .drain_client(&flow, |(): &mut (), b: &[u8]| {
                (b.to_vec(), Consumed::nothing())
            })
            .unwrap();
        assert!(seen.is_empty(), "소비한 바이트를 되살리면 안 된다");
    }
}

#[cfg(test)]
mod round2_tests {
    use super::*;
    use chrono::TimeDelta;
    use std::net::{IpAddr, Ipv4Addr};

    fn ep(last_octet: u8, port: u16) -> Endpoint {
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)), port)
    }

    fn flow() -> FlowId {
        FlowId::classify(ep(1, 50000), ep(2, 1433)).unwrap().0
    }

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    /// 순서가 뒤바뀐 데다 앞부분이 겹쳐서 도착하면, 겹침 처리가 먼저 걸려
    /// 아직 본 적 없는 머리(=TDS 헤더)를 잘라 버렸다.
    #[test]
    fn overlapping_first_segment_before_any_framing_keeps_its_head() {
        let mut r = TcpReassembler::<()>::new();
        let flow = flow();

        // 뒷부분이 먼저 도착한다.
        r.push(flow, 1100, b"TAIL", t0());
        r.drain_client(&flow, |(): &mut (), _: &[u8]| ((), Consumed::nothing()))
            .unwrap();

        // 앞부분이 뒤늦게, 그것도 겹쳐서 도착한다.
        let mut head = b"HEAD".to_vec();
        head.extend_from_slice(b"TAIL");
        r.push(flow, 1096, &head, t0());

        let seen = r
            .drain_client(&flow, |(): &mut (), b: &[u8]| {
                (b.to_vec(), Consumed::nothing())
            })
            .unwrap();
        assert_eq!(seen, b"HEADTAIL", "머리를 잃으면 프레이밍이 불가능하다");
    }

    /// 빈틈을 포기할지는 **그 빈틈의 나이**로 판단해야 한다. "스트림이 마지막으로
    /// 자란 시각"으로 재면, 잠시 쉬었던 클라이언트가 보낸 첫 순서 뒤바뀜 세그먼트가
    /// 곧바로 포기 대상이 되어 뒤늦게 올 앞부분을 영영 버린다. SQL 감사 도구에서
    /// 잘린 문장을 기록하는 것은 아무것도 기록하지 않는 것보다 나쁘다.
    #[test]
    fn a_fresh_gap_after_an_idle_period_is_not_skipped() {
        let mut r = TcpReassembler::<()>::new();
        let flow = flow();

        r.push(flow, 1000, b"HEAD", t0());
        r.drain_client(&flow, |(): &mut (), _: &[u8]| ((), Consumed::synced(4)))
            .unwrap();

        // 클라이언트가 한참 쉬었다가 다시 보낸다. 그런데 순서가 뒤바뀌어
        // 뒷부분이 먼저 도착했다.
        let later = t0() + TimeDelta::seconds(60);
        r.push(flow, 1008, b"TAIL", later);
        r.drain_client(&flow, |(): &mut (), _: &[u8]| ((), Consumed::nothing()))
            .unwrap();

        // 곧이어 앞부분이 도착한다. 방금 생긴 빈틈을 이미 포기했다면 잃는다.
        r.push(flow, 1004, b"MIDL", later);
        let seen = r
            .drain_client(&flow, |(): &mut (), b: &[u8]| {
                (b.to_vec(), Consumed::nothing())
            })
            .unwrap();
        assert_eq!(
            seen, b"MIDLTAIL",
            "방금 생긴 빈틈을 유휴 시간 때문에 포기하면 안 된다"
        );
    }

    /// 빈틈이 열려 있는 동안 앞쪽 바이트를 소비하면 보관 오프셋이 밀린다.
    /// 빈틈 좌표도 함께 밀지 않으면 다음 검사가 이를 '새 빈틈'으로 보고 타이머를
    /// 되감아, 소비할 때마다 유예가 연장된다.
    #[test]
    fn consuming_while_a_gap_is_open_does_not_rewind_the_gap_timer() {
        let mut r = TcpReassembler::<()>::new();
        let flow = flow();

        // 앞쪽에 아직 파싱되지 않은 바이트를 남긴 채 빈틈을 연다.
        r.push(flow, 1000, b"HEADHEAD", t0());
        r.push(flow, 1108, b"AFTER", t0());
        r.drain_client(&flow, |(): &mut (), _: &[u8]| ((), Consumed::nothing()))
            .unwrap();

        // 빈틈이 열린 상태에서 앞쪽 4바이트를 소비한다.
        let mid = t0() + TimeDelta::seconds(1);
        r.push(flow, 1008, b"MORE", mid);
        r.drain_client(&flow, |(): &mut (), _: &[u8]| ((), Consumed::synced(4)))
            .unwrap();

        // 빈틈이 생긴 지 GAP_TIMEOUT_SECS가 지났으므로 건너뛰어야 한다.
        let late = t0() + TimeDelta::seconds(GAP_TIMEOUT_SECS + 1);
        r.push(flow, 1113, b"TAIL", late);
        let seen = r
            .drain_client(&flow, |(): &mut (), b: &[u8]| {
                (b.to_vec(), Consumed::nothing())
            })
            .unwrap();
        assert!(
            seen.ends_with(b"AFTERTAIL"),
            "소비가 빈틈 타이머를 되감으면 안 된다: {seen:?}"
        );
    }

    /// 반대로, 정말 오래 메워지지 않은 빈틈은 포기해야 한다.
    #[test]
    fn a_gap_is_skipped_only_after_it_has_aged() {
        let mut r = TcpReassembler::<()>::new();
        let flow = flow();

        r.push(flow, 1000, b"HEAD", t0());
        r.drain_client(&flow, |(): &mut (), _: &[u8]| ((), Consumed::synced(4)))
            .unwrap();

        // 빈틈 너머 세그먼트가 도착한다. 아직은 기다린다.
        r.push(flow, 1104, b"AFTER", t0());
        let seen = r
            .drain_client(&flow, |(): &mut (), b: &[u8]| {
                (b.to_vec(), Consumed::nothing())
            })
            .unwrap();
        assert!(seen.is_empty(), "갓 생긴 빈틈은 아직 기다린다");

        // 빈틈이 늙은 뒤에는 건너뛴다.
        let later = t0() + TimeDelta::seconds(GAP_TIMEOUT_SECS + 1);
        r.push(flow, 1109, b"MORE", later);
        let seen = r
            .drain_client(&flow, |(): &mut (), b: &[u8]| {
                (b.to_vec(), Consumed::nothing())
            })
            .unwrap();
        assert_eq!(seen, b"AFTERMORE", "늙은 빈틈은 건너뛴다");
    }

    /// 캡처 지점에서 패킷이 유실되면 그 바이트는 재전송되지 않는다. 계속 기다리면
    /// 그 플로우는 커넥션이 끝날 때까지 아무것도 내놓지 못하고, `last_seen`이
    /// 갱신되므로 유휴 축출로도 회수되지 않았다.
    #[test]
    fn an_unfillable_gap_is_skipped_instead_of_blackholing_the_flow() {
        let mut r = TcpReassembler::<()>::new();
        let flow = flow();

        r.push(flow, 1000, b"HELLO", t0());
        assert_eq!(
            r.drain_client(&flow, |(): &mut (), b: &[u8]| (
                b.to_vec(),
                Consumed::synced(b.len())
            ))
            .unwrap(),
            b"HELLO"
        );

        // seq 1005..1105 가 유실됐다. 그 뒤 데이터만 계속 도착한다.
        let mut seq = 1105;
        let mut now = t0();
        let mut seen = Vec::new();
        for _ in 0..10 {
            now += TimeDelta::seconds(1);
            r.push(flow, seq, b"AFTERGAP", now);
            seq += 8;
            seen = r
                .drain_client(&flow, |(): &mut (), b: &[u8]| {
                    (b.to_vec(), Consumed::nothing())
                })
                .unwrap();
        }
        assert!(
            !seen.is_empty(),
            "빈틈을 건너뛰고 이후 데이터를 내놓아야 한다"
        );
    }

    /// 전진하지 못하는 플로우는 세그먼트가 계속 와도 회수되어야 한다.
    #[test]
    fn stalled_flows_are_evicted_even_while_packets_keep_arriving() {
        let mut r = TcpReassembler::<()>::new();
        let flow = flow();

        r.push(flow, 1000, b"HEAD", t0());
        r.drain_client(&flow, |(): &mut (), _: &[u8]| ((), Consumed::synced(4)))
            .unwrap();

        // 빈틈 너머의 세그먼트만 계속, 아주 오랫동안 도착한다.
        for i in 0..40 {
            let now = t0() + TimeDelta::seconds(i * 10);
            r.push(flow, 0x0010_0000, b"X", now);
            r.evict_idle(now);
        }
        assert_eq!(r.flow_count(), 0, "전진하지 못하는 플로우는 회수된다");
    }

    /// 플로우 개수에 상한이 없으면 포트를 흩뿌리는 트래픽이 메모리를 무한정 쓴다.
    #[test]
    fn flow_count_is_capped() {
        let mut r = TcpReassembler::<()>::new();
        for port in 0..u32::try_from(MAX_FLOWS).unwrap() + 500 {
            let [_, _, hi, lo] = port.to_be_bytes();
            let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, hi, lo)), 40000);
            let (flow, _) = FlowId::classify(client, ep(2, 1433)).unwrap();
            r.push(flow, 1, b"x", t0());
        }
        assert!(
            r.flow_count() <= MAX_FLOWS,
            "플로우가 {}개까지 늘었다",
            r.flow_count()
        );
    }

    /// 시계가 뒤로 조정되어 미래 타임스탬프가 한 번 들어오면, 단순 뺄셈으로는
    /// 이후 델타가 계속 음수가 되어 청소가 영영 멈춘다.
    #[test]
    fn a_future_timestamp_does_not_disable_sweeping() {
        let mut r = TcpReassembler::<()>::new();
        r.push(flow(), 1, b"x", t0());

        // 미래에서 온 패킷이 last_sweep을 오염시킨다.
        r.evict_idle(t0() + TimeDelta::days(365));
        // 정상 시각으로 돌아와도 청소가 계속되어야 한다.
        r.evict_idle(t0() + TimeDelta::seconds(IDLE_TIMEOUT_SECS + 1));
        assert_eq!(r.flow_count(), 0);
    }
}

#[cfg(test)]
mod parser_state_tests {
    use super::*;
    use chrono::TimeDelta;
    use std::net::{IpAddr, Ipv4Addr};

    fn ep(last_octet: u8, port: u16) -> Endpoint {
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)), port)
    }

    fn flow() -> FlowId {
        FlowId::classify(ep(1, 50000), ep(2, 1433)).unwrap().0
    }

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    /// 상위 파서가 들고 있는 조립 상태를 흉내낸다.
    #[derive(Default, Debug, PartialEq, Eq)]
    struct FakeParser {
        half_message: Vec<u8>,
    }

    /// 포트 재사용으로 스트림이 끊기면, 이전 커넥션의 반쪽 메시지를 그대로 들고
    /// 있으면 안 된다. 그러지 않으면 새 데이터와 이어붙어 SQL이 오염된다.
    #[test]
    fn parser_state_is_reset_when_the_stream_is_rebased() {
        let mut r = TcpReassembler::<FakeParser>::new();
        let flow = flow();

        r.push(flow, 1000, b"FIRSTCONN", t0());
        r.drain_client(&flow, |p: &mut FakeParser, buf: &[u8]| {
            p.half_message.extend_from_slice(buf);
            ((), Consumed::synced(buf.len()))
        })
        .unwrap();

        // 같은 4-tuple을 재사용하는 새 커넥션.
        let later = t0() + TimeDelta::seconds(1);
        r.push(flow, 0x8000_0000, b"SECONDCONN", later);
        let leftover = r
            .drain_client(&flow, |p: &mut FakeParser, _: &[u8]| {
                (p.half_message.clone(), Consumed::nothing())
            })
            .unwrap();

        assert!(
            leftover.is_empty(),
            "이전 커넥션의 조각이 남으면 안 된다: {leftover:?}"
        );
    }

    /// 메울 수 없는 빈틈을 건너뛴 뒤에도 마찬가지다.
    #[test]
    fn parser_state_is_reset_when_a_gap_is_skipped() {
        let mut r = TcpReassembler::<FakeParser>::new();
        let flow = flow();

        r.push(flow, 1000, b"HEAD", t0());
        r.drain_client(&flow, |p: &mut FakeParser, buf: &[u8]| {
            p.half_message.extend_from_slice(buf);
            ((), Consumed::synced(buf.len()))
        })
        .unwrap();

        // 빈틈 너머 세그먼트가 오고, 빈틈이 늙어 건너뛰어진다.
        r.push(flow, 1104, b"AFTER", t0());
        r.drain_client(&flow, |_: &mut FakeParser, _: &[u8]| {
            ((), Consumed::nothing())
        })
        .unwrap();
        let later = t0() + TimeDelta::seconds(GAP_TIMEOUT_SECS + 1);
        r.push(flow, 1109, b"MORE", later);

        let leftover = r
            .drain_client(&flow, |p: &mut FakeParser, _: &[u8]| {
                (p.half_message.clone(), Consumed::nothing())
            })
            .unwrap();
        assert!(
            leftover.is_empty(),
            "빈틈을 건너뛴 뒤에 조각이 남으면 안 된다: {leftover:?}"
        );
    }

    /// 정상적으로 이어지는 스트림에서는 상태가 유지되어야 한다.
    /// (멀티패킷 메시지 조립이 여기에 달려 있다.)
    #[test]
    fn parser_state_survives_a_continuous_stream() {
        let mut r = TcpReassembler::<FakeParser>::new();
        let flow = flow();

        r.push(flow, 1000, b"AAAA", t0());
        r.drain_client(&flow, |p: &mut FakeParser, buf: &[u8]| {
            p.half_message.extend_from_slice(buf);
            ((), Consumed::synced(buf.len()))
        })
        .unwrap();

        r.push(flow, 1004, b"BBBB", t0());
        let kept = r
            .drain_client(&flow, |p: &mut FakeParser, buf: &[u8]| {
                p.half_message.extend_from_slice(buf);
                (p.half_message.clone(), Consumed::synced(buf.len()))
            })
            .unwrap();
        assert_eq!(kept, b"AAAABBBB", "연속 스트림에서는 상태가 유지된다");
    }
}

#[cfg(test)]
mod round5_tests {
    use super::*;
    use chrono::TimeDelta;
    use std::net::{IpAddr, Ipv4Addr};

    fn flow() -> FlowId {
        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        FlowId::classify(client, server).unwrap().0
    }

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    /// 세그먼트 하나가 유실되면 그 뒤 데이터는 전부 보관 대기열로 간다.
    /// 대기열을 **개수**로 제한하고 가장 나중 것부터 버리면, 이미 캡처한(그리고
    /// 다시 오지 않을) 데이터를 회선 속도로 흘려보내게 된다.
    #[test]
    fn a_lost_segment_does_not_discard_the_data_that_follows_it() {
        let mut r = TcpReassembler::<()>::new();
        let flow = flow();
        let segment = vec![0xEE; 1460];

        // 첫 세그먼트가 유실됐다고 가정하고, 그 뒤 500개가 순서대로 도착한다.
        let mut next = 1000u32.wrapping_add(1460);
        let mut sent = 0usize;
        for i in 0..500 {
            let now = t0() + TimeDelta::milliseconds(i * 5);
            r.push(flow, next, &segment, now);
            next = next.wrapping_add(1460);
            sent += segment.len();
            r.drain_client(&flow, |(): &mut (), _: &[u8]| ((), Consumed::nothing()));
        }

        // 빈틈이 늙어 건너뛰어진 뒤, 남아 있던 데이터가 나와야 한다.
        let late = t0() + TimeDelta::seconds(GAP_TIMEOUT_SECS + 1);
        r.push(flow, next, &segment, late);
        sent += segment.len();
        let recovered = r
            .drain_client(&flow, |(): &mut (), b: &[u8]| {
                (b.len(), Consumed::synced(b.len()))
            })
            .unwrap();

        // 보관 상한(바이트) 안에 들어오는 양이므로 하나도 잃지 않아야 한다.
        // 개수로 제한하던 시절에는 여기서 87%가 사라졌다.
        assert_eq!(
            recovered, sent,
            "{sent}바이트 중 {recovered}바이트만 살아남았다"
        );
    }

    /// 순수 재정렬(유실 없음)로 세그먼트가 많이 밀려도 데이터를 잃으면 안 된다.
    #[test]
    fn heavy_reordering_without_loss_recovers_everything() {
        let mut r = TcpReassembler::<()>::new();
        let flow = flow();

        // 600바이트를 200개 세그먼트로 쪼개 역순으로 넣는다.
        let payload: Vec<u8> = (0..600u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let chunks: Vec<&[u8]> = payload.chunks(3).collect();
        for (i, chunk) in chunks.iter().enumerate().rev() {
            let offset = 1000u32.wrapping_add(u32::try_from(i * 3).unwrap());
            r.push(flow, offset, chunk, t0());
        }

        let recovered = r
            .drain_client(&flow, |(): &mut (), b: &[u8]| {
                (b.to_vec(), Consumed::nothing())
            })
            .unwrap();
        assert_eq!(recovered, payload, "재정렬만으로 데이터를 잃으면 안 된다");
    }

    /// 보관 바이트 수는 상한 안에 머물러야 한다.
    #[test]
    fn pending_bytes_stay_bounded() {
        let mut s = ClientStream::new(1000, t0());
        let segment = vec![0u8; 4096];
        // 절대 메워지지 않을 빈틈 뒤로 계속 쌓는다.
        for i in 0..2000u32 {
            let offset = 1000u32
                .wrapping_add(100_000)
                .wrapping_add(i.wrapping_mul(4096));
            s.push(offset, &segment, t0());
        }
        assert!(
            s.pending_bytes <= MAX_PENDING_BYTES + segment.len(),
            "보관 바이트가 {}까지 늘었다",
            s.pending_bytes
        );
    }
}

#[cfg(test)]
mod round6_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn flow() -> FlowId {
        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        FlowId::classify(client, server).unwrap().0
    }

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    /// 1바이트 세그먼트는 바이트 예산을 1만 쓰지만 실제로는 맵 노드까지 수십
    /// 바이트를 차지한다. 개수 상한이 없으면 2 MiB 예산 안에서 200만 개가 쌓여
    /// 메모리는 73배로, 빈틈 건너뛰기 비용은 패킷당 수십 ms로 뛴다.
    #[test]
    fn tiny_out_of_order_segments_cannot_explode_the_entry_count() {
        let mut s = ClientStream::new(1000, t0());
        // 절대 메워지지 않을 빈틈을 만들고, 그 뒤로 1바이트씩 띄엄띄엄 보낸다.
        for i in 0..200_000u32 {
            s.push(
                1000u32
                    .wrapping_add(1_000_000)
                    .wrapping_add(i.wrapping_mul(2)),
                b"x",
                t0(),
            );
        }
        assert!(
            s.pending.len() <= MAX_PENDING_SEGMENTS + 1,
            "보관 항목이 {}개까지 늘었다",
            s.pending.len()
        );
        assert!(s.pending_bytes <= MAX_PENDING_BYTES + 1);
    }

    /// 포화가 계속되면 대기열을 비우고 재동기화해, 패킷마다 맵을 다시 만드는
    /// 상태에 갇히지 않아야 한다.
    #[test]
    fn a_permanently_saturated_queue_is_dropped_and_resynced() {
        let mut r = TcpReassembler::<()>::new();
        let flow = flow();

        for i in 0..u32::try_from(MAX_PENDING_SEGMENTS).unwrap() * 3 {
            r.push(
                flow,
                1000u32
                    .wrapping_add(1_000_000)
                    .wrapping_add(i.wrapping_mul(2)),
                b"x",
                t0(),
            );
        }
        // 이어지는 데이터는 정상적으로 받아야 한다.
        r.push(flow, 1000, b"HELLO", t0());
        let seen = r
            .drain_client(&flow, |(): &mut (), b: &[u8]| {
                (b.to_vec(), Consumed::nothing())
            })
            .unwrap();
        assert_eq!(seen, b"HELLO", "재동기화 후 정상 데이터를 받아야 한다");
    }
}

#[cfg(test)]
mod round7_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn flow() -> FlowId {
        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        FlowId::classify(client, server).unwrap().0
    }

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    /// 캡처 지점 유실은 몰려서 일어나므로 빈틈이 둘 이상 겹치는 것이 흔하다.
    /// 한 번만 건너뛰면 빈틈 사이의 짧은 구간만 흡수하고, 그 뒤의 큰 연속 구간은
    /// 바이트 압박으로 폐기되어 이미 캡처한 SQL 수 MB가 사라졌다.
    #[test]
    fn two_adjacent_holes_do_not_cost_the_data_after_them() {
        let mut s = ClientStream::new(1000, t0());

        // 빈틈 A(1000..1005) 뒤의 짧은 구간
        s.push(1005, &[0xAA; 16], t0());
        // 빈틈 B(1021..1100) 뒤로 큰 연속 구간이 이어진다
        let segment = vec![0xBB; 1460];
        let mut seq = 1100u32;
        let mut sent = 0usize;
        while sent < MAX_PENDING_BYTES + 4096 {
            s.push(seq, &segment, t0());
            seq = seq.wrapping_add(1460);
            sent += segment.len();
        }

        assert!(
            s.unconsumed().len() >= MAX_PENDING_BYTES,
            "빈틈 두 개가 겹쳤다고 {}바이트만 남으면 안 된다",
            s.unconsumed().len()
        );
    }

    /// 반면 이어붙일 수 없는 조각만 잔뜩 쌓이면 폐기하고 재동기화해야 한다.
    #[test]
    fn unjoinable_fragments_are_still_dropped() {
        let mut s = ClientStream::new(1000, t0());
        for i in 0..(MAX_PENDING_SEGMENTS * 2) {
            let offset = 1000u32
                .wrapping_add(1_000_000)
                .wrapping_add(u32::try_from(i).unwrap() * 2);
            s.push(offset, b"x", t0());
        }
        assert!(
            s.pending.len() <= MAX_PENDING_SEGMENTS,
            "조각이 {}개까지 남았다",
            s.pending.len()
        );
    }

    /// 순수 재정렬(유실 없음)은 여전히 전량 복구되어야 한다.
    #[test]
    fn pure_reordering_is_unaffected_by_the_saturation_logic() {
        let mut r = TcpReassembler::<()>::new();
        let flow = flow();
        let payload: Vec<u8> = (0..20_000u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();

        for (i, chunk) in payload.chunks(20).enumerate().rev() {
            let offset = 1000u32.wrapping_add(u32::try_from(i * 20).unwrap());
            r.push(flow, offset, chunk, t0());
        }
        let seen = r
            .drain_client(&flow, |(): &mut (), b: &[u8]| {
                (b.to_vec(), Consumed::nothing())
            })
            .unwrap();
        assert_eq!(seen, payload, "재정렬만으로 데이터를 잃으면 안 된다");
    }
}

#[cfg(test)]
mod round8_tests {
    use super::*;
    use chrono::TimeDelta;
    use std::net::{IpAddr, Ipv4Addr};

    fn flow() -> FlowId {
        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        FlowId::classify(client, server).unwrap().0
    }

    fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    /// `skip_gap`은 `data.clear()`로 시작하고 `drain_pending()`으로 끝난다.
    /// 반복 호출하면, 직전 호출이 이어붙인 정상 데이터를 파서가 보기도 전에 지운다.
    #[test]
    fn repeated_skips_do_not_erase_data_they_just_reassembled() {
        let mut s = ClientStream::new(1000, t0());

        // 빈틈 뒤로 큰 연속 구간을 채워 포화시킨다.
        let segment = vec![0xCC; 1460];
        let mut seq = 1000u32.wrapping_add(5000);
        let mut sent = 0usize;
        while sent < MAX_PENDING_BYTES + 8192 {
            s.push(seq, &segment, t0());
            seq = seq.wrapping_add(1460);
            sent += segment.len();
        }

        assert!(
            !s.unconsumed().is_empty(),
            "건너뛴 뒤 이어붙인 데이터가 남아 있어야 한다"
        );
    }

    /// 빈틈을 상대 오프셋으로 식별하면, `base`가 움직였을 때 새 빈틈이 이미
    /// 만료된 빈틈의 시각을 물려받아 유예 없이 버려진다.
    #[test]
    fn a_new_gap_gets_its_own_grace_period() {
        let mut r = TcpReassembler::<()>::new();
        let flow = flow();

        // 빈틈 A를 만들고 늙힌 뒤 건너뛰게 한다.
        r.push(flow, 1000, b"HEAD", t0());
        r.drain_client(&flow, |(): &mut (), _: &[u8]| ((), Consumed::synced(4)))
            .unwrap();
        r.push(flow, 1004 + 1460, &[0xAA; 1460], t0());
        let late = t0() + TimeDelta::seconds(GAP_TIMEOUT_SECS + 1);
        r.push(flow, 1004 + 2920, &[0xBB; 1460], late);
        r.drain_client(&flow, |(): &mut (), _: &[u8]| ((), Consumed::synced(2920)))
            .unwrap();

        // 이제 막 생긴 새 빈틈은 곧바로 버려지면 안 된다.
        r.push(flow, 1004 + 5840, &[0xDD; 1460], late);
        let seen = r
            .drain_client(&flow, |(): &mut (), b: &[u8]| {
                (b.to_vec(), Consumed::nothing())
            })
            .unwrap();
        assert!(
            seen.is_empty(),
            "갓 생긴 빈틈은 유예를 받아야 한다 (앞부분을 기다린다)"
        );
    }
}
