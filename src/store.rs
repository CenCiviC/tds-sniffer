use crate::output::{short_table_name, SqlEvent, SqlOp};
use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::BuildHasher;

/// 테이블을 식별하지 못한 SQL이 모이는 그룹 이름.
pub const UNGROUPED: &str = "기타";

/// 원본 패킷 바이트를 보관할 총 예산.
///
/// 이벤트 하나가 최대 4 MiB(멀티패킷 메시지)까지 들고 있을 수 있어, 상한이
/// 없으면 hex 뷰용 데이터가 메모리의 대부분을 차지하게 된다. 예산을 넘으면
/// 원본만 버린다 — SQL과 그룹 정보는 남고, 원본은 `log/raw` 파일에 있다.
const MAX_RETAINED_RAW_BYTES: usize = 64 * 1024 * 1024;

/// 화면에 보관할 최대 고유 SQL 개수.
///
/// 상한을 넘겨도 **로그 파일에는 계속 기록한다.** 감사 기록을 잃지 않으면서
/// 메모리는 유계로 유지하는 절충이다. 넘긴 뒤에는 해시 표식만 남겨 같은 SQL이
/// 반복 기록되는 것을 막는다(고유 SQL당 몇십 바이트).
const MAX_EVENTS: usize = 50_000;

/// 화면에 보관할 SQL 텍스트 총량.
///
/// 원본 예산(`MAX_RETAINED_RAW_BYTES`)은 hex용 바이트만 막는다. 멀티패킷 배치
/// 하나가 수 MB짜리 SQL 텍스트를 남길 수 있으므로 텍스트도 따로 제한한다.
const MAX_RETAINED_TEXT_BYTES: usize = 128 * 1024 * 1024;

/// 중복 판정용 색인이 가질 수 있는 최대 항목 수.
///
/// 상한을 넘긴 SQL의 표식까지 영원히 쌓이면 그 자체가 무한 증가가 된다. 색인이
/// 가득 차면 새 표식을 만들지 않는다 — 그 뒤로는 같은 SQL이 다시 나타날 때
/// 로그에 한 번 더 기록될 수 있지만, 메모리는 유계로 유지된다.
const MAX_SQL_INDEX_ENTRIES: usize = 200_000;

/// 테이블 그룹의 최대 개수.
///
/// 그룹 수는 SQL이 정한다 — `JOIN`이 잔뜩 붙은 배치 하나가 수만 개를 만들 수
/// 있다. 상한을 넘으면 새 이름은 [`UNGROUPED`]로 모으므로, 실제 그룹 수는
/// 이 값에 초과분을 담는 기타 버킷 하나를 더한 만큼이 최대다. 화면 렌더
/// 상한만으로는 색인 자체가 자라는 것을 막지 못한다.
const MAX_TABLE_GROUPS: usize = 2000;

/// 고유 SQL 이벤트를 가리키는 인덱스.
///
/// 벌거벗은 `usize` 대신 뉴타입을 써서 다른 정수와 섞이지 않게 한다. 내부 필드가
/// 비공개라 저장소 밖에서 새로 만들어낼 수 없다.
/// `Rc<RefCell<SqlEvent>>` 대신 인덱스를 쓰는 아레나 패턴이라 소유자는 하나뿐이다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventIdx(usize);

/// 고유 SQL 이벤트 저장소와 그룹 인덱스.
///
/// **읽기 전용 도메인 데이터**만 소유한다. UI 선택 상태나 IO 핸들을 섞지 않기
/// 때문에 `&EventStore`와 `&mut Selection`을 동시에 빌릴 수 있고, 그래서
/// 렌더링 경로에서 방어적 `clone`이 필요 없다.
#[derive(Debug, Default)]
pub struct EventStore {
    events: Vec<SqlEvent>,
    /// SQL 텍스트 해시 -> 같은 해시를 가진 이벤트들.
    ///
    /// SQL 전문을 키로 복사해 두면 모든 쿼리가 메모리에 두 벌 존재한다. 해시만
    /// 보관하고 실제 비교는 저장된 이벤트로 한다. 버킷을 `Vec`으로 둔 이유는
    /// 해시 충돌이 나도 두 텍스트가 모두 색인되게 하기 위해서다 — 하나만
    /// 보관하면 충돌한 쪽이 영영 중복 제거되지 않고 계속 다시 쌓인다.
    by_sql: HashMap<u64, Vec<EventIdx>>,
    /// 테이블 그룹. `BTreeMap`이라 정렬된 순회가 공짜이며, 이름을 두 벌
    /// 보관하던 별도의 정렬 목록이 필요 없다. 정렬 `Vec`에 삽입하던 예전
    /// 방식은 그룹 하나당 O(n) 메모리 이동이라 그룹 수에 대해 제곱으로 느려졌다.
    by_table: BTreeMap<String, Vec<EventIdx>>,
    by_op: HashMap<SqlOp, Vec<EventIdx>>,
    all: Vec<EventIdx>,
    /// 현재 보관 중인 원본 패킷 바이트 총량.
    retained_raw_bytes: usize,
    /// 그룹 상한을 넘겨 기타로 접힌 테이블 이름의 수.
    overflow_table_names: usize,
    /// 상한을 넘겨 화면에는 담지 못한 SQL의 해시.
    ///
    /// 저장된 이벤트와 달리 텍스트가 없어 해시로만 비교한다. 저장된 쪽은
    /// `by_sql`에서 실제 텍스트로 비교하므로 해시 충돌에 안전하다.
    over_capacity_keys: HashSet<u64>,
    /// 상한을 넘겨 화면에는 담지 못한 고유 SQL 개수 (로그에는 남아 있다).
    over_capacity: usize,
    /// 현재 보관 중인 SQL 텍스트 총량.
    retained_text_bytes: usize,
    /// 해시 시드. 프로세스마다 달라야 충돌을 미리 계산할 수 없다.
    hasher: RandomState,
}

impl EventStore {
    /// 새 SQL이면 저장하고, **저장 직전의 온전한 이벤트**를 `on_new`에 넘긴다.
    ///
    /// 로깅을 이 안에서 하도록 만든 이유는 순서 때문이다. 원본 보관 예산에 걸려
    /// hex 바이트를 버리더라도 로그 파일에는 남아야 하는데, 호출자가 "로그 먼저,
    /// 그다음 저장"을 지키도록 맡기면 지켜지지 않는다.
    ///
    /// `on_new`의 첫 인자는 저장된 인덱스다. 개수 상한을 넘겨 화면에는 담지 못한
    /// 경우 `None`이며, 그래도 로깅은 일어난다.
    pub fn insert_with<T>(
        &mut self,
        mut event: SqlEvent,
        on_new: impl FnOnce(Option<EventIdx>, &SqlEvent) -> T,
    ) -> Option<T> {
        let key = self.sql_hash(event.sql());
        // 저장된 것과는 실제 텍스트로 비교한다 (해시 충돌에 안전).
        if self
            .by_sql
            .get(&key)
            .is_some_and(|bucket| bucket.iter().any(|i| self.events[i.0].sql() == event.sql()))
        {
            return None;
        }
        // 상한을 넘겨 저장하지 않은 것과는 해시로만 비교한다.
        if self.over_capacity_keys.contains(&key) {
            return None;
        }

        let text_len = event.sql().len();
        if self.events.len() >= MAX_EVENTS
            || self.retained_text_bytes + text_len > MAX_RETAINED_TEXT_BYTES
        {
            // 화면에는 담지 않지만 기록은 남긴다. 색인에 여유가 있으면 표식을
            // 남겨 같은 SQL이 반복 기록되는 것을 막는다.
            if self.index_len() < MAX_SQL_INDEX_ENTRIES {
                self.over_capacity_keys.insert(key);
            }
            self.over_capacity += 1;
            return Some(on_new(None, &event));
        }

        let idx = EventIdx(self.events.len());

        // 원본이 온전한 상태에서 먼저 알린다.
        let result = on_new(Some(idx), &event);

        // 그다음 원본 보관 예산을 적용한다. 넘기면 hex 표시용 바이트만 버린다.
        let raw_len = event.raw().len();
        if self.retained_raw_bytes + raw_len > MAX_RETAINED_RAW_BYTES {
            event.forget_raw();
        } else {
            self.retained_raw_bytes += raw_len;
        }

        // `short_table_name`은 순서를 보존하지 않으므로 다시 정렬해 중복을 없앤다.
        // 서로 다른 스키마의 같은 테이블이 한 그룹으로 접힐 수 있기 때문이다.
        let mut names: Vec<String> = event
            .tables()
            .iter()
            .map(|t| short_table_name(t).to_string())
            .collect();
        names.sort_unstable();
        names.dedup();
        let ops = event.ops().to_vec();

        // 이벤트를 먼저 저장한 뒤에 인덱스를 공개한다. 반대 순서면 `on_new`가
        // 되감기는 순간 "색인의 모든 EventIdx는 유효하다"는 불변식이 깨진다.
        self.events.push(event);
        self.retained_text_bytes += text_len;

        self.by_sql.entry(key).or_default().push(idx);
        self.all.push(idx);
        for op in ops {
            self.by_op.entry(op).or_default().push(idx);
        }
        if names.is_empty() {
            self.push_table(UNGROUPED, idx);
        } else {
            for name in names {
                self.push_table(&name, idx);
            }
        }

        Some(result)
    }

    /// 이벤트를 추가한다. 저장된 경우에만 그 인덱스를 돌려준다.
    pub fn insert(&mut self, event: SqlEvent) -> Option<EventIdx> {
        self.insert_with(event, |idx, _| idx).flatten()
    }

    /// 상한을 넘겨 화면에 담지 못한 고유 SQL 개수.
    #[must_use]
    pub const fn over_capacity(&self) -> usize {
        self.over_capacity
    }

    /// 중복 판정 색인이 들고 있는 총 항목 수.
    fn index_len(&self) -> usize {
        self.by_sql.len() + self.over_capacity_keys.len()
    }

    fn sql_hash(&self, text: &str) -> u64 {
        self.hasher.hash_one(text)
    }

    /// 그룹에 인덱스를 등록한다. 이름은 **새 그룹일 때만** 할당한다.
    ///
    /// 한 이벤트가 같은 그룹에 두 번 들어가지 않도록 마지막 항목을 확인한다.
    /// 그룹 상한을 넘긴 뒤에는 서로 다른 이름이 모두 기타로 접히므로, 이 검사가
    /// 없으면 같은 이벤트가 이름 수만큼 중복 등록된다.
    fn push_table(&mut self, name: &str, idx: EventIdx) {
        if let Some(group) = self.by_table.get_mut(name) {
            if group.last() != Some(&idx) {
                group.push(idx);
            }
            return;
        }
        // 그룹 상한을 넘으면 새 이름을 만들지 않고 기타로 모은다.
        let name = if self.by_table.len() >= MAX_TABLE_GROUPS {
            self.overflow_table_names += 1;
            UNGROUPED
        } else {
            name
        };
        let group = self.by_table.entry(name.to_string()).or_default();
        if group.last() != Some(&idx) {
            group.push(idx);
        }
    }

    /// 저장소를 비운다.
    ///
    /// 기존 [`EventIdx`]는 모두 무효가 된다. [`Self::get`]이 `Option`을 돌려주므로
    /// 무효 인덱스로 접근해도 패닉 대신 `None`이 나온다.
    pub fn clear(&mut self) {
        self.events.clear();
        self.by_sql.clear();
        self.by_table.clear();
        self.by_op.clear();
        self.all.clear();
        self.retained_raw_bytes = 0;
        self.retained_text_bytes = 0;
        self.over_capacity = 0;
        self.over_capacity_keys.clear();
        self.overflow_table_names = 0;
    }

    /// 인덱스에 해당하는 이벤트. 저장소를 비운 뒤의 오래된 인덱스면 `None`.
    #[must_use]
    pub fn get(&self, idx: EventIdx) -> Option<&SqlEvent> {
        self.events.get(idx.0)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// 테이블 그룹을 이름순으로 순회한다. 복사가 없다.
    pub fn table_groups(&self) -> impl Iterator<Item = (&str, &[EventIdx])> {
        self.by_table
            .iter()
            .map(|(name, group)| (name.as_str(), group.as_slice()))
    }

    /// 테이블 그룹 개수.
    #[must_use]
    pub fn table_group_count(&self) -> usize {
        self.by_table.len()
    }

    /// 그룹 상한을 넘겨 기타로 접힌 테이블 이름의 수.
    #[must_use]
    pub const fn overflow_table_names(&self) -> usize {
        self.overflow_table_names
    }

    #[must_use]
    pub fn table_group(&self, name: &str) -> &[EventIdx] {
        self.by_table.get(name).map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn op_group(&self, op: SqlOp) -> &[EventIdx] {
        self.by_op.get(&op).map_or(&[], Vec::as_slice)
    }

    /// 전체 이벤트 인덱스.
    #[must_use]
    pub fn all(&self) -> &[EventIdx] {
        &self.all
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::{Endpoint, FlowId};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn flow() -> FlowId {
        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        FlowId::classify(client, server).unwrap().0
    }

    fn event(sql: &str) -> SqlEvent {
        SqlEvent::new(Utc::now(), flow(), sql.to_string(), Vec::new())
    }

    #[test]
    fn duplicate_sql_is_reported_once() {
        let mut store = EventStore::default();
        assert!(store.insert(event("SELECT * FROM dbo.TB_A")).is_some());
        assert!(
            store.insert(event("SELECT * FROM dbo.TB_A")).is_none(),
            "중복은 None이어야 로깅이 반복되지 않는다"
        );
        assert_eq!(store.len(), 1);
    }

    /// 원본은 "새 이벤트인가"를 `idx == len - 1`로 추측해서, 직전 SQL이 반복되면
    /// 같은 항목을 로그 파일에 계속 다시 썼다.
    #[test]
    fn repeating_the_most_recent_sql_is_still_a_duplicate() {
        let mut store = EventStore::default();
        store.insert(event("SELECT 1 FROM dbo.TB_A"));
        store.insert(event("SELECT 2 FROM dbo.TB_B"));
        assert!(store.insert(event("SELECT 2 FROM dbo.TB_B")).is_none());
        assert_eq!(store.len(), 2);
    }

    /// 해시 버킷을 하나만 보관하면 충돌한 두 번째 텍스트가 색인되지 않아
    /// 나타날 때마다 다시 삽입되고 다시 로깅된다.
    #[test]
    fn hash_collisions_do_not_break_deduplication() {
        let mut store = EventStore::default();
        let neighbour = store.insert(event("SELECT 1 FROM dbo.TB_A")).unwrap();

        // 서로 다른 텍스트가 같은 해시 버킷에 들어간 상황을 강제로 만든다.
        let target = event("SELECT 2 FROM dbo.TB_B");
        let key = store.sql_hash(target.sql());
        store.by_sql.entry(key).or_default().push(neighbour);

        // 이웃이 있어도 새 SQL은 중복이 아니며 같은 버킷에 색인되어야 한다.
        assert!(
            store.insert(target).is_some(),
            "다른 텍스트를 중복으로 오인하면 안 된다"
        );
        assert!(
            store.insert(event("SELECT 2 FROM dbo.TB_B")).is_none(),
            "충돌 버킷에 색인된 항목도 다음번엔 중복으로 인식해야 한다"
        );
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn events_are_grouped_by_table_and_operation() {
        let mut store = EventStore::default();
        store.insert(event("SELECT * FROM dbo.TB_Users"));
        store.insert(event("UPDATE dbo.TB_Users SET name = 'x'"));
        store.insert(event("INSERT INTO dbo.TB_Logs VALUES (1)"));

        assert_eq!(store.table_group("Users").len(), 2);
        assert_eq!(store.table_group("Logs").len(), 1);
        assert_eq!(store.op_group(SqlOp::Select).len(), 1);
        assert_eq!(store.op_group(SqlOp::Update).len(), 1);
        assert_eq!(store.op_group(SqlOp::Insert).len(), 1);
    }

    /// 같은 그룹 이름이 한 이벤트에서 두 번 나와도 한 번만 등록되어야 한다.
    #[test]
    fn a_table_group_lists_each_event_once() {
        let mut store = EventStore::default();
        store.insert(event(
            "SELECT * FROM dbo.TB_Users u JOIN other.TB_Users o ON u.id = o.id",
        ));
        assert_eq!(store.table_group("Users").len(), 1);
    }

    #[test]
    fn table_names_are_kept_in_sorted_order() {
        let mut store = EventStore::default();
        store.insert(event("SELECT * FROM dbo.TB_Zebra"));
        store.insert(event("SELECT * FROM dbo.TB_Apple"));
        store.insert(event("SELECT * FROM dbo.TB_Mango"));
        let names: Vec<&str> = store.table_groups().map(|(name, _)| name).collect();
        assert_eq!(names, ["Apple", "Mango", "Zebra"]);
    }

    #[test]
    fn untabled_sql_falls_into_the_ungrouped_bucket() {
        let mut store = EventStore::default();
        store.insert(event("EXEC sp_who2"));
        assert_eq!(store.table_group(UNGROUPED).len(), 1);
    }

    #[test]
    fn missing_group_yields_an_empty_slice() {
        let store = EventStore::default();
        assert!(store.table_group("없는테이블").is_empty());
        assert!(store.op_group(SqlOp::Delete).is_empty());
    }

    #[test]
    fn clear_resets_every_index() {
        let mut store = EventStore::default();
        let idx = store.insert(event("SELECT * FROM dbo.TB_Users")).unwrap();
        store.clear();

        assert!(store.is_empty());
        assert_eq!(store.table_group_count(), 0);
        assert!(store.all().is_empty());
        assert!(
            store.get(idx).is_none(),
            "비운 뒤의 오래된 인덱스는 패닉 대신 None이어야 한다"
        );
        assert!(store.insert(event("SELECT * FROM dbo.TB_Users")).is_some());
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    use crate::tcp::{Endpoint, FlowId};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn event(sql: &str, raw_len: usize) -> SqlEvent {
        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        let flow = FlowId::classify(client, server).unwrap().0;
        SqlEvent::new(Utc::now(), flow, sql.to_string(), vec![0xAB; raw_len])
    }

    /// 원본 바이트 보관량은 상한을 넘지 않아야 한다. 넘으면 hex 표시용 바이트만
    /// 버리고 SQL과 그룹 정보는 그대로 남는다.
    #[test]
    fn raw_retention_is_capped_without_losing_sql() {
        let mut store = EventStore::default();
        let chunk = 4 * 1024 * 1024;
        let count = MAX_RETAINED_RAW_BYTES / chunk + 4;

        for i in 0..count {
            store.insert(event(&format!("SELECT {i} FROM dbo.TB_A"), chunk));
        }

        assert_eq!(store.len(), count, "SQL은 하나도 잃지 않는다");
        assert!(
            store.retained_raw_bytes <= MAX_RETAINED_RAW_BYTES,
            "보관량 {}바이트",
            store.retained_raw_bytes
        );
        // 예산 안의 앞쪽 이벤트는 원본을 그대로 들고 있다.
        assert!(!store.get(EventIdx(0)).unwrap().raw().is_empty());
        // 예산을 넘긴 뒤의 이벤트는 원본을 버렸지만 SQL은 온전하다.
        let last = store.get(EventIdx(count - 1)).unwrap();
        assert!(last.raw().is_empty());
        assert!(last.sql().starts_with("SELECT"));
    }

    #[test]
    fn clear_resets_the_raw_budget() {
        let mut store = EventStore::default();
        store.insert(event("SELECT 1 FROM dbo.TB_A", 1024));
        assert_eq!(store.retained_raw_bytes, 1024);
        store.clear();
        assert_eq!(store.retained_raw_bytes, 0);
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    use crate::tcp::{Endpoint, FlowId};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn event(sql: &str, raw_len: usize) -> SqlEvent {
        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        let flow = FlowId::classify(client, server).unwrap().0;
        SqlEvent::new(Utc::now(), flow, sql.to_string(), vec![0xAB; raw_len])
    }

    /// 보관 예산에 걸려 hex를 버리더라도, 콜백은 **버리기 전에** 온전한 이벤트를
    /// 받아야 한다. 그러지 않으면 로그 파일의 원본 섹션이 조용히 사라진다.
    #[test]
    fn the_callback_sees_raw_bytes_before_the_budget_trims_them() {
        let mut store = EventStore::default();
        let chunk = 4 * 1024 * 1024;
        let count = MAX_RETAINED_RAW_BYTES / chunk + 4;

        let mut with_raw = 0usize;
        for i in 0..count {
            store.insert_with(
                event(&format!("SELECT {i} FROM dbo.TB_A"), chunk),
                |_, e| {
                    if !e.raw().is_empty() {
                        with_raw += 1;
                    }
                },
            );
        }

        assert_eq!(
            with_raw, count,
            "예산을 넘긴 이벤트도 로깅 시점에는 원본을 갖고 있어야 한다"
        );
        assert!(store.retained_raw_bytes <= MAX_RETAINED_RAW_BYTES);
    }

    /// 개수 상한을 넘겨도 로깅은 계속되고, 같은 SQL이 반복 기록되지는 않는다.
    #[test]
    fn over_capacity_events_are_still_reported_once_each() {
        let mut store = EventStore::default();
        for i in 0..MAX_EVENTS {
            store.insert(event(&format!("SELECT {i} FROM dbo.TB_A"), 0));
        }
        assert_eq!(store.len(), MAX_EVENTS);

        let mut logged = 0usize;
        for _ in 0..3 {
            store.insert_with(event("SELECT 'over' FROM dbo.TB_B", 0), |idx, _| {
                assert!(idx.is_none(), "상한을 넘으면 저장하지 않는다");
                logged += 1;
            });
        }
        assert_eq!(logged, 1, "상한을 넘어도 같은 SQL은 한 번만 기록한다");
        assert_eq!(store.over_capacity(), 1);
        assert_eq!(store.len(), MAX_EVENTS, "저장소는 상한에서 멈춘다");
    }

    /// 해시 시드는 프로세스마다 달라야 충돌을 미리 계산할 수 없다.
    #[test]
    fn hash_seed_differs_between_stores() {
        let a = EventStore::default();
        let b = EventStore::default();
        assert_ne!(
            a.sql_hash("SELECT 1 FROM dbo.TB_A"),
            b.sql_hash("SELECT 1 FROM dbo.TB_A"),
            "고정 시드면 충돌을 미리 만들어 낼 수 있다"
        );
    }
}

#[cfg(test)]
mod round5_tests {
    use super::*;
    use crate::tcp::{Endpoint, FlowId};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn event(sql: &str) -> SqlEvent {
        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        let flow = FlowId::classify(client, server).unwrap().0;
        SqlEvent::new(Utc::now(), flow, sql.to_string(), Vec::new())
    }

    fn fill_to_capacity(store: &mut EventStore) {
        for i in 0..MAX_EVENTS {
            store.insert(event(&format!("SELECT {i} FROM dbo.TB_A")));
        }
    }

    /// 상한 초과 표식은 저장된 이벤트의 해시 버킷과 별개로 기록되어야 한다.
    /// `by_sql.entry(key).or_default()`로 표식을 남기던 방식은, 그 해시에 이미
    /// 저장된 이벤트가 있으면 아무것도 하지 않아 같은 SQL이 매번 다시 기록됐다.
    #[test]
    fn an_over_capacity_statement_is_reported_once_even_on_a_busy_hash() {
        let mut store = EventStore::default();
        fill_to_capacity(&mut store);

        let over = event("SELECT 'over' FROM dbo.TB_B");
        let key = store.sql_hash(over.sql());
        // 이 해시 버킷에 이미 저장된 이벤트가 있는 상황을 강제로 만든다.
        store.by_sql.entry(key).or_default().push(EventIdx(0));

        let mut logged = 0usize;
        for _ in 0..5 {
            store.insert_with(event("SELECT 'over' FROM dbo.TB_B"), |idx, _| {
                assert!(idx.is_none());
                logged += 1;
            });
        }
        assert_eq!(logged, 1, "버킷이 비어 있지 않아도 표식이 남아야 한다");
    }

    /// 텍스트 예산을 넘겨도 로깅은 계속되고 저장만 멈춘다.
    #[test]
    fn the_text_budget_stops_storing_but_not_logging() {
        let mut store = EventStore::default();
        let big = "x".repeat(1024 * 1024);
        let mut logged = 0usize;

        for i in 0..(MAX_RETAINED_TEXT_BYTES / big.len() + 4) {
            store.insert_with(
                event(&format!("SELECT '{big}' , {i} FROM dbo.TB_A")),
                |_, _| {
                    logged += 1;
                },
            );
        }

        assert!(store.retained_text_bytes <= MAX_RETAINED_TEXT_BYTES);
        assert!(
            logged > store.len(),
            "저장은 멈춰도 기록은 계속되어야 한다 (기록 {logged}, 저장 {})",
            store.len()
        );
        assert!(store.over_capacity() > 0);
    }

    /// 표식 색인도 무한히 자라면 안 된다.
    #[test]
    fn the_dedup_index_is_bounded() {
        let mut store = EventStore::default();
        fill_to_capacity(&mut store);
        for i in 0..(MAX_SQL_INDEX_ENTRIES + 10_000) {
            store.insert(event(&format!("SELECT over{i} FROM dbo.TB_B")));
        }
        assert!(
            store.index_len() <= MAX_SQL_INDEX_ENTRIES + 1,
            "색인이 {}개까지 늘었다",
            store.index_len()
        );
    }

    #[test]
    fn clear_resets_every_budget() {
        let mut store = EventStore::default();
        store.insert(event("SELECT 1 FROM dbo.TB_A"));
        store.clear();
        assert_eq!(store.retained_text_bytes, 0);
        assert_eq!(store.retained_raw_bytes, 0);
        assert_eq!(store.over_capacity(), 0);
        assert!(store.over_capacity_keys.is_empty());
    }
}

#[cfg(test)]
mod round6_tests {
    use super::*;
    use crate::tcp::{Endpoint, FlowId};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn event(sql: &str) -> SqlEvent {
        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        let flow = FlowId::classify(client, server).unwrap().0;
        SqlEvent::new(Utc::now(), flow, sql.to_string(), Vec::new())
    }

    /// 그룹 수는 SQL이 정한다. `JOIN`이 잔뜩 붙은 배치 하나가 수만 개를 만들 수
    /// 있고, 색인에 상한이 없으면 정렬 삽입 비용이 제곱으로 늘어난다.
    #[test]
    fn table_group_count_is_bounded() {
        let mut store = EventStore::default();
        for chunk in 0..40 {
            let mut joins = String::new();
            for i in 0..200 {
                use std::fmt::Write as _;
                let _ = write!(joins, " JOIN dbo.TB_t{chunk}_{i}");
            }
            store.insert(event(&format!("SELECT * FROM dbo.TB_base{joins}")));
        }
        assert!(
            // 상한 + 초과분을 담는 기타 버킷 하나.
            store.table_group_count() <= MAX_TABLE_GROUPS + 1,
            "그룹이 {}개까지 늘었다",
            store.table_group_count()
        );
        // 상한을 넘어도 이벤트 자체는 기타 그룹으로 계속 찾을 수 있다.
        assert!(!store.table_group(UNGROUPED).is_empty());
    }

    /// 그룹 순회는 이름순이어야 한다 (별도의 정렬 목록 없이).
    #[test]
    fn groups_iterate_in_name_order() {
        let mut store = EventStore::default();
        store.insert(event("SELECT * FROM dbo.TB_Zebra"));
        store.insert(event("SELECT * FROM dbo.TB_Apple"));
        store.insert(event("SELECT * FROM dbo.TB_Mango"));
        let names: Vec<&str> = store.table_groups().map(|(name, _)| name).collect();
        assert_eq!(names, ["Apple", "Mango", "Zebra"]);
    }

    /// 색인의 모든 `EventIdx`는 항상 유효해야 한다 — 콜백이 되감겨도.
    #[test]
    fn indices_are_published_only_after_the_event_is_stored() {
        let mut store = EventStore::default();
        let seen = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.insert_with(event("SELECT * FROM dbo.TB_A"), |_, _| {
                panic!("콜백이 되감긴다");
            })
        }));
        assert!(seen.is_err());
        // 색인에 죽은 인덱스가 남지 않았어야 한다.
        assert!(store.is_empty());
        assert_eq!(store.table_group_count(), 0);
        assert!(store.all().is_empty());
    }
}

#[cfg(test)]
mod round7_tests {
    use super::*;
    use crate::tcp::{Endpoint, FlowId};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    fn event(sql: &str) -> SqlEvent {
        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        let flow = FlowId::classify(client, server).unwrap().0;
        SqlEvent::new(Utc::now(), flow, sql.to_string(), Vec::new())
    }

    /// 그룹 상한을 넘기면 서로 다른 이름이 모두 기타로 접힌다. 그때 같은 이벤트가
    /// 이름 수만큼 중복 등록되면 사이드바 개수가 부풀고 카드가 여러 번 그려진다.
    #[test]
    fn an_event_appears_once_in_the_overflow_bucket() {
        let mut store = EventStore::default();
        // 그룹을 상한까지 채운다.
        for i in 0..MAX_TABLE_GROUPS {
            store.insert(event(&format!("SELECT * FROM dbo.TB_g{i}")));
        }
        let before = store.table_group(UNGROUPED).len();

        // 새 이름 셋을 가진 쿼리 하나 — 전부 기타로 접힌다.
        store.insert(event(
            "SELECT * FROM dbo.TB_new1 JOIN dbo.TB_new2 ON 1=1 JOIN dbo.TB_new3 ON 1=1",
        ));

        assert_eq!(
            store.table_group(UNGROUPED).len(),
            before + 1,
            "이벤트 하나는 기타에 한 번만 들어가야 한다"
        );
        assert_eq!(
            store.overflow_table_names(),
            3,
            "접힌 이름 수를 세어야 한다"
        );
    }
}
