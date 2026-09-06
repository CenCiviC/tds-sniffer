use crate::tcp::FlowId;
use chrono::{DateTime, Utc};
use regex::Regex;
use std::fmt;
use std::io;
use std::sync::LazyLock;

/// SQL 문에서 식별한 작업 종류.
///
/// 문자열 대신 열거형을 쓰는 이유는 두 가지다.
/// 1. `"셀렉트"` 같은 표현 불가능한 상태를 컴파일 시점에 배제한다.
/// 2. 변형을 추가하면 `rgb()` 등의 `match`가 컴파일 에러로 누락을 알려준다.
///
/// 의도적으로 `Ord`를 구현하지 않는다. "먼저 나온 작업"은 텍스트 위치로 정해지고
/// 사이드바 표시 순서는 [`SqlOp::ALL`]로 정해지므로, 두 순서를 하나의 `Ord`에
/// 섞으면 둘 다 틀린다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SqlOp {
    Select,
    Insert,
    Update,
    Delete,
    Exec,
    /// SQL 키워드를 하나도 찾지 못한 경우.
    Other,
}

impl SqlOp {
    /// 사이드바 표시 순서이자 망라 검사를 위한 전체 목록.
    pub const ALL: [Self; 6] = [
        Self::Select,
        Self::Insert,
        Self::Update,
        Self::Delete,
        Self::Exec,
        Self::Other,
    ];

    /// UI 표시용 이름.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Exec => "EXEC",
            Self::Other => "OTHER",
        }
    }

    /// UI 색상 (r, g, b).
    #[must_use]
    pub const fn rgb(self) -> (u8, u8, u8) {
        match self {
            Self::Select => (100, 200, 100),
            Self::Insert => (100, 150, 255),
            Self::Update => (255, 200, 100),
            Self::Delete => (255, 100, 100),
            Self::Exec => (200, 100, 255),
            Self::Other => (160, 160, 160),
        }
    }

    /// 매칭된 키워드를 작업 종류로 바꾼다.
    fn from_keyword(keyword: &str) -> Self {
        match keyword.to_ascii_uppercase().as_str() {
            "SELECT" => Self::Select,
            "INSERT" => Self::Insert,
            "UPDATE" => Self::Update,
            "DELETE" => Self::Delete,
            // EXEC / EXECUTE
            _ => Self::Exec,
        }
    }
}

impl fmt::Display for SqlOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 미리보기로 보여줄 최대 글자 수.
pub const PREVIEW_CHARS: usize = 200;

/// 로그와 화면이 공유하는 타임스탬프 형식.
const TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.3f";

/// 캡처된 SQL 이벤트.
///
/// 파생 정보(테이블, 작업 종류, 표시용 문자열)는 [`SqlEvent::new`]에서 **생성
/// 시점에 한 번** 계산되고 그 뒤로 바뀌지 않는다. 모든 필드가 비공개라 원본만
/// 갈아끼워 파생 정보와 어긋나게 만드는 일 자체가 불가능하다.
///
/// 표시용 문자열까지 여기서 만드는 이유는, GUI가 매 프레임 같은 `format!`을
/// 다시 돌리기 때문이다. 불변 입력에서 나오는 값은 한 번만 계산한다.
///
/// 의도적으로 `Clone`을 유도하지 않는다. 이벤트의 소유자는 [`crate::store::EventStore`]
/// 하나뿐이고, 나머지는 인덱스로 빌려 쓴다.
#[derive(Debug)]
pub struct SqlEvent {
    timestamp: DateTime<Utc>,
    flow: FlowId,
    raw: Vec<u8>,
    sql_text: String,
    tables: Vec<String>,
    ops: Vec<SqlOp>,
    primary: SqlOp,
    timestamp_text: String,
    flow_text: String,
    /// `"테이블: a, b"` 형태. 테이블을 못 찾았으면 `None`.
    tables_text: Option<String>,
    preview: String,
}

impl SqlEvent {
    /// SQL 텍스트를 파싱해 완전히 채워진 이벤트를 만든다.
    ///
    /// 텍스트 정규화(trim)도 여기서 한 번만 한다. 호출자가 미리 다듬어 올
    /// 것이라고 기대하지 않으므로, 소비자 쪽에서 방어적으로 다시 다듬을 필요가 없다.
    #[must_use]
    pub fn new(timestamp: DateTime<Utc>, flow: FlowId, mut sql_text: String, raw: Vec<u8>) -> Self {
        trim_in_place(&mut sql_text);

        let tables = extract_tables_from_sql(&sql_text);
        let ops = extract_operations(&sql_text);
        // `extract_operations`가 비어 있지 않음을 보장하므로 첫 원소가 항상 있다.
        let primary = ops[0];

        let tables_text = (!tables.is_empty()).then(|| format!("테이블: {}", tables.join(", ")));
        Self {
            timestamp_text: timestamp.format(TIMESTAMP_FORMAT).to_string(),
            flow_text: flow.to_string(),
            preview: make_preview(&sql_text),
            tables_text,
            timestamp,
            flow,
            raw,
            sql_text,
            tables,
            ops,
            primary,
        }
    }

    /// 정규화된 SQL 텍스트.
    #[must_use]
    pub fn sql(&self) -> &str {
        &self.sql_text
    }

    /// SQL에서 추출한 테이블명. 비어 있으면 정말로 찾지 못한 것이다.
    #[must_use]
    pub fn tables(&self) -> &[String] {
        &self.tables
    }

    /// SQL에 등장한 작업 종류를 **텍스트에 나타난 순서대로** 돌려준다.
    #[must_use]
    pub fn ops(&self) -> &[SqlOp] {
        &self.ops
    }

    /// 가장 먼저 등장한 작업 종류 (색상/라벨용).
    ///
    /// `new`에서 계산해 두므로 방어적인 기본값 처리가 필요 없다.
    #[must_use]
    pub const fn primary_op(&self) -> SqlOp {
        self.primary
    }

    /// 패킷이 관찰된 시각.
    #[must_use]
    pub const fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    /// 이 SQL이 오간 TCP 플로우.
    #[must_use]
    pub const fn flow(&self) -> FlowId {
        self.flow
    }

    /// 원본 TDS 패킷 바이트 (hex 표시용).
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// 표시용 타임스탬프 문자열.
    #[must_use]
    pub fn timestamp_text(&self) -> &str {
        &self.timestamp_text
    }

    /// 표시용 플로우 문자열 (`client:port->server:port`).
    #[must_use]
    pub fn flow_text(&self) -> &str {
        &self.flow_text
    }

    /// 표시용 테이블 목록. 테이블을 찾지 못했으면 `None`.
    #[must_use]
    pub fn tables_text(&self) -> Option<&str> {
        self.tables_text.as_deref()
    }

    /// 목록에 보여줄 SQL 미리보기 (최대 [`PREVIEW_CHARS`]자).
    #[must_use]
    pub fn preview(&self) -> &str {
        &self.preview
    }

    /// 원본 바이트를 버린다.
    ///
    /// 저장소가 보관 예산을 넘겼을 때 쓴다. hex 뷰만 사라지고 SQL과 파생 정보는
    /// 그대로이며, 원본은 `log/raw` 로그 파일에 이미 기록돼 있다.
    pub(crate) fn forget_raw(&mut self) {
        self.raw = Vec::new();
    }
}

/// 앞뒤 공백을 새 할당 없이 제자리에서 잘라낸다.
fn trim_in_place(text: &mut String) {
    let end = text.trim_end().len();
    text.truncate(end);
    let start = text.len() - text.trim_start().len();
    text.drain(..start);
}

/// 미리보기를 만든다. 문자 경계를 기준으로 자른다.
fn make_preview(sql: &str) -> String {
    let mut chars = sql.chars();
    let head: String = chars.by_ref().take(PREVIEW_CHARS).collect();
    if chars.next().is_some() {
        head + "..."
    } else {
        head
    }
}

// database.schema.table / schema.table / table (한글 식별자 포함, 점 최대 2개)
const TABLE_NAME: &str = r"([a-zA-Z_\u{ac00}-\u{d7a3}][a-zA-Z0-9_\u{ac00}-\u{d7a3}]*(?:\.[a-zA-Z_\u{ac00}-\u{d7a3}][a-zA-Z0-9_\u{ac00}-\u{d7a3}]*){0,2})";

/// 테이블명 추출용 정규식.
///
/// `Regex::new`는 매칭보다 훨씬 비싸므로 프로세스당 한 번만 컴파일한다.
/// 패턴은 컴파일 타임 리터럴이므로 실패는 프로그래머 오류다.
static TABLE_PATTERNS: LazyLock<[Regex; 4]> = LazyLock::new(|| {
    let build = |keyword: &str| {
        Regex::new(&format!(r"(?i)\b{keyword}\s+{TABLE_NAME}"))
            .expect("테이블명 정규식은 컴파일 타임 상수다")
    };
    [
        build("FROM"),
        build("UPDATE"),
        build(r"INSERT\s+INTO"),
        build("JOIN"),
    ]
});

/// 작업 키워드 추출용 정규식.
///
/// `\b`가 없으면 `DELETED_AT` 같은 컬럼명이 DELETE로 잡힌다.
static OPERATION_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|EXECUTE|EXEC)\b")
        .expect("작업 키워드 정규식은 컴파일 타임 상수다")
});

/// SQL 텍스트에서 테이블명 추출.
///
/// `FROM`, `UPDATE`, `INSERT INTO`, `JOIN` 절 뒤의 식별자를 찾는다.
/// 한글 테이블명을 지원한다 (예: `dbo.TB_진료내역`).
/// 결과는 중복 없이 정렬되어 돌아온다.
pub(crate) fn extract_tables_from_sql(sql_text: &str) -> Vec<String> {
    let mut tables: Vec<String> = TABLE_PATTERNS
        .iter()
        .flat_map(|re| re.captures_iter(sql_text))
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect();
    tables.sort_unstable();
    tables.dedup();
    tables
}

/// SQL 텍스트에서 작업 종류를 **등장 순서대로** 추출한다.
///
/// 첫 원소가 그 쿼리의 대표 작업이 되므로 순서가 의미를 갖는다. 열거형 선언
/// 순서로 정렬하면 `UPDATE ... 'select'` 같은 쿼리가 SELECT로 뒤바뀐다.
///
/// 하나도 찾지 못하면 [`SqlOp::Other`]를 담아 돌려주므로 결과는 절대 비어 있지 않다.
/// (문자열 리터럴 안의 키워드까지 구분하지는 못한다. 다만 대표 작업은 맨 앞에
/// 오는 키워드로 정해지므로 리터럴이 대표 작업을 바꾸지는 않는다.)
pub(crate) fn extract_operations(sql_text: &str) -> Vec<SqlOp> {
    let mut ops: Vec<SqlOp> = Vec::new();
    for matched in OPERATION_PATTERN.find_iter(sql_text) {
        let op = SqlOp::from_keyword(matched.as_str());
        if !ops.contains(&op) {
            ops.push(op);
        }
    }
    if ops.is_empty() {
        ops.push(SqlOp::Other);
    }
    ops
}

/// 정규화된 테이블명에서 그룹 표시용 짧은 이름을 **빌려서** 돌려준다.
///
/// 예: `"dbo.TB_PI치료계획세부내역"` -> `"PI치료계획세부내역"`
pub(crate) fn short_table_name(table: &str) -> &str {
    let leaf = table.rsplit('.').next().unwrap_or(table);
    leaf.find("TB_")
        .map_or(leaf, |pos| &leaf[pos + "TB_".len()..])
}

/// 바이트 배열을 offset 접두사가 붙은 16바이트 폭 hex 덤프로 쓴다.
///
/// 파일 로거는 이 스트리밍 버전을 쓴다. 4 MiB 메시지 하나가 14 MB짜리 `String`을
/// 먼저 만들게 하지 않기 위해서다 — 그 할당과 포맷팅이 전부 UI 스레드에서 일어난다.
///
/// # Errors
/// 대상에 쓰기가 실패하면 그 오류를 그대로 돌려준다.
pub(crate) fn write_hex_dump(out: &mut impl io::Write, bytes: &[u8]) -> io::Result<()> {
    let mut line_buf = String::with_capacity(16 * 3 + 12);
    for (line, chunk) in bytes.chunks(16).enumerate() {
        use fmt::Write as _;

        line_buf.clear();
        if line > 0 {
            line_buf.push('\n');
        }
        let _ = write!(line_buf, "{:08x}: ", line * 16);
        for byte in chunk {
            let _ = write!(line_buf, " {byte:02x}");
        }
        out.write_all(line_buf.as_bytes())?;
    }
    Ok(())
}

/// 화면 표시용 hex 덤프 문자열.
pub(crate) fn hex_dump(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len() * 4);
    let _ = write_hex_dump(&mut out, bytes);
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- 테이블명 추출 ----------

    #[test]
    fn extracts_table_from_each_supported_clause() {
        assert_eq!(extract_tables_from_sql("SELECT * FROM Users"), ["Users"]);
        assert_eq!(extract_tables_from_sql("UPDATE Users SET a = 1"), ["Users"]);
        assert_eq!(
            extract_tables_from_sql("INSERT   INTO  Users VALUES (1)"),
            ["Users"]
        );
        assert_eq!(
            extract_tables_from_sql("SELECT * FROM A JOIN B ON A.id = B.id"),
            ["A", "B"]
        );
    }

    #[test]
    fn accepts_one_two_and_three_part_names() {
        assert_eq!(extract_tables_from_sql("SELECT * FROM t"), ["t"]);
        assert_eq!(extract_tables_from_sql("SELECT * FROM dbo.t"), ["dbo.t"]);
        assert_eq!(
            extract_tables_from_sql("SELECT * FROM DentWeb.dbo.t"),
            ["DentWeb.dbo.t"]
        );
    }

    /// 4단 이름(연결 서버)은 패턴이 점 2개까지만 허용하므로 뒤가 잘린다.
    /// 현재 동작을 명시적으로 고정해 둔다.
    #[test]
    fn four_part_linked_server_names_are_truncated() {
        assert_eq!(
            extract_tables_from_sql("SELECT * FROM srv.db.dbo.t"),
            ["srv.db.dbo"],
            "알려진 한계: 연결 서버 4단 이름은 앞 3단만 잡힌다"
        );
    }

    #[test]
    fn supports_korean_table_names() {
        assert_eq!(
            extract_tables_from_sql("SELECT * FROM DentWeb.dbo.TB_진료내역"),
            ["DentWeb.dbo.TB_진료내역"]
        );
    }

    #[test]
    fn table_extraction_is_case_insensitive_and_deduplicated() {
        assert_eq!(
            extract_tables_from_sql("select * from Users union select * FROM Users"),
            ["Users"]
        );
    }

    #[test]
    fn no_table_yields_empty_list() {
        assert!(extract_tables_from_sql("EXEC sp_who2").is_empty());
    }

    // ---------- 작업 종류 추출 ----------

    #[test]
    fn operations_are_ordered_by_position_in_the_text() {
        assert_eq!(
            extract_operations("UPDATE dbo.TB_A SET x = (SELECT 1)"),
            [SqlOp::Update, SqlOp::Select],
            "먼저 등장한 키워드가 대표 작업이어야 한다"
        );
    }

    /// 열거형 선언 순서로 정렬하면 이 UPDATE가 SELECT로 표시된다.
    #[test]
    fn keyword_inside_a_literal_does_not_hijack_the_primary_op() {
        let ops = extract_operations("UPDATE dbo.TB_A SET note = 'please select later'");
        assert_eq!(ops[0], SqlOp::Update);
    }

    /// `\b`가 없으면 `DELETED_AT` 컬럼이 DELETE로 잡힌다.
    #[test]
    fn keywords_require_word_boundaries() {
        assert_eq!(
            extract_operations("SELECT DELETED_AT, UPDATED_BY FROM dbo.TB_A"),
            [SqlOp::Select],
            "컬럼명 일부가 키워드로 잡히면 안 된다"
        );
    }

    #[test]
    fn exec_and_execute_map_to_the_same_operation() {
        assert_eq!(extract_operations("EXEC sp_who2"), [SqlOp::Exec]);
        assert_eq!(extract_operations("EXECUTE sp_who2"), [SqlOp::Exec]);
    }

    #[test]
    fn operations_are_never_empty() {
        assert_eq!(extract_operations("BEGIN TRAN"), [SqlOp::Other]);
        assert_eq!(extract_operations(""), [SqlOp::Other]);
    }

    #[test]
    fn duplicate_keywords_appear_once() {
        assert_eq!(
            extract_operations("SELECT a FROM t WHERE b IN (SELECT c FROM u)"),
            [SqlOp::Select]
        );
    }

    // ---------- 짧은 테이블명 ----------

    #[test]
    fn short_name_strips_schema_and_tb_prefix() {
        assert_eq!(
            short_table_name("dbo.TB_PI치료계획세부내역"),
            "PI치료계획세부내역"
        );
        assert_eq!(short_table_name("DentWeb.dbo.TB_Users"), "Users");
    }

    #[test]
    fn short_name_passes_through_names_without_tb_prefix() {
        assert_eq!(short_table_name("dbo.Users"), "Users");
        assert_eq!(short_table_name("Users"), "Users");
        assert_eq!(short_table_name(""), "");
    }

    // ---------- hex 덤프 ----------

    #[test]
    fn hex_dump_format_matches_documented_layout() {
        let dump = hex_dump(&(0u8..=0x11).collect::<Vec<_>>());
        let mut lines = dump.lines();
        assert_eq!(
            lines.next().unwrap(),
            "00000000:  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
        );
        assert_eq!(lines.next().unwrap(), "00000010:  10 11");
        assert!(lines.next().is_none());
    }

    #[test]
    fn hex_dump_of_empty_input_is_empty() {
        assert_eq!(hex_dump(&[]), "");
    }
}

#[cfg(test)]
mod event_tests {
    use super::*;
    use crate::tcp::{Endpoint, FlowId};
    use std::net::{IpAddr, Ipv4Addr};

    fn flow() -> FlowId {
        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        FlowId::classify(client, server).unwrap().0
    }

    fn event(sql: &str) -> SqlEvent {
        SqlEvent::new(
            DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            flow(),
            sql.to_string(),
            Vec::new(),
        )
    }

    #[test]
    fn derived_data_is_computed_once_at_construction() {
        let e = event("  SELECT * FROM dbo.TB_Users  ");
        assert_eq!(
            e.sql(),
            "SELECT * FROM dbo.TB_Users",
            "생성 시점에 다듬는다"
        );
        assert_eq!(e.tables(), ["dbo.TB_Users"]);
        assert_eq!(e.ops(), [SqlOp::Select]);
        assert_eq!(e.primary_op(), SqlOp::Select);
        assert_eq!(e.tables_text(), Some("테이블: dbo.TB_Users"));
        assert_eq!(e.flow_text(), "10.0.0.1:50000->10.0.0.2:1433");
        assert!(e.timestamp_text().starts_with("2023-11-14"));
    }

    #[test]
    fn events_without_tables_have_no_table_label() {
        assert_eq!(event("EXEC sp_who2").tables_text(), None);
    }

    #[test]
    fn preview_truncates_on_character_boundaries() {
        let long = "가".repeat(PREVIEW_CHARS + 50);
        let e = event(&long);
        assert!(e.preview().ends_with("..."));
        assert_eq!(e.preview().chars().count(), PREVIEW_CHARS + 3);
        assert_eq!(event("SELECT 1").preview(), "SELECT 1", "짧은 SQL은 그대로");
    }
}
