use crate::output::{write_hex_dump, SqlEvent};
use chrono::Utc;
use log::info;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// 로그 루트 아래의 하위 폴더 이름.
const BASIC_SUBDIR: &str = "basic";
const RAW_SUBDIR: &str = "raw";
/// 기본 로그 루트 (실행 디렉터리 기준).
const DEFAULT_ROOT: &str = "log";

const SEPARATOR: &str =
    "================================================================================";

/// 열려 있는 로그 파일 한 쌍.
///
/// 캡처가 진행 중일 때만 존재한다. `Option<Sinks>` 하나로 "실행 중/아님"을
/// 표현하므로, 파일 핸들만 있고 경로는 없는 어중간한 상태가 나올 수 없다.
struct Sinks {
    basic: BufWriter<File>,
    raw: BufWriter<File>,
    basic_path: PathBuf,
}

/// SQL 이벤트를 두 개의 로그 파일과 콘솔에 기록한다.
///
/// - `<root>/basic/`: SQL 텍스트만
/// - `<root>/raw/`: SQL 텍스트 + 원본 TDS 패킷 Hex
///
/// 이 로거는 GUI 스레드 하나에서만 쓰인다. `&mut self`가 이미 배타 접근을
/// 보장하므로 `Arc`/`Mutex` 같은 동기화 장치를 두지 않는다.
pub struct SqlLogger {
    root: PathBuf,
    sinks: Option<Sinks>,
}

impl Default for SqlLogger {
    fn default() -> Self {
        Self::new(DEFAULT_ROOT)
    }
}

impl SqlLogger {
    /// 로그 루트를 지정해 로거를 만든다.
    ///
    /// 경로를 주입받는 이유는 테스트에서 임시 디렉터리를 쓸 수 있게 하기 위해서다.
    /// 상대 경로를 하드코딩하면 프로세스 CWD에 의존하게 되는데, Windows GUI
    /// 바이너리의 CWD는 실행 방식에 따라 달라진다.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            sinks: None,
        }
    }

    /// 로그 파일을 만들고 헤더를 쓴다. 기본 로그 파일 경로를 돌려준다.
    ///
    /// # Errors
    /// 디렉터리 생성이나 파일 열기/쓰기에 실패하면 `io::Error`를 돌려준다.
    /// 예전처럼 조용히 삼키지 않는다.
    pub fn start(&mut self, interface: &str) -> io::Result<&Path> {
        let basic_dir = self.root.join(BASIC_SUBDIR);
        let raw_dir = self.root.join(RAW_SUBDIR);
        std::fs::create_dir_all(&basic_dir)?;
        std::fs::create_dir_all(&raw_dir)?;

        let now = Utc::now();
        let filename = format!("sql_capture_{}.log", now.format("%Y%m%d_%H%M%S"));
        let basic_path = basic_dir.join(&filename);

        let mut basic = BufWriter::new(open_append(&basic_path)?);
        let mut raw = BufWriter::new(open_append(&raw_dir.join(&filename))?);

        let header = format!(
            "\n{SEPARATOR}\nCapture Started: {}\nInterface: {interface}\n{SEPARATOR}\n\n",
            now.format("%Y-%m-%d %H:%M:%S%.3f")
        );
        basic.write_all(header.as_bytes())?;
        basic.flush()?;
        raw.write_all(header.as_bytes())?;
        raw.flush()?;

        // `Option::insert`가 방금 넣은 값을 그대로 빌려주므로 `expect`가 필요 없다.
        let sinks = self.sinks.insert(Sinks {
            basic,
            raw,
            basic_path,
        });
        Ok(sinks.basic_path.as_path())
    }

    /// 이벤트 하나를 기록한다. 캡처 중이 아니면 아무것도 하지 않는다.
    ///
    /// # Errors
    /// 파일 쓰기에 실패하면 호출자에게 알린다. 로그가 조용히 사라지지 않도록
    /// 오류를 삼키지 않는 것이 이 시그니처의 목적이다.
    pub fn log_event(&mut self, event: &SqlEvent) -> io::Result<()> {
        // 파생 정보는 이벤트가 이미 들고 있다. 여기서 다시 파싱하지 않는다.
        let tables = if event.tables().is_empty() {
            "N/A".to_string()
        } else {
            event.tables().join(", ")
        };
        let head = format!(
            "\n{SEPARATOR}\nTimestamp: {}\nFlow: {}\nTables: {tables}\nSQL:\n{}\n",
            event.timestamp_text(),
            event.flow_text(),
            event.sql(),
        );

        info!("{head}{SEPARATOR}");

        let Some(sinks) = self.sinks.as_mut() else {
            return Ok(());
        };

        write_record(&mut sinks.basic, &head, None)?;
        write_record(&mut sinks.raw, &head, Some(event.raw()))
    }

    /// 푸터를 쓰고 파일을 닫는다.
    ///
    /// # Errors
    /// 파일 쓰기에 실패하면 오류를 돌려준다. 실패하더라도 핸들은 반드시 닫힌다.
    pub fn stop(&mut self, event_count: usize) -> io::Result<()> {
        let Some(mut sinks) = self.sinks.take() else {
            return Ok(());
        };
        let footer = format!(
            "\n{SEPARATOR}\nCapture Stopped: {}\nTotal Events: {event_count}\n{SEPARATOR}\n",
            Utc::now().format("%Y-%m-%d %H:%M:%S%.3f")
        );
        // 한쪽이 실패해도 다른 쪽은 반드시 시도한다.
        let basic = write_all_and_flush(&mut sinks.basic, footer.as_bytes());
        let raw = write_all_and_flush(&mut sinks.raw, footer.as_bytes());
        basic.and(raw)
    }
}

fn write_record(sink: &mut BufWriter<File>, head: &str, raw: Option<&[u8]>) -> io::Result<()> {
    sink.write_all(head.as_bytes())?;
    if let Some(bytes) = raw.filter(|b| !b.is_empty()) {
        sink.write_all(b"\nRaw Data (Hex):\n")?;
        // 통째로 문자열을 만들지 않고 흘려 쓴다.
        write_hex_dump(sink, bytes)?;
        sink.write_all(b"\n")?;
    }
    write_all_and_flush(sink, SEPARATOR.as_bytes())?;
    Ok(())
}

fn write_all_and_flush(sink: &mut BufWriter<File>, bytes: &[u8]) -> io::Result<()> {
    sink.write_all(bytes)?;
    sink.write_all(b"\n")?;
    sink.flush()
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::{Endpoint, FlowId};
    use std::net::{IpAddr, Ipv4Addr};

    /// 테스트가 끝나면 지워지는 임시 디렉터리.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "tds-sniffer-test-{tag}-{}",
                u64::from(std::process::id()) * 1_000_000
                    + u64::from(Utc::now().timestamp_subsec_nanos())
            ));
            std::fs::create_dir_all(&path).expect("임시 디렉터리 생성");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sample_event(sql: &str) -> SqlEvent {
        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        let flow = FlowId::classify(client, server).unwrap().0;
        SqlEvent::new(Utc::now(), flow, sql.to_string(), vec![0x01, 0x02, 0x03])
    }

    #[test]
    fn logging_without_started_capture_is_a_noop() {
        let mut logger = SqlLogger::new("/nonexistent-root");
        logger
            .log_event(&sample_event("SELECT 1 FROM dbo.TB_A"))
            .expect("무시되어야 한다");
        logger.stop(0).expect("무시되어야 한다");
    }

    #[test]
    fn start_creates_both_log_directories() {
        let dir = TempDir::new("dirs");
        let mut logger = SqlLogger::new(&dir.0);
        assert!(logger.start("eth0").expect("로그 시작").is_file());

        assert!(dir.0.join(BASIC_SUBDIR).is_dir());
        assert!(dir.0.join(RAW_SUBDIR).is_dir());
    }

    #[test]
    fn basic_log_holds_sql_only_and_raw_log_holds_the_hex_dump() {
        let dir = TempDir::new("content");
        let mut logger = SqlLogger::new(&dir.0);
        let basic_path = logger.start("eth0").expect("로그 시작").to_path_buf();
        let raw_path = dir.0.join(RAW_SUBDIR).join(
            basic_path
                .file_name()
                .expect("파일 이름")
                .to_str()
                .expect("UTF-8"),
        );

        logger
            .log_event(&sample_event("SELECT * FROM dbo.TB_Users"))
            .expect("기록");
        logger.stop(1).expect("마무리");

        let basic = std::fs::read_to_string(&basic_path).expect("basic 읽기");
        let raw = std::fs::read_to_string(&raw_path).expect("raw 읽기");

        // 헤더 / 본문 / 푸터가 문서화된 형식대로 들어간다.
        assert!(basic.contains("Capture Started:"));
        assert!(basic.contains("Interface: eth0"));
        assert!(
            basic.contains("Tables: dbo.TB_Users"),
            "로그에는 전체 테이블명이 들어간다"
        );
        assert!(basic.contains("SELECT * FROM dbo.TB_Users"));
        assert!(basic.contains("Capture Stopped:"));
        assert!(basic.contains("Total Events: 1"));

        assert!(
            !basic.contains("Raw Data (Hex)"),
            "basic 로그에는 hex가 없어야 한다"
        );
        assert!(raw.contains("Raw Data (Hex):"));
        assert!(raw.contains("00000000:  01 02 03"));
    }

    #[test]
    fn stop_is_idempotent_and_releases_the_files() {
        let dir = TempDir::new("stop");
        let mut logger = SqlLogger::new(&dir.0);
        logger.start("eth0").expect("로그 시작");
        logger.stop(0).expect("첫 번째 마무리");
        logger.stop(0).expect("두 번째 마무리는 무시된다");
    }

    #[test]
    fn start_reports_an_error_instead_of_swallowing_it() {
        // 파일을 루트로 지정하면 하위 디렉터리를 만들 수 없다.
        let dir = TempDir::new("err");
        let blocker = dir.0.join("not-a-dir");
        std::fs::write(&blocker, b"x").expect("파일 생성");

        let mut logger = SqlLogger::new(&blocker);
        assert!(
            logger.start("eth0").is_err(),
            "디렉터리를 만들 수 없으면 오류를 돌려줘야 한다"
        );
    }

    #[test]
    fn events_without_raw_bytes_omit_the_hex_section() {
        let dir = TempDir::new("noraw");
        let mut logger = SqlLogger::new(&dir.0);
        let basic_path = logger.start("eth0").expect("로그 시작").to_path_buf();
        let raw_path = dir.0.join(RAW_SUBDIR).join(basic_path.file_name().unwrap());

        let client = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000);
        let server = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 1433);
        let flow = FlowId::classify(client, server).unwrap().0;
        logger
            .log_event(&SqlEvent::new(
                Utc::now(),
                flow,
                "EXEC sp_who2".to_string(),
                Vec::new(),
            ))
            .expect("기록");
        logger.stop(1).expect("마무리");

        let raw = std::fs::read_to_string(&raw_path).expect("raw 읽기");
        assert!(raw.contains("EXEC sp_who2"));
        assert!(!raw.contains("Raw Data (Hex)"));
    }
}
