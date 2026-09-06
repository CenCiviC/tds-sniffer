use crate::extractor::Extractor;
use crate::logging::SqlLogger;
use crate::output::SqlEvent;
use crate::store::EventStore;
use log::error;
use std::path::Path;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// 한 프레임에 회수·기록에 쓸 최대 시간.
///
/// 회수·로깅이 전부 UI 스레드에서 일어나므로 큐를 매번 끝까지 비우면 밀린 대량
/// 이벤트가 화면을 몇 초씩 얼린다. 반대로 **개수**로 제한하면 처리 속도에 인위적인
/// 천장이 생겨(프레임당 N개 × 초당 프레임 수) 생산 속도가 그보다 빠를 때 큐가
/// 영원히 자란다. 시간으로 제한하고, 남은 일이 있으면 다음 프레임을 곧바로 요청한다.
const DRAIN_BUDGET: Duration = Duration::from_millis(15);

/// 사용자에게 보여줄 캡처 상태.
///
/// 예전에는 `String` 하나에 빈 문자열을 "상태 없음"으로 쓰는 sentinel이었고,
/// GUI가 `!status.is_empty()`로 방어했다. 열거형으로 두면 표현 불가능한
/// 상태가 사라지고, 문장 조립은 표시를 담당하는 GUI로 간다.
#[derive(Debug, Clone, Default)]
pub enum CaptureStatus {
    /// 아직 아무것도 하지 않았다.
    #[default]
    Idle,
    /// 캡처 중. `log_error`가 있으면 기록이 깨진 채로 캡처만 계속되는 상태다.
    Running {
        unique: usize,
        log: Arc<Path>,
        log_error: Option<String>,
    },
    /// 정상적으로 끝났다.
    Stopped {
        unique: usize,
        log: Arc<Path>,
        log_error: Option<String>,
    },
    /// 시작하지 못했거나 도중에 실패했다.
    Failed { reason: String },
}

/// 실행 중인 캡처가 소유하는 자원 묶음.
///
/// 채널 두 개와 워커 핸들은 **언제나 함께** 존재하거나 함께 없다. 예전처럼
/// `Option` 세 개와 `running: bool`로 나눠 두면 `running == true, rx == None`
/// 같은 상태가 표현 가능해지고, 세 메서드가 각자 네 필드를 손으로 맞춰야 한다.
struct Session {
    rx: mpsc::Receiver<SqlEvent>,
    stop_tx: mpsc::Sender<()>,
    worker: JoinHandle<Result<(), String>>,
    /// `Arc`라 상태를 다시 만들 때마다 경로를 복사하지 않는다.
    log: Arc<Path>,
}

/// 캡처 스레드와 로그 파일의 소유자.
///
/// `Option<Session>` 하나가 "실행 중/아님"을 표현한다. `SqlLogger`의
/// `Option<Sinks>`와 같은 패턴이다.
#[derive(Default)]
pub struct Capture {
    session: Option<Session>,
    logger: SqlLogger,
    status: CaptureStatus,
    /// 이번 세션에서 로그 기록이 실패한 적이 있는가.
    ///
    /// 한 프레임만 표시하고 사라지면 안 된다. 디스크가 찬 채로 캡처가 계속되면
    /// 사용자는 정상인 줄 알고 끝내게 된다.
    log_error: Option<String>,
}

impl Capture {
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.session.is_some()
    }

    #[must_use]
    pub const fn status(&self) -> &CaptureStatus {
        &self.status
    }

    /// 로그 파일을 열고 캡처 스레드를 띄운다.
    ///
    /// 로그 파일을 열지 못하면 캡처를 시작하지 않는다 — 기록되지 않는 캡처는
    /// 이 도구의 목적을 잃기 때문이다.
    pub fn start(&mut self, interface: &str) {
        if self.is_running() {
            return;
        }
        self.log_error = None;
        let log: Arc<Path> = match self.logger.start(interface) {
            Ok(path) => Arc::from(path),
            Err(e) => {
                self.status = CaptureStatus::Failed {
                    reason: format!("로그 파일을 열지 못했습니다: {e}"),
                };
                return;
            }
        };

        let (event_tx, rx) = mpsc::channel();
        let (stop_tx, stop_rx) = mpsc::channel();
        let interface = interface.to_string();

        // 워커의 반환값 자체가 오류 채널 역할을 한다. 별도의 공유 상태가 필요 없다.
        let worker = thread::spawn(move || {
            Extractor::new()
                .start_live_capture(&interface, &event_tx, &stop_rx)
                .map_err(|e| e.to_string())
        });

        self.status = CaptureStatus::Running {
            unique: 0,
            log: Arc::clone(&log),
            log_error: None,
        };
        self.session = Some(Session {
            rx,
            stop_tx,
            worker,
            log,
        });
    }

    /// 매 프레임 호출된다. 도착한 이벤트를 회수하고, 워커가 스스로 끝났으면 정리한다.
    ///
    /// 시간 예산을 다 써서 아직 처리할 이벤트가 남았으면 `true`를 돌려준다.
    /// 호출자는 다음 프레임을 곧바로 요청해야 큐가 밀리지 않는다.
    pub fn poll(&mut self, store: &mut EventStore) -> bool {
        // `&self.session`(읽기)과 `&mut self.logger`(쓰기)는 서로 다른 필드라
        // 동시에 빌릴 수 있다. 빌림 충돌을 피하려던 임시 `Vec`이 필요 없다.
        let Some(session) = self.session.as_ref() else {
            return false;
        };
        let report = Self::drain(&session.rx, store, &mut self.logger, Some(DRAIN_BUDGET));
        let finished = session.worker.is_finished();
        // `Arc`이므로 참조 카운트만 올린다. 여기서 빌림을 끊어야 아래에서
        // `self`를 다시 빌릴 수 있다.
        let log = Arc::clone(&session.log);

        if let Some(e) = report.log_error {
            self.log_error = Some(e);
        }
        if finished {
            self.finish(store);
            return false;
        }
        if report.received > 0 {
            self.status = CaptureStatus::Running {
                unique: store.len(),
                log,
                log_error: self.log_error.clone(),
            };
        }
        report.backlog
    }

    /// 사용자가 중지를 눌렀을 때.
    pub fn stop(&mut self, store: &mut EventStore) {
        self.finish(store);
    }

    /// 세션을 끝내고 자원을 정리한다.
    ///
    /// 반드시 **채널을 비운 뒤** 로그 푸터를 쓴다. 예전에는 `rx`를 그냥 버려서
    /// 중지 시점에 채널에 남아 있던 이벤트가 화면에도 로그에도 남지 않았고,
    /// `JoinHandle`을 드롭해 스레드를 분리하는 바람에 곧바로 다시 시작하면
    /// 이전 스레드가 pcap 핸들을 쥔 채로 두 번째 스레드가 뜰 수 있었다.
    fn finish(&mut self, store: &mut EventStore) {
        let Some(session) = self.session.take() else {
            return;
        };
        // 이미 죽은 스레드면 실패해도 무방하다.
        let _ = session.stop_tx.send(());

        // 워커는 pcap 타임아웃(100ms) 안에 중지 신호를 확인하므로 join은 짧게 끝난다.
        //
        // 가정: `pcap::Capture::next_packet`이 설정한 타임아웃을 지킨다. 일부
        // Npcap 어댑터는 트래픽이 전혀 없을 때 이를 어긴다고 알려져 있는데, 그
        // 경우 여기서 UI가 멈춘다. std에는 시한부 join이 없어 제대로 고치려면
        // 워커가 완료를 채널로 알리게 해야 한다. 스레드를 떼어놓는(detach) 쪽은
        // 더 나쁘다 — 다시 시작할 때 이전 스레드가 pcap 핸들을 쥔 채로 두 번째
        // 스레드가 뜬다.
        let outcome = session.worker.join();
        // 워커가 끝났으니 채널에 남은 것을 남김없이 회수한다. 여기서는 예산을
        // 두지 않는다 — 남기면 그대로 잃는다.
        let report = Self::drain(&session.rx, store, &mut self.logger, None);
        if let Some(e) = report.log_error {
            self.log_error = Some(e);
        }
        let log_result = self.logger.stop(store.len() + store.over_capacity());

        // 캡처 자체가 실패했으면 그것을 보여준다. 로그 문제는 캡처가 정상일 때만
        // 최종 상태로 승격되지만, 어느 쪽이든 조용히 사라지지 않는다.
        // 로그 문제는 캡처 실패와 함께 보여준다. 한쪽이 다른 쪽을 가리면 안 된다.
        let log_note = self
            .log_error
            .take()
            .map(|e| format!(" ({e})"))
            .unwrap_or_default();

        self.status = match outcome {
            Ok(Err(e)) => CaptureStatus::Failed {
                reason: format!("캡처 실패: {e}{log_note}"),
            },
            Err(_) => CaptureStatus::Failed {
                reason: format!("캡처 스레드가 패닉으로 종료되었습니다{log_note}"),
            },
            Ok(Ok(())) => {
                let log_error = match log_result {
                    Err(e) => Some(format!("로그 마무리 실패: {e}{log_note}")),
                    Ok(()) => (!log_note.is_empty()).then(|| log_note.trim().to_string()),
                };
                CaptureStatus::Stopped {
                    unique: store.len(),
                    log: session.log,
                    log_error,
                }
            }
        };
    }

    /// 채널을 비워 저장소로 옮기고, 새로 등장한 SQL만 로깅한다.
    ///
    /// 시간 예산을 다 쓰면 즉시 멈춘다. 예산은 UI 스레드가 한 프레임에 쓰는
    /// 시간을 제한하기 위한 것이므로, 표식만 세우고 루프를 계속 돌면 아무 의미가 없다.
    fn drain(
        rx: &mpsc::Receiver<SqlEvent>,
        store: &mut EventStore,
        logger: &mut SqlLogger,
        budget: Option<Duration>,
    ) -> DrainReport {
        let started = Instant::now();
        let mut report = DrainReport::default();

        while let Ok(event) = rx.try_recv() {
            report.received += 1;
            // 저장소가 새 SQL일 때만 콜백을 부르므로 중복 로깅이 원천 차단되고,
            // 원본 보관 예산을 적용하기 **전에** 부르므로 hex가 로그에서 사라지지
            // 않는다. 순서를 여기서 지키려 하면 언젠가 어긋난다.
            if let Some(Err(e)) = store.insert_with(event, |_, stored| logger.log_event(stored)) {
                error!("로그 기록 실패: {e}");
                // 첫 실패 사유만 남긴다. 뒤이은 실패는 대개 같은 원인이다.
                report
                    .log_error
                    .get_or_insert_with(|| format!("로그 기록 실패: {e}"));
            }

            if budget.is_some_and(|limit| started.elapsed() >= limit) {
                // 예산 초과. 남은 것은 다음 프레임에 처리한다.
                report.backlog = true;
                break;
            }
        }
        report
    }
}

/// 채널을 한 번 비운 결과.
///
/// "아직 남은 일이 있는가"와 "로그 기록이 실패했는가"는 별개의 사실이다.
/// 하나의 열거형에 담으면 한쪽이 다른 쪽을 가려, 디스크가 찬 순간 밀림 신호가
/// 사라지는 식의 결합이 생긴다.
#[derive(Debug, Default)]
struct DrainReport {
    /// 이번에 회수한 이벤트 수.
    received: usize,
    /// 시간 예산을 다 써서 아직 남은 이벤트가 있다.
    backlog: bool,
    /// 로그 기록 실패 사유 (첫 번째).
    log_error: Option<String>,
}

/// 선택 가능한 네트워크 인터페이스 목록.
///
/// 선택 상태를 이름 복사본이 아니라 `available`의 인덱스로 들고 있어서,
/// "목록에 없는 인터페이스가 선택되어 있는" 상태를 만들 수 없다.
/// `Default`를 두지 않는다 — 장치 열거는 I/O이자 실패할 수 있는 작업이고,
/// `Default`가 libpcap을 여는 타입은 테스트에서 만들 수조차 없다.
pub struct Interfaces {
    available: Vec<(String, String)>,
    selected: Option<usize>,
    /// 열거에 실패한 이유. 화면에 그대로 보여준다.
    error: Option<String>,
}

impl Interfaces {
    /// 시스템의 캡처 가능한 인터페이스를 조회한다.
    #[must_use]
    pub fn detect() -> Self {
        match Extractor::list_interfaces() {
            Ok(available) => {
                let selected = (!available.is_empty()).then_some(0);
                Self {
                    available,
                    selected,
                    error: None,
                }
            }
            Err(e) => {
                // Npcap 미설치나 권한 부족이 여기로 온다. GUI 빌드에는 콘솔이 없어
                // 로그만 남기면 사용자는 이유를 알 방법이 없다.
                error!("인터페이스 목록을 가져오지 못했습니다: {e}");
                Self {
                    available: Vec::new(),
                    selected: None,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    #[must_use]
    pub fn available(&self) -> &[(String, String)] {
        &self.available
    }

    /// 선택된 인터페이스 이름. 인덱스가 목록을 가리키므로 항상 유효하다.
    #[must_use]
    pub fn selected(&self) -> Option<&str> {
        let (name, _) = self.available.get(self.selected?)?;
        Some(name)
    }

    /// 목록에 있는 항목을 선택한다. 범위를 벗어난 인덱스는 무시한다.
    pub const fn select(&mut self, index: usize) {
        if index < self.available.len() {
            self.selected = Some(index);
        }
    }

    #[must_use]
    pub const fn is_selected(&self, index: usize) -> bool {
        matches!(self.selected, Some(i) if i == index)
    }

    /// 인터페이스를 열거하지 못한 이유 (있다면).
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interfaces(names: &[&str]) -> Interfaces {
        let available: Vec<(String, String)> = names
            .iter()
            .map(|n| ((*n).to_string(), String::new()))
            .collect();
        let selected = (!available.is_empty()).then_some(0);
        Interfaces {
            available,
            selected,
            error: None,
        }
    }

    #[test]
    fn first_interface_is_selected_by_default() {
        assert_eq!(interfaces(&["eth0", "eth1"]).selected(), Some("eth0"));
    }

    #[test]
    fn empty_list_has_no_selection() {
        assert_eq!(interfaces(&[]).selected(), None);
    }

    /// 인덱스가 목록을 가리키므로 "목록에 없는 인터페이스가 선택된" 상태를
    /// 만들 수 없다. 예전에는 임의의 문자열을 넣을 수 있었다.
    #[test]
    fn out_of_range_selection_is_rejected() {
        let mut i = interfaces(&["eth0"]);
        i.select(99);
        assert_eq!(i.selected(), Some("eth0"), "선택이 바뀌면 안 된다");
        i.select(0);
        assert_eq!(i.selected(), Some("eth0"));
    }

    #[test]
    fn idle_capture_has_no_session_and_no_status_sentinel() {
        let cap = Capture::default();
        assert!(!cap.is_running());
        assert!(matches!(cap.status(), CaptureStatus::Idle));
    }
}
