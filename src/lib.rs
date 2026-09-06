//! pcap으로 캡처한 MSSQL TDS 트래픽에서 SQL 쿼리를 추출한다.
//!
//! 파이프라인:
//! 프레임 파싱([`extractor`]) → 플로우 분류·TCP 재조립([`tcp`])
//! → TDS 프레이밍·디코딩([`tds`]) → 도메인 이벤트([`output`])
//! → 중복 제거·그룹화([`store`]) → 캡처 수명 관리([`capture`])
//! → 표시([`gui`])·기록([`logging`]).

pub mod capture;
pub mod extractor;
pub mod gui;
pub mod logging;
pub mod output;
pub mod store;
pub mod tcp;
pub mod tds;

// 파사드는 공개 시그니처에 등장하는 타입을 빠짐없이 포함한다.
// 예전에는 `TcpReassembler`만 내보내고 `drain_client`에 필요한 `Consumed`가
// 빠져 있는 식이라, 파사드만 보고는 API를 쓸 수 없었다.
pub use capture::{Capture, CaptureStatus, Interfaces};
pub use extractor::{parse_packet, CaptureError, Extractor, ParsedPacket};
pub use gui::{show_gui, GuiState};
pub use logging::SqlLogger;
pub use output::{SqlEvent, SqlOp};
pub use store::{EventIdx, EventStore};
pub use tcp::{Consumed, Direction, Endpoint, FlowId, TcpReassembler};
pub use tds::{DecodedPacket, StreamScan, TdsError, TdsParser};
