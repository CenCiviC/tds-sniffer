# Rust Wireshark - MSSQL TDS SQL 추출기

pcap/pcapng 파일에서 MSSQL TDS 프로토콜의 SQL 쿼리를 추출하는 Rust 도구입니다.

## 기능

- **TCP 스트림 재조립**: 순서가 바뀐 패킷과 재전송 처리
- **TDS 파싱**: SQLBatch/RPC 요청에서 SQL 텍스트 추출
- **UTF-16LE 디코딩**: MSSQL의 UTF-16LE 인코딩된 SQL 처리
- **JSONL 출력**: 타임스탬프, 플로우 ID, SQL 텍스트, 테이블명, 작업 유형 포함
- **egui GUI**: 브라우징, 필터링, 그룹화 기능

## 빌드

```bash
cargo build --release
```

## 사용법
https://npcap.com/
에서 installer 다운 및 실행 이때 WinPcap API-compatible Mode 체크 해야됨
또한 SDK 실행 받아서 

### GUI 실행
```bash
cargo run --release
```

GUI에서:
1. **파일 선택** 버튼을 클릭하여 pcap/pcapng 파일 선택
2. **TDS 헤더 기반 파싱 (v2)** 체크박스로 파싱 모드 선택 (선택 안 하면 휴리스틱 v1 사용)
3. **시작** 버튼을 클릭하여 처리 시작
4. 처리 완료 후 테이블별로 그룹화된 결과 확인
5. 왼쪽 테이블 목록에서 테이블을 클릭하면 해당 테이블을 사용하는 SQL만 필터링

## 마일스톤

- **v1**: TCP 재조립 + UTF-16LE 휴리스틱 추출 ✅
- **v2**: TDS 헤더 기반 추출 ✅
- **v3**: 외부 로그 파일을 사용한 시간 윈도우 기반 버튼-라벨 매핑 (예정)

## 출력 형식

JSONL 파일의 각 라인은 다음과 같은 형식입니다:

```json
{
  "timestamp": "2025-01-23T11:44:09.908599Z",
  "flow_id": "192.168.219.49:xxxx->183.111.64.36:1433",
  "sql_text": "SELECT ...",
  "tables": ["TB_치료계획", "TB_치료계획수납내역"],
  "operation": "SELECT",
  "label": null
}
```

## 검증

Wireshark의 "Follow TCP Stream" 기능과 비교하여 95% 이상의 일치율을 목표로 합니다.

