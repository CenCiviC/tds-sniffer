# Rust Wireshark - MSSQL TDS SQL 추출기

pcap/pcapng 파일에서 MSSQL TDS 프로토콜의 SQL 쿼리를 추출하는 Rust 도구입니다.
> [!CAUTION]
> 해당 프로그램은 윈도우 전용 프로그램입니다.  
> mac에서 개발은 가능하지만 실행은 윈도우에서 해주세요.

## 사용법

## Demo
![records](https://github.com/user-attachments/assets/d1a66b05-5787-48b2-9815-62270ba885a6)


### Pre-requisties

#### rust(rustup)
- macos, linux : `curl https://sh.rustup.rs -sSf | sh -s`
- window : `https://win.rustup.rs/`에 접속 후 실행

> [!NOTE]
> rustup을 쓰기 싫은경우, 각 시스템에 기본으로 탑재되어있는 패키지매니저를 사용하여 설치해도 됩니다.  
> 그러나 이와 같은 방식으로 설치할경우, 상당히 늦은 버전의 Rust가 설치되므로 주의하세요.
>
> ```bash
> # 초기 세팅
># Ubuntu, Debian
>apt install rustc cargo
># Fedora
>dnf install rust
>
># macOS에서 Homebrew를 쓰는 경우
>brew install rust
># macOS에서 Mac Ports를 쓰는 경우
>port install rust
>
># 윈도우즈에서 Chocolatey를 쓰는 경우
>choco install rust     # GNU ABI
>choco install rust-ms  # MSVC ABI
> ```

### npcap(window)
1. [Npcap](https://npcap.com/#download)에서 installer 다운로드 및 실행
   - 설치 시 **WinPcap API-compatible Mode** 체크 필수
2. [Npcap SDK](https://npcap.com/#download)에서 Npcap SDK 다운로드
3. **LIB 환경 변수 설정**:
   - SDK의 `/Lib` 또는 `/Lib/x64` 폴더를 LIB 환경 변수에 추가
   - **PowerShell에서 임시 설정**:
     ```bash
     $env:LIB += ";<npcap 설치경로>"

     # ex: $env:LIB += ";C:\Users\User\Downloads\npcap-sdk-1.15\Lib\x64"
     ```
   - **영구 설정** (시스템 환경 변수):
     - 제어판 → 시스템 → 고급 시스템 설정 → 환경 변수
     - 시스템 변수에서 `LIB` 선택 → 편집 → 새로 만들기로 SDK 경로 추가 
  > [!NOTE] 
  > .cargo/config.toml에서 수동 링크 설정도 가능합니다.  
  > 환경변수를 설정하고 싶지 않은 경우 해당 방안을 추천합니다.
  >

### 실행
```bash
cargo run --release
```

GUI에서:
1. **네트워크 인터페이스**에서 사용중인 네트워크를 선택
2. **시작** 버튼을 클릭하여 처리 시작
3. 처리 완료 후 테이블별로 그룹화된 결과 확인
4. 왼쪽 테이블, SQL을 선택해서 테이블, SQL 별로 필터링하여 확인

## 로그 파일

프로그램 실행 중 캡처된 SQL 이벤트는 자동으로 로그 파일로 저장됩니다.

### 로그 파일 위치
- 로그 파일은 두 개의 폴더로 분리되어 저장됩니다
  - `log/basic/`: 기본 SQL 텍스트만 포함하는 로그 파일
  - `log/raw/`: 원본 데이터(Hex)를 포함하는 로그 파일
- 캡처 시작 시 자동으로 `log/basic` 및 `log/raw` 폴더가 생성됩니다

### 로그 파일 종류

프로그램은 두 가지 타입의 로그 파일을 생성합니다

1. `log/basic/sql_capture_YYYYMMDD_HHMMSS.log`
   - SQL 텍스트만 포함하는 로그 파일
   - 각 이벤트의 타임스탬프, Flow ID, 테이블 정보, SQL 쿼리만 기록

2. `log/raw/sql_capture_YYYYMMDD_HHMMSS.log`
   - 기존 데이터 + 원본 TDS 패킷 데이터(Hex)를 포함하는 로그 파일
   - 디버깅 용(추후 decoding이 잘못된 형식이 나올 수도 있음)

### 로그 파일 형식

각 로그 파일은 다음과 같은 구조를 가집니다

```
================================================================================
Capture Started: 2025-12-30 12:34:56.789
Interface: <네트워크 인터페이스 이름>
================================================================================

================================================================================
Timestamp: 2025-12-30 12:34:56.890
Flow: 192.168.1.100:12345->192.168.1.200:1433
Tables: dbo.TB_Users, dbo.TB_Orders
SQL:
SELECT * FROM dbo.TB_Users WHERE id = 1
================================================================================

...

================================================================================
Capture Stopped: 2025-12-30 12:35:10.123
Total Events: 42
================================================================================
```

원본 데이터 로그 파일(`log/raw/sql_capture_*.log`)에는 각 이벤트에 추가로 다음과 같은 Hex 데이터가 포함됩니다

```
Raw Data (Hex):
00000000:  01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10
00000010:  11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20
...
```