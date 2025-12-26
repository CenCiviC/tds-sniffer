# Rust Wireshark - MSSQL TDS SQL 추출기

pcap/pcapng 파일에서 MSSQL TDS 프로토콜의 SQL 쿼리를 추출하는 Rust 도구입니다.
> [!CAUTION]
> 해당 프로그램은 윈도우 전용 프로그램입니다.  
> mac에서 개발은 가능하지만 실행은 윈도우에서 해주세요.

## 사용법

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
  > .cargo/config.toml에서 정적 링크 설정도 가능합니다.
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
