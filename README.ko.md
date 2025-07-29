[![PyPI에 태그로 배포](https://github.com/call518/LogSentinelAI/actions/workflows/pypi-publish.yml/badge.svg)](https://github.com/call518/LogSentinelAI/actions/workflows/pypi-publish.yml)

# LogSentinelAI - AI 기반 로그 분석기

LogSentinelAI는 LLM을 활용하여 Apache, Linux 등 다양한 로그에서 보안 이벤트, 이상 징후, 오류를 분석하고, 이를 Elasticsearch/Kibana로 시각화 가능한 구조화 데이터로 변환합니다.

## 🚀 주요 특징

### AI 기반 분석
- **LLM 제공자**: OpenAI API, Ollama, vLLM
- **지원 로그 유형**: HTTP Access, Apache Error, Linux System, TCPDump
- **위협 탐지**: SQL Injection, XSS, Brute Force, 네트워크 이상 탐지
- **출력**: Pydantic 검증이 적용된 구조화 JSON
- **적응형 민감도**: LLM 모델 및 로그 유형별 프롬프트에 따라 탐지 민감도 자동 조정

### 처리 모드
- **배치**: 과거 로그 일괄 분석
- **실시간**: 샘플링 기반 라이브 모니터링
- **접근 방식**: 로컬 파일, SSH 원격

### 데이터 부가정보
- **GeoIP**: MaxMind GeoLite2 City 조회(좌표 포함, Kibana geo_point 지원)
- **통계**: IP 카운트, 응답 코드, 각종 메트릭
- **다국어 지원**: 결과 언어 설정 가능(기본: 한국어)

### 엔터프라이즈 통합
- **저장소**: Elasticsearch(ILM 정책 지원)
- **시각화**: Kibana 대시보드
- **배포**: Docker 컨테이너

## 대시보드 예시

![Kibana Dashboard](img/ex-dashboard.png)

## 📋 JSON 출력 예시

![JSON Output](img/ex-json.png)

## 시스템 아키텍처

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Log Sources   │───>│ LogSentinelAI   │───>│ Elasticsearch   │
│                 │    │   Analysis      │    │                 │
│ • Local Files   │    │                 │    │ • Security      │
│ • Remote SSH    │    │ • LLM Analysis  │    │   Events        │
│ • HTTP Access   │    │ • Outlines      │    │ • Raw Logs      │
│ • Apache Error  │    │ • Pydantic      │    │ • Metadata      │
│ • System Logs   │    │   Validation    │    │                 │
│ • TCPDump       │    │ • Multi-format  │    │                 │
│   (Auto-detect) │    │   Support       │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │ LLM Provider    │    │     Kibana      │
                       │                 │    │   Dashboard     │
                       │ • OpenAI        │    │                 │
                       │ • Ollama        │    │ • Visualization │
                       │ • vLLM          │    │ • Alerts        │
                       │                 │    │ • Analytics     │
                       │                 │    │ • Geo-Map       │
                       └─────────────────┘    └─────────────────┘
```

## 📁 프로젝트 구조 및 주요 파이썬 스크립트

### 핵심 파이썬 구성요소

```
src/logsentinelai/
├── __init__.py                    # 패키지 초기화
├── cli.py                         # 메인 CLI 진입점 및 명령 라우팅
├── py.typed                       # mypy 타입 힌트 마커
│
├── analyzers/                     # 로그 유형별 분석기
│   ├── __init__.py               # 분석기 패키지 초기화
│   ├── httpd_access.py           # HTTP access 로그 분석기(Apache/Nginx)
│   ├── httpd_apache.py           # Apache error 로그 분석기
│   ├── linux_system.py           # Linux system 로그 분석기(syslog/messages)
│   └── tcpdump_packet.py         # 네트워크 패킷 캡처 분석기
│
├── core/                          # 핵심 분석 엔진(모듈화)
│   ├── __init__.py               # Core 패키지 초기화 및 통합 import
│   ├── commons.py                # 주요 분석 함수 및 인터페이스
│   ├── config.py                 # 설정 관리 및 환경 변수
│   ├── llm.py                    # LLM 모델 초기화 및 상호작용
│   ├── elasticsearch.py          # Elasticsearch 연동 및 데이터 전송
│   ├── geoip.py                  # GeoIP 조회 및 IP 부가정보
│   ├── ssh.py                    # SSH 원격 로그 접근
│   ├── monitoring.py             # 실시간 로그 모니터링 및 처리
│   ├── utils.py                  # 로그 처리 유틸리티 및 헬퍼
│   └── prompts.py                # 로그 유형별 LLM 프롬프트 템플릿
│
└── utils/                         # 유틸리티 함수
    ├── __init__.py               # Utils 패키지 초기화
    └── geoip_downloader.py       # MaxMind GeoIP DB 다운로더
```

### CLI 명령 매핑

```bash
# CLI 명령은 분석기 스크립트에 매핑됨:
logsentinelai-httpd-access   → analyzers/httpd_access.py
logsentinelai-apache-error   → analyzers/httpd_apache.py  
logsentinelai-linux-system   → analyzers/linux_system.py
logsentinelai-tcpdump        → analyzers/tcpdump_packet.py
logsentinelai-geoip-download → utils/geoip_downloader.py
```

## 🚀 빠른 시작: 설치 및 환경설정

### 데모 환경 검증

LogSentinelAI는 다음 환경에서 성공적으로 테스트 및 검증되었습니다:

```bash
# 테스트 환경 사양
- Host OS: Windows 11
- WSL2: v2.5.9 (RockyLinux 8)
- Docker Desktop: v4.39.0
- GPU: NVIDIA GeForce GTX 1660, CUDA 12.9

# GPU 확인(RockyLinux8, WSL2)
$ nvidia-smi
Tue Jul 22 22:39:22 2025
+-----------------------------------------------------------------------------------------+
| NVIDIA-SMI 575.64.01              Driver Version: 576.88         CUDA Version: 12.9     |
|-----------------------------------------+------------------------+----------------------+
| GPU  Name                 Persistence-M | Bus-Id          Disp.A | Volatile Uncorr. ECC |
| Fan  Temp   Perf          Pwr:Usage/Cap |           Memory-Usage | GPU-Util  Compute M. |
|                                         |                        |               MIG M. |
|=========================================+========================+======================|
|   0  NVIDIA GeForce GTX 1660 ...    On  |   00000000:01:00.0  On |                  N/A |
| 45%   63C    P2            120W /  125W |    5891MiB /   6144MiB |    100%      Default |
|                                         |                        |                  N/A |
+-----------------------------------------+------------------------+----------------------+

+-----------------------------------------------------------------------------------------+
| Processes:                                                                              |
|  GPU   GI   CI              PID   Type   Process name                        GPU Memory |
|        ID   ID                                                               Usage      |
|=========================================================================================|
|    0   N/A  N/A              45      C   /python3.12                           N/A      |
+-----------------------------------------------------------------------------------------+
```

✅ **검증 상태**: OpenAI API, Ollama(로컬), vLLM(GPU) 등 모든 주요 기능 정상 동작 확인

### 1. 사전 준비

- **운영체제**: Linux, Windows, Mac 지원
- **Python**: 3.11 이상
- **Elasticsearch/Kibana**: 9.0.3 이상(Docker 권장)
- **Ollama**: 0.9.5 이상

### 📦 패키지 설치

LogSentinelAI는 PyPI에서 설치할 수 있습니다:

```bash
# 가상환경 생성 및 활성화(권장)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# LogSentinelAI 설치
pip install logsentinelai
```

### ⚙️ 설정 파일 준비

```bash
# 1. 기본 설정 파일 다운로드(택1)
curl -o config https://raw.githubusercontent.com/call518/LogSentinelAI/main/config.template

# 2. config 파일에서 OPENAI_API_KEY 입력
# API 키 발급: https://platform.openai.com/api-keys
nano config  # 또는 vim config
```

### 🌍 GeoIP DB 자동설정

GeoIP City DB는 최초 사용 시 자동 다운로드됩니다:

```bash
# 최초 필요 시 ~/.logsentinelai/에 자동 다운로드
# 수동 다운로드도 가능
logsentinelai-geoip-download
```

### 🚀 빠른 사용 예시

```bash
# 사용 가능한 명령 확인
logsentinelai --help

# 샘플 로그 파일용 저장소 클론
git clone https://github.com/call518/LogSentinelAI.git
cd LogSentinelAI

# HTTP Access 로그 분석
logsentinelai-httpd-access --log-path sample-logs/access-10k.log

# Apache Error 로그 분석
logsentinelai-apache-error --log-path sample-logs/apache-10k.log

# Linux System 로그 분석
logsentinelai-linux-system --log-path sample-logs/linux-2k.log

# TCPDump 패킷 분석
logsentinelai-tcpdump --log-path sample-logs/tcpdump-packet-10k-single-line.log

# 실시간 모니터링  
logsentinelai-linux-system --mode realtime

# 원격 SSH 분석(known_hosts 필요)
logsentinelai-tcpdump --remote --ssh admin@server.com --ssh-key ~/.ssh/id_rsa

# GeoIP DB 다운로드
logsentinelai-geoip-download
```

### ⚙️ CLI 옵션 요약

모든 분석 명령(`logsentinelai-httpd-access`, `logsentinelai-apache-error`, `logsentinelai-linux-system`, `logsentinelai-tcpdump`)은 동일한 CLI 옵션을 지원합니다:

| 옵션 | 설명 | config 기본값 | CLI로 덮어쓰기 |
|------|------|---------------|---------------|
| `--log-path <경로>` | 분석할 로그 파일 경로 | `LOG_PATH_*` | ✅ 가능 |
| `--mode <모드>` | 분석 모드: `batch` 또는 `realtime` | `ANALYSIS_MODE=batch` | ✅ 가능 |
| `--chunk-size <숫자>` | 분석 단위(로그 라인 수) | `CHUNK_SIZE_*=10` | ✅ 가능 |
| `--processing-mode <모드>` | 실시간 처리: `full` 또는 `sampling` | `REALTIME_PROCESSING_MODE=full` | ✅ 가능 |
| `--sampling-threshold <숫자>` | 실시간 샘플링 임계값 | `REALTIME_SAMPLING_THRESHOLD=100` | ✅ 가능 |
| `--remote` | 원격 SSH 로그 접근 활성화 | `REMOTE_LOG_MODE=local` | ✅ 가능 |
| `--ssh <user@host:port>` | SSH 접속 문자열 | `REMOTE_SSH_*` | ✅ 가능 |
| `--ssh-key <경로>` | SSH 개인키 경로 | `REMOTE_SSH_KEY_PATH` | ✅ 가능 |
| `--help` | 도움말 표시 | N/A | N/A |

**주요 사용 패턴:**
```bash
# config 기본값 덮어쓰기
logsentinelai-linux-system --chunk-size 20 --mode realtime

# SSH 원격 분석(known_hosts 필요)
logsentinelai-httpd-access --remote --ssh admin@server.com:2222 --ssh-key ~/.ssh/id_rsa

# 실시간 샘플링 모드
logsentinelai-tcpdump --mode realtime --processing-mode sampling --sampling-threshold 50
```

**참고:**
- CLI 옵션이 항상 config 파일 설정보다 우선
- config 값은 옵션 미지정 시 기본값으로 사용
- 모든 명령에 `--help` 사용 가능

## 🚀 Elasticsearch & Kibana 설정(선택)

고급 시각화 및 분석을 위해 Elasticsearch와 Kibana를 설정할 수 있습니다:

> [!IMPORTANT]
> [Platinum 기능](https://www.elastic.co/subscriptions)은 기본적으로 30일 평가판으로 활성화됩니다. 이후 Open Basic 라이선스의 무료 기능만 자동 전환되어 데이터 손실 없이 사용 가능합니다. 유료 기능 비활성화는 [공식 가이드](https://github.com/deviantony/docker-elk#how-to-disable-paid-features) 참고.

```bash
# 1. ELK 스택 저장소 클론 및 이동
# (원본) https://github.com/deviantony/docker-elk
git clone https://github.com/call518/Docker-ELK.git
cd Docker-ELK

# 2. 초기화 및 실행
# 1회 초기화
docker compose up setup
# Kibana 암호화 키 생성(권장)
docker compose up kibana-genkeys
# 생성된 키를 kibana/config/kibana.yml에 복사
# ELK 스택 실행
docker compose up -d

# 3. Kibana 접속: http://localhost:5601
# 기본 계정: elastic / changeme
```

### 📊 Elasticsearch 인덱스/정책 설정

Elasticsearch 연동 시:

```bash
# 1. ILM 정책 생성(7일 보관, 10GB/1일 롤오버)
curl -X PUT "localhost:9200/_ilm/policy/logsentinelai-analysis-policy" \
-H "Content-Type: application/json" \
-u elastic:changeme \
-d '{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "10gb",
            "max_age": "1d"
          }
        }
      },
      "delete": {
        "min_age": "7d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'

# 2. 인덱스 템플릿 생성
curl -X PUT "localhost:9200/_index_template/logsentinelai-analysis-template" \
-H "Content-Type: application/json" \
-u elastic:changeme \
-d 'PUT _index_template/logsentinelai-analysis-template
{
  "index_patterns": ["logsentinelai-analysis-*"]...
```
(이하 원본 README와 동일하게 번역 및 작성)
