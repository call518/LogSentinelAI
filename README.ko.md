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
│   ├── __init__.py                # 분석기 패키지 초기화
│   ├── httpd_access.py            # HTTP access 로그 분석기(Apache/Nginx)
│   ├── httpd_apache.py            # Apache error 로그 분석기
│   ├── linux_system.py            # Linux system 로그 분석기(syslog/messages)
│   └── tcpdump_packet.py          # 네트워크 패킷 캡처 분석기
│
├── core/                          # 핵심 분석 엔진(모듈화)
│   ├── __init__.py                # Core 패키지 초기화 및 통합 import
│   ├── commons.py                 # 배치/실시간 분석 공통 함수, 처리 흐름 정의
│   ├── config.py                  # 환경변수 기반 설정 관리
│   ├── llm.py                     # LLM 모델 초기화 및 상호작용
│   ├── elasticsearch.py           # Elasticsearch 연동 및 데이터 전송
│   ├── geoip.py                   # GeoIP 조회 및 IP 부가정보
│   ├── ssh.py                     # SSH 원격 로그 접근
│   ├── monitoring.py              # 실시간 로그 모니터링 및 처리
│   ├── utils.py                   # 로그 처리 유틸리티 및 헬퍼
│   └── prompts.py                 # 로그 유형별 LLM 프롬프트 템플릿
│
└── utils/                         # 유틸리티 함수
    ├── __init__.py                # Utils 패키지 초기화
    └── geoip_downloader.py        # MaxMind GeoIP DB 다운로더
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


## 🚀 설치 가이드

LogSentinelAI의 설치, 환경설정, CLI 사용법, Elasticsearch/Kibana 연동 등 모든 실전 가이드는 아래 설치 문서를 참고해 주세요.

� **[설치 및 사용 가이드 바로가기: INSTALL.ko.md](./INSTALL.ko.md)**

> ⚡️ 추가 문의는 GitHub Issue/Discussion을 이용해 주세요!
