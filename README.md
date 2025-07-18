# SonarLog - AI-Powered Log Security Analysis

SonarLog은 LLM(Large Language Model)을 활용하여 다양한 로그 파일을 분석하고 보안 이벤트를 탐지하는 시스템입니다. Apache HTTP 로그, Linux 시스템 로그 등을 자동으로 분석하여 보안 위협을 식별하고 Elasticsearch에 구조화된 데이터로 저장합니다.

## 🌟 주요 기능

- **다중 로그 형식 지원**: HTTP Access Log, Apache Error Log, Linux System Log
- **AI 기반 보안 분석**: LLM을 통한 지능적인 보안 이벤트 탐지
- **구조화된 데이터 출력**: Pydantic 모델을 사용한 JSON 스키마 검증
- **Elasticsearch 통합**: 실시간 로그 분석 결과 저장 및 검색
- **Kibana 대시보드**: 시각화된 보안 분석 결과 모니터링
- **LOGID 추적**: 원본 로그와 분석 결과의 완전한 추적성 보장

## 📊 대시보드 예시

![Kibana Dashboard](img/ex-dashboard.png)

## 📋 JSON 출력 예시

![JSON Output](img/ex-json.png)

## 🏗️ 시스템 아키텍처

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Log Files     │───▶│   SonarLog      │───▶│ Elasticsearch   │
│                 │    │   Analysis      │    │                 │
│ • HTTP Access   │    │                 │    │ • Security      │
│ • Apache Error  │    │ • LLM Analysis  │    │   Events        │
│ • System Logs   │    │ • Pydantic      │    │ • Raw Logs      │
│                 │    │   Validation    │    │ • Metadata      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │     Kibana      │
                                               │   Dashboard     │
                                               │                 │
                                               │ • Visualization │
                                               │ • Alerts        │
                                               │ • Analytics     │
                                               └─────────────────┘
```

## 🚀 설치 및 설정

### 1. 의존성 설치

```bash
# Python 가상환경 생성 (옵션)
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# 패키지 설치
pip install -r requirements.txt
```

### 2. 환경 변수 설정

```bash
# .env 파일 생성
cp .env.template .env

# OpenAI API 키 설정 (OpenAI 사용 시)
echo "OPENAI_API_KEY=your_api_key_here" >> .env
```

### 3. LLM 모델 설정

#### Option 1: Ollama (로컬 실행)
```bash
# Ollama 설치 및 모델 다운로드
ollama pull qwen2.5-coder:3b
ollama serve
```

#### Option 2: vLLM (GPU 가속)
```bash
# vLLM 설치 및 서버 실행
pip install vllm
python -m vllm.entrypoints.openai.api_server --model qwen2.5-coder:3b
```

#### Option 3: OpenAI API
- `.env` 파일에 `OPENAI_API_KEY` 설정

### 4. Elasticsearch 설정

- Github: https://github.com/call518/Docker-ELK

```bash
# Docker Compose로 Elasticsearch + Kibana 실행
docker-compose up -d

# 또는 로컬 Elasticsearch 설치
# Elasticsearch 9200 포트, Kibana 5601 포트 확인
```

## 💻 사용법

### HTTP Access Log 분석

```bash
python analysis-httpd-access-log.py
```

### Apache Error Log 분석

```bash
python analysis-httpd-apache-log.py
```

### Linux System Log 분석

```bash
python analysis-linux-system-log.py
```

## 📁 프로젝트 구조

```
SonarLog/
├── analysis-httpd-access-log.py    # HTTP 접근 로그 분석기
├── analysis-httpd-apache-log.py    # Apache 에러 로그 분석기
├── analysis-linux-system-log.py    # Linux 시스템 로그 분석기
├── commons.py                      # 공통 함수 및 유틸리티
├── requirements.txt                # Python 의존성
├── .env.template                   # 환경변수 템플릿
├── sample-logs/                    # 샘플 로그 파일들
│   ├── access-10.log
│   ├── apache-10.log
│   └── linux-10.log
├── img/                           # 문서 이미지
│   ├── ex-dashboard.png
│   └── ex-json.png
└── Kibana-Dashboard-SonarLog.ndjson # Kibana 대시보드 설정
```

## 🔧 설정 옵션

### LLM 제공자 변경

`commons.py`에서 LLM 제공자를 변경할 수 있습니다:

```python
# initialize_llm_model 함수에서 설정
model = initialize_llm_model("ollama")    # Ollama
model = initialize_llm_model("vllm")      # vLLM
model = initialize_llm_model("openai")    # OpenAI
```

### 청크 크기 조정

로그 처리 성능을 위해 청크 크기를 조정할 수 있습니다:

```python
# 각 분석 스크립트에서
chunk_size = 10  # 기본값, 필요에 따라 조정
```

## 📊 출력 데이터 스키마

### Security Event 구조

```json
{
  "event_type": "SQL_INJECTION",
  "severity": "HIGH",
  "description": "SQL 인젝션 공격 시도 탐지",
  "confidence_score": 0.85,
  "url_pattern": "/api/users",
  "http_method": "POST",
  "source_ips": ["192.168.1.100"],
  "response_codes": ["403"],
  "attack_patterns": ["SQL_INJECTION"],
  "recommended_actions": ["IP 차단", "WAF 규칙 추가"],
  "requires_human_review": true,
  "related_log_ids": ["LOGID-ABC123", "LOGID-DEF456"]
}
```

### Elasticsearch 문서 구조

```json
{
  "chunk_analysis_start_utc": "2025-07-18T10:00:00Z",
  "chunk_analysis_end_utc": "2025-07-18T10:00:05Z",
  "analysis_result": "success",
  "@log_raw_data": {
    "LOGID-ABC123": "192.168.1.100 - - [18/Jul/2025:10:00:01] GET /api/users",
    "LOGID-DEF456": "192.168.1.100 - - [18/Jul/2025:10:00:02] POST /api/login"
  },
  "security_events": [...],
  "statistics": {...}
}
```

## 🎯 주요 특징

### 1. 지능적인 보안 탐지
- **다양한 공격 패턴 인식**: SQL Injection, XSS, Brute Force, Command Injection 등
- **컨텍스트 기반 분석**: 로그 패턴과 연관성을 고려한 분석
- **신뢰도 점수**: 각 탐지 결과에 대한 신뢰도 제공

### 2. 완전한 추적성
- **LOGID 시스템**: 각 로그 라인에 고유 식별자 부여
- **원본 데이터 보존**: 분석 결과와 함께 원본 로그 데이터 저장
- **관련 로그 매핑**: 보안 이벤트와 관련된 로그 라인들 연결

### 3. 확장 가능한 아키텍처
- **모듈화된 설계**: 각 로그 타입별 독립적인 분석기
- **공통 함수 라이브러리**: 중복 코드 제거 및 유지보수성 향상
- **플러그인 방식**: 새로운 로그 형식 쉽게 추가 가능

## 📈 성능 최적화

### 청크 기반 처리
- 대용량 로그 파일을 작은 청크로 나누어 처리
- 메모리 효율성 및 병렬 처리 지원

### 토큰 최적화
- LLM 입력 토큰 수 최소화를 위한 프롬프트 최적화
- 구조화된 출력을 통한 파싱 효율성 향상

## 🔍 모니터링 및 알람

### Kibana 대시보드
- 실시간 보안 이벤트 모니터링
- 공격 트렌드 및 패턴 분석
- 지리적 위치 기반 공격 시각화

### 알람 설정
- 고위험 보안 이벤트 자동 알람
- 임계치 기반 알람 규칙
- 이메일/Slack 통합 지원

## 🤝 기여하기

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## 🆘 지원 및 문의

- **Issues**: [GitHub Issues](https://github.com/your-repo/sonarlog/issues)
- **Documentation**: [Wiki](https://github.com/your-repo/sonarlog/wiki)
- **Email**: call518@gmail.com

## 🏷️ 버전 정보

- **Current Version**: 1.0.0
- **Python**: 3.11+
- **Elasticsearch**: 8.16+
- **Kibana**: 8.16+

---

**SonarLog** - Intelligent Log Security Analysis with AI 🔍🛡️