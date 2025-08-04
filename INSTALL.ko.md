# LogSentinelAI 설치 및 사용 가이드 (RHEL & Ubuntu)

이 문서는 LogSentinelAI를 RHEL(RockyLinux, CentOS 등) 및 Ubuntu 환경에서 설치, 설정, 테스트하는 전체 과정을 매우 상세하게 안내합니다. 각 단계별로 명확한 명령어, 주의사항, 실전 예시를 포함합니다.

---

## 1. 시스템 요구사항

- **운영체제**: RHEL 8/9, RockyLinux 8/9, CentOS 8/9, Ubuntu 20.04/22.04 (WSL2 포함)
- **Python**: 3.11 이상 (3.12 권장)
- **메모리**: 최소 4GB (LL# 실시간 모니터링 (로컬)
logsentinelai-linux-system --mode realtime
# SSH 원격 로그 분석
logsentinelai-linu각 분석기에서 원하는 결과 구조만 선언하면, LLM이 자동으로 해당 구조에 맞는 결과를 반환해 주므로 별도의 파싱 작업이 필요 없습니다.

---mote --ssh admin@192.168.1.100 --ssh-key ~/.ssh/id_rsa --log-path /var/log/messages
# 수동 GeoIP DB 다운로드/경로 지정
logsentinelai-geoip-download --output-dir ~/.logsentinelai/시 8GB 이상 권장)
- **디스크**: 2GB 이상 여유 공간
- **네트워크**: PyPI, GitHub, OpenAI, Ollama/vLLM 등 외부 접속 필요
- **(선택) Docker**: Elasticsearch/Kibana, vLLM, Ollama 등 컨테이너 실행 시 필요

---


## 2. uv 설치 및 가상환경 생성

### 2.1 uv 설치
```bash
# Python 3.9+ 환경에서 uv 설치
python3 -m pip install --user uv
# 또는
pip3 install --user uv

# PATH 추가 (필요시)
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# 설치 확인
uv --version
```

### 2.2 Python 3.11+ 설치 및 가상환경 생성
```bash
# Python 3.11 설치
uv python install 3.11

# 가상환경 생성 및 활성화
uv venv --python=3.11 logsentinelai-venv
source logsentinelai-venv/bin/activate

# 프롬프트가 (logsentinelai-venv)로 변경되는지 확인
```

---

## 3. LogSentinelAI 설치

### 3.1 PyPI에서 설치 (권장)
```bash
# uv를 사용한 설치
uv sync
uv pip install -U logsentinelai
```

### 3.2 GitHub 소스에서 설치 (개발/최신)
```bash
git clone https://github.com/call518/LogSentinelAI.git
cd LogSentinelAI
uv sync
uv pip install .
```

---

## 4. 필수 외부 도구 설치

### 4.1 (선택) Docker 설치
- [공식 Docker 설치 가이드](https://docs.docker.com/engine/install/)
- RHEL/Ubuntu 모두 공식 문서 참고

### 4.2 (선택) Ollama 설치 (로컬 LLM)
- [Ollama 공식 설치](https://ollama.com/download)
```bash
curl -fsSL https://ollama.com/install.sh | sh
systemctl start ollama
ollama pull gemma3:1b
```

### 4.3 (선택) vLLM 설치 (로컬 GPU LLM)
```bash
# Docker 기반 vLLM 설치 및 모델 다운로드 예시
git clone https://github.com/call518/vLLM-Tutorial.git
cd vLLM-Tutorial
uv pip install huggingface_hub
huggingface-cli download lmstudio-community/Qwen2.5-3B-Instruct-GGUF Qwen2.5-3B-Instruct-Q4_K_M.gguf --local-dir ./models/Qwen2.5-3B-Instruct/
huggingface-cli download Qwen/Qwen2.5-3B-Instruct generation_config.json --local-dir ./config/Qwen2.5-3B-Instruct
# Docker로 vLLM 실행
./run-docker-vllm---Qwen2.5-1.5B-Instruct.sh
# API 정상 동작 확인
curl -s -X GET http://localhost:5000/v1/models | jq
```

#### vLLM generation_config.json 예시 (권장값)
```json
{
  "temperature": 0.1,
  "top_p": 0.5,
  "top_k": 20
}
```

---


## 5. 설정 파일 준비 및 주요 옵션

```bash
cd ~/LogSentinelAI  # 소스 설치 시
curl -o config https://raw.githubusercontent.com/call518/LogSentinelAI/main/config.template
nano config  # 또는 vim config
# OPENAI_API_KEY 등 필수 항목 입력
```

### config 주요 항목 예시
```ini
# LLM Provider 및 모델
LLM_PROVIDER=openai   # openai/ollama/vllm/gemini
LLM_MODEL_OPENAI=gpt-4o-mini
LLM_MODEL_OLLAMA=gemma3:1b
LLM_MODEL_VLLM=Qwen/Qwen2.5-1.5B-Instruct
LLM_MODEL_GEMINI=gemini-1.5-pro

# OpenAI API Key
OPENAI_API_KEY=sk-...

# Gemini API Key (required if using Gemini provider)
GEMINI_API_KEY=YOUR_GEMINI_API_KEY_HERE

# 분석 결과 언어
RESPONSE_LANGUAGE=korean   # 또는 english

# 분석 모드
ANALYSIS_MODE=batch        # batch/realtime

# 로그 파일 경로(배치/실시간)
LOG_PATH_HTTPD_ACCESS=sample-logs/access-10k.log
LOG_PATH_HTTPD_APACHE_ERROR=sample-logs/apache-10k.log
LOG_PATH_LINUX_SYSTEM=sample-logs/linux-2k.log
LOG_PATH_REALTIME_HTTPD_ACCESS=/var/log/apache2/access.log
LOG_PATH_REALTIME_HTTPD_APACHE_ERROR=/var/log/apache2/error.log
LOG_PATH_REALTIME_LINUX_SYSTEM=/var/log/messages

# chunk size(분석 단위)
CHUNK_SIZE_HTTPD_ACCESS=10
CHUNK_SIZE_HTTPD_APACHE_ERROR=10
CHUNK_SIZE_LINUX_SYSTEM=10

# 실시간 모드 옵션
REALTIME_POLLING_INTERVAL=5
REALTIME_MAX_LINES_PER_BATCH=50
REALTIME_POSITION_FILE_DIR=.positions
REALTIME_BUFFER_TIME=2
REALTIME_PROCESSING_MODE=full     # full/sampling
REALTIME_SAMPLING_THRESHOLD=100

# GeoIP 옵션
GEOIP_ENABLED=true
GEOIP_DATABASE_PATH=~/.logsentinelai/GeoLite2-City.mmdb
GEOIP_FALLBACK_COUNTRY=Unknown
GEOIP_INCLUDE_PRIVATE_IPS=false

# Elasticsearch 연동 옵션(선택)
ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=changeme
```

---


## 6. GeoIP DB 자동/수동 설치 및 활용

- 최초 실행 시 GeoIP City DB가 자동 다운로드되어 `~/.logsentinelai/`에 저장됨(권장)
- 수동 다운로드 필요 시:
```bash
logsentinelai-geoip-download
# 또는
logsentinelai-geoip-download --output-dir ~/.logsentinelai/
```

### GeoIP 주요 특징
- City/country/coordinates(geo_point) 자동 부여, Kibana 지도 시각화 지원
- Private IP는 geo_point 제외
- DB 미존재 시에도 분석은 정상 진행(GeoIP enrich만 생략)

---


## 7. 샘플 로그 파일 준비(테스트용)

```bash
# 이미 git clone을 한 경우에는 아래 명령은 생략해도 됩니다.
git clone https://github.com/call518/LogSentinelAI.git
cd LogSentinelAI/sample-logs
ls *.log  # 다양한 샘플 로그 확인
```

---

## 8. Elasticsearch & Kibana 설치 및 연동(선택)

### 8.1 Docker 기반 ELK 스택 설치
```bash
git clone https://github.com/call518/Docker-ELK.git
cd Docker-ELK
docker compose up setup
docker compose up kibana-genkeys  # 키 생성(권장)
docker compose up -d
# http://localhost:5601 접속, elastic/changeme
```


### 8.2 Elasticsearch 인덱스/정책/템플릿 설정

아래 명령은 Kibana/Elasticsearch가 정상적으로 실행 중일 때(기본: http://localhost:5601, http://localhost:9200) 터미널에서 직접 실행합니다. 기본 계정은 `elastic`/`changeme`입니다.

#### 1) ILM 정책 생성 (7일 보관, 10GB/1일 롤오버)
```bash
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
```

#### 2) 인덱스 템플릿 생성
```bash
curl -X PUT "localhost:9200/_index_template/logsentinelai-analysis-template" \
-H "Content-Type: application/json" \
-u elastic:changeme \
-d '{
  "index_patterns": ["logsentinelai-analysis-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.lifecycle.name": "logsentinelai-analysis-policy",
      "index.lifecycle.rollover_alias": "logsentinelai-analysis",
      "index.mapping.total_fields.limit": "10000"
    },
    "mappings": {
      "properties": {
        "@log_raw_data": {
          "type": "object",
          "dynamic": false
        },
        "events": {
          "type": "object",
          "properties": {
            "source_ips": {
              "type": "object",
              "properties": {
                "ip": { "type": "ip" },
                "location": { "type": "geo_point" }
              }
            },
            "dest_ips": {
              "type": "object",
              "properties": {
                "ip": { "type": "ip" },
                "location": { "type": "geo_point" }
              }
            }
          }
        }
      }
    }
  }
}'
```

#### 3) 초기 인덱스 및 write alias 생성
```bash
curl -X PUT "localhost:9200/logsentinelai-analysis-000001" \
-H "Content-Type: application/json" \
-u elastic:changeme \
-d '{
  "aliases": {
    "logsentinelai-analysis": {
      "is_write_index": true
    }
  }
}'
```

#### 4) Kibana 대시보드/설정 임포트
1. http://localhost:5601 접속 (elastic/changeme)
2. Stack Management → Saved Objects → Import
3. `Kibana-9.0.3-Advanced-Settings.ndjson` → `Kibana-9.0.3-Dashboard-LogSentinelAI.ndjson` 순서로 임포트
4. Analytics > Dashboard > LogSentinelAI Dashboard에서 결과 확인

---


## 9. LogSentinelAI 주요 명령어 및 동작 테스트

### 9.1 명령어 전체 목록 확인
```bash
logsentinelai --help
```

### 9.2 주요 분석 명령어 예시
```bash
# HTTP Access 로그 분석(배치)
logsentinelai-httpd-access --log-path sample-logs/access-10k.log
# Apache Error 로그 분석
logsentinelai-httpd-apache --log-path sample-logs/apache-10k.log
# Linux System 로그 분석
logsentinelai-linux-system --log-path sample-logs/linux-2k.log
# 실시간 모니터링(로컬)
logsentinelai-linux-system --mode realtime
# SSH 원격 로그 분석
logsentinelai-linux-system --remote --ssh admin@192.168.1.100 --ssh-key ~/.ssh/id_rsa --log-path /var/log/messages
# GeoIP DB 수동 다운로드/경로 지정
logsentinelai-geoip-download --output-dir ~/.logsentinelai/
```

### 9.3 CLI 옵션 요약

| 옵션 | 설명 | config 기본값 | CLI로 덮어쓰기 |
|------|------|---------------|---------------|
| --log-path <path> | 분석할 로그 파일 경로 | LOG_PATH_* | O |
| --mode <mode> | batch/realtime 분석 모드 | ANALYSIS_MODE | O |
| --chunk-size <num> | 분석 단위(라인 수) | CHUNK_SIZE_* | O |
| --processing-mode <mode> | 실시간 처리(full/sampling) | REALTIME_PROCESSING_MODE | O |
| --sampling-threshold <num> | 샘플링 임계값 | REALTIME_SAMPLING_THRESHOLD | O |
| --remote | SSH 원격 분석 활성화 | REMOTE_LOG_MODE | O |
| --ssh <user@host:port> | SSH 접속 정보 | REMOTE_SSH_* | O |
| --ssh-key <path> | SSH 키 경로 | REMOTE_SSH_KEY_PATH | O |
| --help | 도움말 | - | - |

> CLI 옵션이 config 파일보다 항상 우선 적용됨

### 9.8 SSH 원격 로그 분석
```bash
logsentinelai-linux-system --remote --ssh admin@192.168.1.100 --ssh-key ~/.ssh/id_rsa --log-path /var/log/messages
```
- **Tip:** 대상 서버를 미리 known_hosts에 등록해야 함 (`ssh-keyscan -H <host> >> ~/.ssh/known_hosts`)

### 9.9 GeoIP DB 수동 다운로드/경로 지정
```bash
logsentinelai-geoip-download --output-dir ~/.logsentinelai/
```

---


## 10. Declarative Extraction(선언적 추출) 사용법

LogSentinelAI의 가장 큰 특징은 **Declarative Extraction**입니다. 각 분석기에서 원하는 결과 구조(Pydantic class)만 선언하면, LLM이 해당 구조에 맞춰 자동으로 로그를 분석하고 JSON으로 결과를 반환합니다. 복잡한 파싱/후처리 없이 원하는 필드만 선언하면 AI가 알아서 결과를 채워줍니다.

### 10.1 기본 사용법

1. 분석기 스크립트에서 결과로 받고 싶은 구조(Pydantic class)를 선언합니다.
2. 분석 명령을 실행하면, LLM이 해당 구조에 맞는 JSON을 자동 생성합니다.

#### 예시: HTTP Access 로그 분석기 커스터마이징
```python
from pydantic import BaseModel

class MyAccessLogResult(BaseModel):
    ip: str
    url: str
    is_attack: bool
```
이렇게 원하는 필드만 정의하면, LLM이 아래와 같은 결과를 자동 생성합니다:
```json
{
  "ip": "192.168.0.1",
  "url": "/admin.php",
  "is_attack": true
}
```

#### 예시: Apache Error 로그 분석기 커스터마이징
```python
from pydantic import BaseModel

class MyApacheErrorResult(BaseModel):
    log_level: str
    event_message: str
    is_critical: bool
```

#### 예시: Linux System 로그 분석기 커스터마이징
```python
from pydantic import BaseModel

class MyLinuxLogResult(BaseModel):
    event_type: str
    user: str
    is_anomaly: bool
```

이처럼 각 분석기에서 원하는 결과 구조만 선언하면, 복잡한 파싱 없이 LLM이 자동으로 해당 구조에 맞는 결과를 반환합니다.

---

## 11. 고급 사용 예시

### 11.1 config 파일로 기본값 설정 & CLI로 덮어쓰기
```bash
# config 파일에서 CHUNK_SIZE_LINUX_SYSTEM=20 설정
logsentinelai-linux-system --chunk-size 10  # CLI 옵션이 우선 적용
```


### 11.2 실시간 모드 자동 샘플링 동작 및 원리
```bash
logsentinelai-httpd-access --mode realtime --processing-mode full --sampling-threshold 100
# 대량 로그 유입 시 자동 샘플링 전환 확인
```

#### 샘플링 동작 예시
1. 평시: 15줄 유입 → FULL 모드(임계값 미만), chunk_size만큼 분석
2. 트래픽 폭증: 250줄 유입 → 임계값(100) 초과 시 SAMPLING 모드 자동 전환, 최신 10줄만 분석, 나머지 스킵(로그 원본은 보존)
3. 트래픽 정상화: 다시 FULL 모드 복귀

#### 샘플링 전략
- FIFO 버퍼, 임계값 초과 시 최신 chunk_size만 분석
- 심각도/패턴 기반 우선순위 없음(순수 시간순)
- 분석 누락 가능성 있음(로그 원본은 보존)


### 11.3 Kibana 대시보드 임포트
1. http://localhost:5601 접속 (elastic/changeme)
2. Stack Management → Saved Objects → Import
3. `Kibana-9.0.3-Advanced-Settings.ndjson` → `Kibana-9.0.3-Dashboard-LogSentinelAI.ndjson` 순서로 임포트
4. Analytics > Dashboard > LogSentinelAI Dashboard에서 결과 확인

---


## 12. 문제 해결 FAQ

- **pip install 시 Permission denied**: 가상환경 활성화 또는 `pip install --user` 사용
- **Python 3.11 not found**: 설치 경로 확인, `python3.11` 명령 직접 사용
- **Elasticsearch/Kibana 접속 불가**: Docker 상태, 포트 충돌, 방화벽 확인
- **GeoIP DB 다운로드 실패**: 수동 다운로드 후 config에서 경로 지정
- **SSH 원격 분석 오류**: SSH 키 권한, known_hosts, 방화벽, 포트 확인
- **LLM API 오류**: OPENAI_API_KEY, Ollama/vLLM 서버 상태, 네트워크 확인

---

## 13. 참고 링크 및 문의
- [LogSentinelAI GitHub](https://github.com/call518/LogSentinelAI)
- [Docker-ELK 공식](https://github.com/deviantony/docker-elk)
- [Ollama 공식](https://ollama.com/)
- [vLLM 공식](https://github.com/vllm-project/vllm)
- [Python 공식](https://www.python.org/downloads/)

**문의/피드백**: GitHub Issue, Discussions, Pull Request 환영

---

## Appendix

### A. 실시간 자동 샘플링(Auto-Sampling) 상세 메커니즘

실시간 모드에서 대량의 로그가 유입될 때 시스템이 어떻게 자동으로 처리 모드를 전환하는지에 대한 상세한 설명입니다.

#### A.1 관련 매개변수 및 역할

| 매개변수 | 기본값 | 역할 | 영향 |
|---------|--------|------|------|
| `REALTIME_PROCESSING_MODE` | `full` | 기본 처리 모드 (full/sampling) | 시작 시 처리 방식 결정 |
| `REALTIME_SAMPLING_THRESHOLD` | `100` | 자동 샘플링 전환 임계값 | 대기 중인 로그 라인 수 기준 |
| `CHUNK_SIZE_*` | `10` | LLM 분석 단위 | 한 번에 분석할 로그 라인 수 |
| `REALTIME_POLLING_INTERVAL` | `5` | 폴링 간격 (초) | 로그 파일 확인 주기 |
| `REALTIME_MAX_LINES_PER_BATCH` | `50` | 읽기 제한 | 한 번에 읽을 최대 라인 수 |
| `REALTIME_BUFFER_TIME` | `2` | 버퍼링 시간 (초) | 불완전한 로그 라인 방지 |

#### A.2 자동 샘플링 발동 시나리오

##### 시나리오 1: 평상시 로그 처리 (FULL 모드 유지)
```
설정값:
- CHUNK_SIZE_HTTPD_ACCESS = 10
- REALTIME_SAMPLING_THRESHOLD = 100
- REALTIME_POLLING_INTERVAL = 5
- REALTIME_MAX_LINES_PER_BATCH = 50

동작 과정:
1. 5초마다 /var/log/apache2/access.log 확인
2. 신규 로그 15줄 발견 → 내부 대기 버퍼에 추가
3. 대기 버퍼: 15줄 (임계값 100 미만)
4. CHUNK_SIZE(10)만큼 처리: 10줄 LLM 분석, 5줄 대기
5. 다음 폴링에서 추가 로그 확인
```

##### 시나리오 2: 트래픽 급증 시 자동 샘플링 전환
```
설정값: 동일

급증 상황:
1. 5초마다 폴링하는데 매번 50줄씩(MAX_LINES_PER_BATCH) 읽음
2. 여러 폴링 사이클 동안 지속적으로 대량 로그 유입
3. 대기 버퍼 누적: 20줄 → 45줄 → 85줄 → 125줄
4. 125줄 > 임계값(100) ▶️ 자동 SAMPLING 모드 전환

SAMPLING 모드 동작:
- 시스템이 "AUTO-SWITCH: Pending lines (125) exceed threshold (100)" 출력
- "SWITCHING TO SAMPLING MODE" 메시지 표시
- 대기 중인 125줄 중 최신 10줄(CHUNK_SIZE)만 선택
- 나머지 115줄은 폐기 (원본 로그 파일은 보존)
- "SAMPLING: Discarded 115 older lines, keeping latest 10" 메시지 출력
- LLM에 최신 10줄만 전송하여 분석
- 메모리 사용량 제한, 시스템 과부하 방지
```

##### 시나리오 3: 트래픽 정상화 후 FULL 모드 복귀
```
정상화 과정:
1. 로그 유입량 감소: 폴링당 5-15줄 정도
2. 대기 버퍼가 임계값(100) 미만으로 감소
3. 자동으로 FULL 모드로 복귀
4. 다시 모든 로그를 순차적으로 처리
```

#### A.3 실제 사용 예시

##### 웹 서버 DDoS 공격 상황
```bash
# 설정: config 파일에서
CHUNK_SIZE_HTTPD_ACCESS=15
REALTIME_SAMPLING_THRESHOLD=200
REALTIME_POLLING_INTERVAL=3

# 실행
logsentinelai-httpd-access --mode realtime

# 상황별 동작:
# 평시: 초당 10-20개 요청 → FULL 모드로 모든 로그 분석
# 공격: 초당 500+ 요청 → 대기 버퍼 200줄 초과 시 SAMPLING 모드
# SAMPLING: 최신 15줄만 분석, 나머지 무시하여 시스템 보호
# 공격 종료: 요청량 정상화 → 자동 FULL 모드 복귀
```

##### 시스템 로그 대량 생성 상황
```bash
# 설정
CHUNK_SIZE_LINUX_SYSTEM=20
REALTIME_SAMPLING_THRESHOLD=150

# 상황: 시스템 오류로 초당 100줄의 에러 로그 생성
# 1-2분 내에 대기 버퍼가 150줄 초과
# → 자동 SAMPLING: 최신 20줄만 분석
# → 시스템 리소스 보호, 최신 오류만 우선 분석
```

#### A.4 샘플링 전략의 특징 및 한계

##### 장점
- **자동화**: 사용자 개입 없이 시스템 부하 제어
- **메모리 보호**: 무제한 버퍼 증가 방지
- **최신성 보장**: 가장 최근 로그에 집중
- **원본 보존**: 로그 파일 자체는 손상되지 않음

##### 한계
- **분석 누락**: 샘플링 시 일부 로그 분석 생략
- **순서 기반**: 시간순 처리, 심각도 기반 우선순위 없음
- **일시적 맹점**: 급증 구간의 패턴 분석 제한

##### 권장 튜닝 방법
```bash
# 고성능 시스템 (메모리 충분)
REALTIME_SAMPLING_THRESHOLD=500
CHUNK_SIZE_*=25

# 저사양 시스템 (메모리 제한적)
REALTIME_SAMPLING_THRESHOLD=50
CHUNK_SIZE_*=5

# 중요 로그 (누락 최소화)
REALTIME_SAMPLING_THRESHOLD=1000
REALTIME_POLLING_INTERVAL=2

# 일반 모니터링 (효율성 우선)
REALTIME_SAMPLING_THRESHOLD=100
REALTIME_POLLING_INTERVAL=10
