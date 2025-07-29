# LogSentinelAI 설치 및 사용 가이드 (RHEL & Ubuntu)

이 문서는 LogSentinelAI를 RHEL(RockyLinux, CentOS 등) 및 Ubuntu 환경에서 설치, 설정, 테스트하는 전체 과정을 매우 상세하게 안내합니다. 각 단계별로 명확한 명령어, 주의사항, 실전 예시를 포함합니다.

---

## 1. 시스템 요구사항

- **운영체제**: RHEL 8/9, RockyLinux 8/9, CentOS 8/9, Ubuntu 20.04/22.04 (WSL2 포함)
- **Python**: 3.11 이상 (3.12 권장)
- **메모리**: 최소 4GB (LLM 로컬 실행 시 8GB 이상 권장)
- **디스크**: 2GB 이상 여유 공간
- **네트워크**: PyPI, GitHub, OpenAI, Ollama/vLLM 등 외부 접속 필요
- **(선택) Docker**: Elasticsearch/Kibana, vLLM, Ollama 등 컨테이너 실행 시 필요

---


## 2. uv 설치 및 최신 Python 준비

### 2.1 uv 설치 (pip로)
```bash
python3 -m pip install --user --upgrade uv
# 또는
pip3 install --user --upgrade uv
# uv 명령이 PATH에 없으면 아래 추가
export PATH="$HOME/.local/bin:$PATH"
uv --version  # 정상 출력 확인
```

### 2.2 최신 Python 설치 (예: 3.11)
```bash
uv pip install -U pip  # uv pip 최신화(권장)
uv python install 3.11
uv python list  # 설치된 python 목록 확인
```

---

## 3. uv로 가상환경 생성 및 활성화

```bash
uv venv --python=3.11 --seed ~/logsentinelai-venv
source ~/logsentinelai-venv/bin/activate
# 프롬프트가 (logsentinelai-venv)로 바뀌는지 확인
```

---

## 4. LogSentinelAI 설치

### 4.1 PyPI에서 설치(권장)
```bash
pip install --upgrade pip
pip install logsentinelai
```

### 4.2 GitHub 소스 직접 설치(개발/최신)
```bash
git clone https://github.com/call518/LogSentinelAI.git
cd LogSentinelAI
pip install .
```

---

## 5. 필수 외부 도구 설치

### 5.1 (선택) Docker 설치
- [공식 Docker 설치 가이드](https://docs.docker.com/engine/install/)
- RHEL/Ubuntu 모두 공식 문서 참고

### 5.2 (선택) Ollama 설치 (로컬 LLM)
- [Ollama 공식 설치](https://ollama.com/download)
- Ubuntu: `curl -fsSL https://ollama.com/install.sh | sh`
- RHEL: 공식 지원 없음, Ubuntu 컨테이너/WSL2 권장


### 5.3 (선택) vLLM 설치 (로컬 GPU LLM)
```bash
# (A) PyPI 설치
pip install vllm

# (B) Docker 기반 vLLM 설치 및 모델 다운로드 예시
git clone https://github.com/call518/vLLM-Tutorial.git
cd vLLM-Tutorial
pip install huggingface_hub
huggingface-cli download lmstudio-community/Qwen2.5-3B-Instruct-GGUF Qwen2.5-3B-Instruct-Q4_K_M.gguf --local-dir ./models/Qwen2.5-3B-Instruct/
huggingface-cli download Qwen/Qwen2.5-3B-Instruct generation_config.json --local-dir ./config/Qwen2.5-3B-Instruct
# Docker로 vLLM 실행
./run-docker-vllm---Qwen2.5-1.5B-Instruct.sh
# API 정상 동작 확인
curl -s -X GET http://localhost:5000/v1/models | jq
```

#### vLLM config 예시 (권장값)
```json
{
  "temperature": 0.1,
  "top_p": 0.5,
  "top_k": 20
}
```

---


## 6. 설정 파일 준비 및 주요 옵션

```bash
cd ~/LogSentinelAI  # 소스 설치 시
curl -o config https://raw.githubusercontent.com/call518/LogSentinelAI/main/config.template
nano config  # 또는 vim config
# OPENAI_API_KEY 등 필수 항목 입력
```

### config 주요 항목 예시
```ini
# LLM Provider 및 모델
LLM_PROVIDER=openai   # openai/ollama/vllm
LLM_MODEL_OPENAI=gpt-4o-mini
LLM_MODEL_OLLAMA=qwen2.5:1.5b
LLM_MODEL_VLLM=Qwen/Qwen2.5-1.5B-Instruct

# OpenAI API Key
OPENAI_API_KEY=sk-...

# 분석 결과 언어
RESPONSE_LANGUAGE=korean   # 또는 english

# 분석 모드
ANALYSIS_MODE=batch        # batch/realtime

# 로그 파일 경로(배치/실시간)
LOG_PATH_HTTPD_ACCESS=sample-logs/access-10k.log
LOG_PATH_APACHE_ERROR=sample-logs/apache-10k.log
LOG_PATH_LINUX_SYSTEM=sample-logs/linux-2k.log
LOG_PATH_TCPDUMP_PACKET=sample-logs/tcpdump-packet-2k.log
LOG_PATH_REALTIME_HTTPD_ACCESS=/var/log/apache2/access.log
LOG_PATH_REALTIME_APACHE_ERROR=/var/log/apache2/error.log
LOG_PATH_REALTIME_LINUX_SYSTEM=/var/log/messages
LOG_PATH_REALTIME_TCPDUMP_PACKET=/var/log/tcpdump.log

# chunk size(분석 단위)
CHUNK_SIZE_HTTPD_ACCESS=10
CHUNK_SIZE_APACHE_ERROR=10
CHUNK_SIZE_LINUX_SYSTEM=10
CHUNK_SIZE_TCPDUMP_PACKET=5

# 실시간 모드 옵션
REALTIME_POLLING_INTERVAL=5
REALTIME_MAX_LINES_PER_BATCH=50
REALTIME_POSITION_FILE_DIR=.positions
REALTIME_BUFFER_TIME=2
REALTIME_PROCESSING_MODE=full     # full/sampling/auto-sampling
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


## 7. GeoIP DB 자동/수동 설치 및 활용

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


## 8. 샘플 로그 파일 준비(테스트용)

```bash
# 이미 git clone을 한 경우에는 아래 명령은 생략해도 됩니다.
git clone https://github.com/call518/LogSentinelAI.git
cd LogSentinelAI/sample-logs
ls *.log  # 다양한 샘플 로그 확인
```

---

## 9. Elasticsearch & Kibana 설치 및 연동(선택)

### 9.1 Docker 기반 ELK 스택 설치
```bash
git clone https://github.com/call518/Docker-ELK.git
cd Docker-ELK
docker compose up setup
docker compose up kibana-genkeys  # 키 생성(권장)
docker compose up -d
# http://localhost:5601 접속, elastic/changeme
```


### 9.2 Elasticsearch 인덱스/정책/템플릿 설정

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
  "index_patterns": ["logsentinelai-analysis-*"] ,
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
        },
        "statistics": {
          "type": "object",
          "properties": {
            "top_source_ips": {
              "type": "object",
              "properties": {
                "ip": { "type": "ip" },
                "location": { "type": "geo_point" },
                "count": { "type": "integer" }
              }
            },
            "top_dest_ips": {
              "type": "object",
              "properties": {
                "ip": { "type": "ip" },
                "location": { "type": "geo_point" },
                "count": { "type": "integer" }
              }
            },
            "top_event_ips": {
              "type": "object",
              "properties": {
                "ip": { "type": "ip" },
                "location": { "type": "geo_point" },
                "count": { "type": "integer" }
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


## 10. LogSentinelAI 주요 명령어 및 동작 테스트

### 10.1 명령어 전체 목록 확인
```bash
logsentinelai --help
```

### 10.2 주요 분석 명령어 예시
```bash
# HTTP Access 로그 분석(배치)
logsentinelai-httpd-access --log-path sample-logs/access-10k.log
# Apache Error 로그 분석
logsentinelai-apache-error --log-path sample-logs/apache-10k.log
# Linux System 로그 분석
logsentinelai-linux-system --log-path sample-logs/linux-2k.log
# TCPDump 패킷 로그 분석
logsentinelai-tcpdump --log-path sample-logs/tcpdump-packet-10k-single-line.log
# 실시간 모니터링(로컬)
logsentinelai-linux-system --mode realtime
# 실시간 샘플링 모드
logsentinelai-tcpdump --mode realtime --processing-mode sampling --sampling-threshold 50
# SSH 원격 로그 분석
logsentinelai-linux-system --remote --ssh admin@192.168.1.100 --ssh-key ~/.ssh/id_rsa --log-path /var/log/messages
# GeoIP DB 수동 다운로드/경로 지정
logsentinelai-geoip-download --output-dir ~/.logsentinelai/
```

### 10.3 CLI 옵션 요약

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

### 10.8 SSH 원격 로그 분석
```bash
logsentinelai-linux-system --remote --ssh admin@192.168.1.100 --ssh-key ~/.ssh/id_rsa --log-path /var/log/messages
```
- **Tip:** 대상 서버를 미리 known_hosts에 등록해야 함 (`ssh-keyscan -H <host> >> ~/.ssh/known_hosts`)

### 10.9 GeoIP DB 수동 다운로드/경로 지정
```bash
logsentinelai-geoip-download --output-dir ~/.logsentinelai/
```

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

## 13. 참고/권장 링크 및 문의
- [LogSentinelAI GitHub](https://github.com/call518/LogSentinelAI)
- [Docker-ELK 공식](https://github.com/deviantony/docker-elk)
- [Ollama 공식](https://ollama.com/)
- [vLLM 공식](https://github.com/vllm-project/vllm)
- [Python 공식](https://www.python.org/downloads/)

문의/피드백: GitHub Issue, Discussions, Pull Request 환영

---

**LogSentinelAI 설치 및 사용에 어려움이 있다면 언제든 문의해 주세요.**

---

## 13. 참고/권장 링크
- [LogSentinelAI GitHub](https://github.com/call518/LogSentinelAI)
- [Docker-ELK 공식](https://github.com/deviantony/docker-elk)
- [Ollama 공식](https://ollama.com/)
- [vLLM 공식](https://github.com/vllm-project/vllm)
- [Python 공식](https://www.python.org/downloads/)

---

## 14. 문의 및 피드백
- GitHub Issue, Discussions, Pull Request 환영
- 문서/코드 개선 제안, 버그 리포트, 신규 기능 요청 모두 환영합니다!

---

**LogSentinelAI 설치 및 사용에 어려움이 있다면 언제든 문의해 주세요.**
