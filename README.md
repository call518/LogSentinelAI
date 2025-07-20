# LogSentinelAI - AI-Powered Log Security Analysis

LogSentinelAI is a system that leverages LLM (Large Language Model) to analyze various log files and detect security events. It automatically analyzes Apache HTTP logs, Linux system logs, and other log types to identify security threats and stores them as structured data in Elasticsearch for visualization and analysis.

## 🌟 Key Features

- **Multi-format Log Support**: HTTP Access Log, Apache Error Log, Linux System Log, Network Packet Analysis
- **AI-based Security Analysis**: Intelligent security event detection through LLM
- **Structured Generation**: Uses [Outlines](https://github.com/dottxt-ai/outlines) for reliable JSON output from LLM
- **Network Packet Analysis**: tcpdump packet inspection and security analysis
- **Structured Data Output**: JSON schema validation using Pydantic models
- **Elasticsearch Integration**: Real-time log analysis result storage and search
- **Kibana Dashboard**: Visualized security analysis result monitoring
- **LOGID Tracking**: Complete traceability between original logs and analysis results
- **LLM Provider Support**: Compatible with OpenAI, vLLM, and Ollama

## 📊 Dashboard Example

![Kibana Dashboard](img/ex-dashboard.png)

## 📋 JSON Output Example

![JSON Output](img/ex-json.png)

## 🏗️ System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Log Files     │───>│ LogSentinelAI   │───>│ Elasticsearch   │
│                 │    │   Analysis      │    │                 │
│ • HTTP Access   │    │                 │    │ • Security      │
│ • Apache Error  │    │ • LLM Analysis  │    │   Events        │
│ • System Logs   │    │ • Outlines      │    │ • Raw Logs      │
│ • Network Pcap  │    │ • Pydantic      │    │ • Metadata      │
│                 │    │   Validation    │    │                 │
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

## 🚀 QuickStart: OpenAI API 기반 설치 및 실행

### 1. 기본 환경 준비

- **운영체제**: Linux, Windows, Mac 모두 지원
- **Python**: 3.11 이상
- **Elasticsearch/Kibana**: 9.0.3 이상 (Docker 기반 설치 권장)

### 2. 프로젝트 설치

```bash
# 1. 저장소 클론 및 진입
git clone https://github.com/call518/LogSentinelAI.git
cd LogSentinelAI

# 2. Python 가상환경 생성 및 활성화
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# 3. 패키지 설치
pip install -r requirements.txt

# 4. 환경 변수 파일 준비
cp config.template config
# config 파일에서 OPENAI_API_KEY 값을 입력 (OpenAI 계정에서 발급)

# 5. LLM 설정 (config 파일에서 설정)
# OpenAI API 사용시 config 파일에서 다음과 같이 설정:
#   LLM_PROVIDER=openai  (기본값)
#   LLM_MODEL_OPENAI=gpt-4o-mini  (기본값)
```

### 3. Elasticsearch & Kibana 설치 (Docker)

```bash
# 1. ELK 스택 저장소 클론 및 진입
git clone https://github.com/call518/Docker-ELK.git
cd Docker-ELK

# 2. ELK 스택 초기화 및 실행
# 최초 1회 초기화
docker compose up setup
# Kibana 암호화키 생성(권장)
docker compose up kibana-genkeys
# 생성된 키를 kibana/config/kibana.yml에 복사
# ELK 스택 실행
docker compose up -d

# 3. Kibana 접속: http://localhost:5601
# 기본 계정: elastic / changeme
```

### 4. Elasticsearch 인덱스/정책/템플릿 설정

```bash
# 1. ILM 정책 생성 (7일 보존, 10GB/1일 롤오버)
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
-d '{
  "index_patterns": ["logsentinelai-analysis-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.lifecycle.name": "logsentinelai-analysis-policy",
      "index.lifecycle.rollover_alias": "logsentinelai-analysis"
    },
    "mappings": {
      "properties": {
        "@log_raw_data": {
          "type": "object",
          "dynamic": false
        }
      }
    }
  }
}'

# 3. 초기 인덱스 및 write alias 생성
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

### 5. 로그 분석 실행 (OpenAI API 기준)

```bash
# HTTP access log 분석
python analysis-httpd-access-log.py

# Apache error log 분석
python analysis-httpd-apache-log.py

# Linux system log 분석
python analysis-linux-system-log.py

# 네트워크 패킷 분석 (tcpdump)
python analysis-tcpdump-packet.py
```

### 6. Kibana 대시보드/설정 임포트

```bash
# 1. Kibana 접속: http://localhost:5601
# 2. 로그인: elastic / changeme
# 3. Stack Management > Saved Objects > Import
#    - Kibana-9.0.3-Advanced-Settings.ndjson (먼저)
#    - Kibana-9.0.3-Dashboard-LogSentinelAI.ndjson (다음)
# 4. Analytics > Dashboard > LogSentinelAI Dashboard에서 결과 확인
```

---

## 🔄 LLM Provider 변경/고급 옵션 (선택)

OpenAI API 대신 Ollama(로컬), vLLM(로컬/GPU) 등으로 변경하려면 아래 가이드를 참고하세요.

### LLM Provider & Model 설정 (`config` 파일 수정)

LogSentinelAI는 `config` 파일에서 LLM Provider와 모델을 중앙 관리합니다.

#### OpenAI API 설정 (기본값)
```bash
# config 파일에서 설정
LLM_PROVIDER=openai
LLM_MODEL_OPENAI=gpt-4o-mini

# API 키 설정 필요
OPENAI_API_KEY=your_openai_api_key_here
```

#### Ollama (로컬 LLM) 설정
```bash
# 1. Ollama 설치 및 모델 다운로드
ollama pull qwen2.5-coder:3b
ollama serve
```

```bash
# config 파일에서 설정 변경
LLM_PROVIDER=ollama
LLM_MODEL_OLLAMA=qwen2.5-coder:3b
```

#### vLLM (로컬 GPU) 설정
```bash
# Option A: Clone and use vLLM-Tutorial (권장)
git clone https://github.com/call518/vLLM-Tutorial.git
cd vLLM-Tutorial

# Install Hugging Face CLI for model download
pip install huggingface_hub

# Download model
huggingface-cli download lmstudio-community/Qwen2.5-3B-Instruct-GGUF Qwen2.5-3B-Instruct-Q4_K_M.gguf --local-dir ./models/Qwen2.5-3B-Instruct/
huggingface-cli download Qwen/Qwen2.5-3B-Instruct generation_config.json --local-dir ./config/Qwen2.5-3B-Instruct

# Download model (Optional)
huggingface-cli download lmstudio-community/Qwen2.5-1.5B-Instruct-GGUF Qwen2.5-1.5B-Instruct-Q4_K_M.gguf --local-dir ./models/Qwen2.5-1.5B-Instruct/
huggingface-cli download Qwen/Qwen2.5-1.5B-Instruct generation_config.json --local-dir ./config/Qwen2.5-1.5B-Instruct

# Change value of temperature : 0.7 --> 0.0
cat config/Qwen2.5-3B-Instruct/generation_config.json
{
  "bos_token_id": 151643,
  "pad_token_id": 151643,
  "do_sample": true,
  "eos_token_id": [
    151645,
    151643
  ],
  "repetition_penalty": 1.05,
  "temperature": 0.0,
  "top_p": 0.8,
  "top_k": 20,
  "transformers_version": "4.37.0"
}

# Run vLLM with Docker
./run-docker-vllm---Qwen2.5-3B-Instruct.sh

# Verify API is working
curl -s -X GET http://localhost:5000/v1/models | jq

# Option B: Simple vLLM setup (without Docker)
pip install vllm
python -m vllm.entrypoints.openai.api_server --model qwen2.5-coder:3b
```

```bash
# config 파일에서 설정 변경
LLM_PROVIDER=vllm
LLM_MODEL_VLLM=Qwen/Qwen2.5-1.5B-Instruct
```

### 추가 설정 옵션 (`config` 파일)

#### 응답 언어 설정
```bash
# 분석 결과 언어 설정
RESPONSE_LANGUAGE=korean    # 한국어 (기본값)
# RESPONSE_LANGUAGE=english # 영어
```

#### 로그 파일 경로 및 청크 크기 설정
```bash
# 로그 파일 경로 설정
LOG_PATH_HTTPD_ACCESS=sample-logs/access-10k.log      # 10k 엔트리 (기본값)
LOG_PATH_HTTPD_APACHE_ERROR=sample-logs/apache-10k.log
LOG_PATH_LINUX_SYSTEM=sample-logs/linux-2k.log
LOG_PATH_TCPDUMP_PACKET=sample-logs/tcpdump-packet-2k.log

# 청크 크기 설정 (한 번에 처리할 로그 엔트리 수)
CHUNK_SIZE_HTTPD_ACCESS=10        # HTTP 액세스 로그
CHUNK_SIZE_HTTPD_APACHE_ERROR=10  # Apache 에러 로그
CHUNK_SIZE_LINUX_SYSTEM=10       # Linux 시스템 로그
CHUNK_SIZE_TCPDUMP_PACKET=5       # 네트워크 패킷 (더 작은 청크 권장)
```

### 설정 변경 후 확인
```bash
# 설정 변경 후 분석 실행하여 동작 확인
python analysis-httpd-access-log.py
```

---
## 📁 Project Structure

```
LogSentinelAI/
├── analysis-httpd-access-log.py    # HTTP access log analyzer
├── analysis-httpd-apache-log.py    # Apache error log analyzer
├── analysis-linux-system-log.py    # Linux system log analyzer
├── analysis-tcpdump-packet.py      # Network packet analyzer (tcpdump)
├── commons.py                      # Common functions and utilities
├── prompts.py                      # LLM prompt templates
├── requirements.txt                # Python dependencies
├── config                         # Configuration file (created from template)
├── config.template                # Configuration template
├── .env                           # Environment variables (deprecated - use config instead)
├── .env.template                  # Environment variables template (deprecated)
├── .gitignore                     # Git ignore file
├── LICENSE                        # MIT License
├── README.md                      # This file
├── sample-logs/                   # Sample log files
│   ├── access-100.log             # 100 HTTP access log entries
│   ├── access-10k.log             # 10,000 HTTP access log entries
│   ├── apache-100.log             # 100 Apache error log entries
│   ├── apache-10k.log             # 10,000 Apache error log entries
│   ├── linux-100.log              # 100 Linux system log entries
│   ├── linux-2k.log               # 2,000 Linux system log entries
│   ├── tcpdump-packet-39.log      # Sample tcpdump packet capture (39 packets)
│   └── tcpdump-packet-2k.log      # Sample tcpdump packet capture (2,000 packets)
├── img/                           # Documentation images
│   ├── ex-dashboard.png           # Kibana dashboard example
│   └── ex-json.png                # JSON output example
├── Kibana-9.0.3-Advanced-Settings.ndjson    # Kibana advanced settings (index patterns, etc.)
└── Kibana-9.0.3-Dashboard-LogSentinelAI.ndjson # Kibana dashboard configuration
```

## 🔧 Configuration Options

### Change LLM Provider

You can change the LLM provider in each analysis script:

```python
# In each analysis script (analysis-httpd-access-log.py, etc.)
llm_provider = "vllm"  # Choose from "ollama", "vllm", "openai"
model = initialize_llm_model(llm_provider)
```

Available providers:
- **Ollama**: Local model execution with models like `qwen2.5-coder:3b`
- **vLLM**: GPU-accelerated local inference with OpenAI-compatible API
- **OpenAI**: Cloud-based API using models like `gpt-4o-mini`

### Adjust Chunk Size

You can adjust chunk size for log processing performance:

```python
# In each analysis script
chunk_size = 5  # Default value, adjust as needed (typically 5-10)
```

### Sample Log Files

The project includes different sized sample files for testing:

```python
# Choose log file size in each script
# log_path = "sample-logs/access-10.log"     # 10 entries
# log_path = "sample-logs/access-100.log"    # 100 entries  
log_path = "sample-logs/access-10k.log"     # 10,000 entries (default)
```

## 📊 Output Data Schema

### Security Event Structure

```json
{
  "event_type": "SQL_INJECTION",
  "severity": "HIGH",
  "description": "SQL injection attack attempt detected",
  "confidence_score": 0.85,
  "url_pattern": "/api/users",
  "http_method": "POST",
  "source_ips": ["192.168.1.100"],
  "response_codes": ["403"],
  "attack_patterns": ["SQL_INJECTION"],
  "recommended_actions": ["Block IP", "Add WAF rule"],
  "requires_human_review": true,
  "related_log_ids": ["LOGID-7DD17B008706AC22C60AD6DF9AC5E2E9", "LOGID-F3B6E3F03EC9E5BC1F65624EB65C6C51"]
}
```

### Elasticsearch Document Structure

```json
{
  "chunk_analysis_start_utc": "2025-07-18T10:00:00Z",
  "chunk_analysis_end_utc": "2025-07-18T10:00:05Z", 
  "@processing_result": "success",
  "@timestamp": "2025-07-18T10:00:05.123Z",
  "@log_type": "httpd_access",
  "@document_id": "httpd_access_20250718_100005_123456_chunk_1",
  "@log_raw_data": {
    "LOGID-7DD17B008706AC22C60AD6DF9AC5E2E9": "192.168.1.100 - - [18/Jul/2025:10:00:01] GET /api/users",
    "LOGID-F3B6E3F03EC9E5BC1F65624EB65C6C51": "192.168.1.100 - - [18/Jul/2025:10:00:02] POST /api/login"
  },
  "summary": "Analysis summary in Korean",
  "events": [
    {
      "event_type": "SQL_INJECTION",
      "severity": "HIGH", 
      "description": "SQL injection attack attempt detected",
      "confidence_score": 0.85,
      "related_log_ids": ["LOGID-7DD17B008706AC22C60AD6DF9AC5E2E9"],
      ...
    }
  ],
  "statistics": {...},
  "highest_severity": "HIGH",
  "requires_immediate_attention": true
}
```

## 🎯 Advanced Features

### 1. Structured Generation with Outlines
- **Reliable JSON Output**: Uses [Outlines](https://github.com/dottxt-ai/outlines) library for guaranteed structured generation
- **Schema-Guided Generation**: Pydantic models ensure LLM outputs follow exact JSON schemas
- **Enhanced Parsing Reliability**: Eliminates JSON parsing errors through guided generation
- **Multi-Provider Support**: Works consistently across OpenAI, vLLM, and Ollama providers
- **Performance Optimization**: Faster and more reliable than post-processing approaches

### 2. Intelligent Security Detection
- **Various Attack Pattern Recognition**: SQL Injection, XSS, Brute Force, Command Injection, etc.
- **Context-based Analysis**: Analysis considering log patterns and correlations
- **Confidence Score**: Confidence level for each detection result
- **Mandatory Event Generation**: Every log chunk generates at least one security event
- **Balanced Severity Assessment**: Enhanced sensitivity for security pattern detection

### 3. Complete Traceability  
- **LOGID System**: Unique MD5-based identifier for each log line (e.g., `LOGID-7DD17B008706AC22C60AD6DF9AC5E2E9`)
- **Original Data Preservation**: Raw log data stored with `@log_raw_data` field in Elasticsearch
- **Related Log Mapping**: LLM specifies which LOGIDs are related to each security event
- **Full Audit Trail**: Complete traceability from original logs to analysis results

### 4. Scalable Architecture
- **Modular Design**: Independent analyzer for each log type
- **Shared Commons Library**: Centralized functions in `commons.py` for code reusability
- **Chunk-based Processing**: Memory-efficient processing of large log files
- **Error Handling**: Robust error handling with failure tracking in Elasticsearch

## 📈 Performance Optimization

### Structured Generation
- **Outlines Library**: Eliminates JSON parsing errors through guided generation
- **Schema Validation**: Pydantic models ensure consistent output structure
- **Faster Processing**: Avoids retry loops from malformed JSON responses
- **Memory Efficiency**: Direct structured output without post-processing overhead

### Chunk-based Processing
- Process large log files by dividing into small chunks (default: 5 entries per chunk)
- Memory efficiency and error isolation
- Independent processing of each chunk with failure tracking

### Token Optimization
- Prompt optimization to minimize LLM input tokens
- Structured output using Pydantic models for parsing efficiency
- Simplified JSON schemas to reduce redundancy

### Error Resilience
- Comprehensive error handling with JSON parsing fallbacks
- Failed chunk analysis recorded in Elasticsearch for debugging
- Continued processing even when individual chunks fail

## 🔍 Monitoring & Alerting

### Kibana Dashboard
- Real-time security event monitoring
- Attack trend and pattern analysis
- Geographic location-based attack visualization

### Alert Configuration
- Automatic alerts for high-risk security events
- Threshold-based alert rules
- Email/Slack integration support

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is distributed under the MIT License. See [LICENSE](LICENSE) file for more details.

## 🆘 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/call518/LogSentinelAI/issues)
- **Documentation**: [GitHub Wiki](https://github.com/call518/LogSentinelAI/wiki)
- **Repository**: [GitHub Repository](https://github.com/call518/LogSentinelAI)
- **Email**: support@logsentinelai.dev

## 🏷️ Version Information

- **Python**: 3.11+
- **Elasticsearch**: 9.0.3+
- **Kibana**: 9.0.3+
- **Key Dependencies**: 
  - `outlines` for structured LLM output generation
  - `pydantic` for data validation and schema enforcement
  - `elasticsearch` for data storage and search capabilities
  - `ollama`, `openai` for LLM provider integrations

### 🔗 Important Links
- **Outlines Library**: [https://github.com/dottxt-ai/outlines](https://github.com/dottxt-ai/outlines)
- **Outlines Documentation**: [https://dottxt-ai.github.io/outlines/](https://dottxt-ai.github.io/outlines/)
- **Pydantic**: [https://docs.pydantic.dev/](https://docs.pydantic.dev/)
- **Elasticsearch**: [https://www.elastic.co/elasticsearch/](https://www.elastic.co/elasticsearch/)

## 📋 ToDo & Roadmap

### 🎯 Upcoming Features

#### Real-time Log Analysis
- **Real-time Log File Monitoring**: Implement file watcher to detect new log entries
- **Sampling vs. Full Processing**: Add configurable sampling strategies for high-volume logs
- **Stream Processing**: Support for continuous log stream analysis
- **Performance Modes**: 
  - Full processing mode for comprehensive analysis
  - Sampling mode for high-throughput scenarios

#### Performance Enhancements
- **LLM Processing Optimization**: Improve throughput (logs per second)
- **Batch Processing**: Process multiple log chunks in parallel
- **Model Caching**: Cache LLM responses for similar log patterns
- **Async Processing**: Implement asynchronous log analysis pipeline

### 🚀 Future Enhancements
- **Machine Learning Integration**: Anomaly detection using ML models
- **Custom Rule Engine**: User-defined security rules and patterns
- **Multi-tenant Support**: Support for multiple organizations/tenants
- **Advanced Visualization**: Enhanced Kibana dashboards with geo-mapping
- **API Integration**: RESTful API for external system integration

## 🔧 Technical Implementation

### Outlines Integration
LogSentinelAI leverages the [Outlines](https://github.com/dottxt-ai/outlines) library for structured generation, ensuring reliable JSON output from Language Models:

```python
# Example of structured generation with Outlines
from outlines import models, generate
from pydantic import BaseModel

class SecurityEvent(BaseModel):
    event_type: str
    severity: str
    description: str
    confidence_score: float

# Initialize model with Outlines
model = models.transformers("microsoft/DialoGPT-medium")
generator = generate.json(model, SecurityEvent)

# Generate structured output
result = generator(prompt)  # Always returns valid SecurityEvent JSON
```

### Why Outlines?
- **Guaranteed Structure**: Unlike traditional LLM outputs, Outlines ensures the response always follows the specified schema
- **No Parsing Errors**: Eliminates JSON parsing failures and retry logic
- **Better Performance**: Faster processing through guided generation
- **Multi-Provider Support**: Works with various LLM backends (OpenAI, vLLM, Ollama)
- **Type Safety**: Perfect integration with Pydantic models for type-safe data handling

---

**LogSentinelAI** - Intelligent Log Security Analysis with AI 🔍🛡️