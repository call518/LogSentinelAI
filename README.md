# LogSentinelAI - AI-Powered Log Security Analysis

LogSentinelAI is a system that leverages LLM (Large Language Model) to analyze various log files and detect security events. It automatically analyzes Apache HTTP logs, Linux system logs, and other log types to identify security threats and stores them as structured data in Elasticsearch for visualization and analysis.

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

## 🚀 QuickStart: OpenAI API Installation & Setup

### 1. Prerequisites

- **Operating Systems**: Linux, Windows, Mac all supported
- **Python**: 3.11 or higher
- **Elasticsearch/Kibana**: 9.0.3 or higher (Docker-based installation recommended)

### 2. Project Installation

```bash
# 1. Clone repository and navigate to directory
git clone https://github.com/call518/LogSentinelAI.git
cd LogSentinelAI

# 2. Create and activate Python virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# 3. Install packages
pip install -r requirements.txt

# 4. Setup configuration file
cp config.template config
# Edit config file and set OPENAI_API_KEY value (obtained from OpenAI account)

# 5. LLM Configuration (set in config file)
# For OpenAI API usage, configure in config file as follows:
#   LLM_PROVIDER=openai  (default)
#   LLM_MODEL_OPENAI=gpt-4o-mini  (default)
```

### 3. Elasticsearch & Kibana Installation (Docker)

```bash
# 1. Clone ELK stack repository and navigate to directory
git clone https://github.com/call518/Docker-ELK.git
cd Docker-ELK

# 2. Initialize and run ELK stack
# One-time initialization
docker compose up setup
# Generate Kibana encryption keys (recommended)
docker compose up kibana-genkeys
# Copy generated keys to kibana/config/kibana.yml
# Start ELK stack
docker compose up -d

# 3. Access Kibana: http://localhost:5601
# Default credentials: elastic / changeme
```

### 4. Elasticsearch Index/Policy/Template Setup

```bash
# 1. Create ILM policy (7-day retention, 10GB/1-day rollover)
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

# 2. Create index template
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

# 3. Create initial index and write alias
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

### 5. Run Log Analysis

#### Universal Command-Line Interface
All analysis scripts now support the same command-line arguments and modes:

```bash
# View available options for any script
python analysis-linux-system-log.py --help
python analysis-httpd-access-log.py --help
python analysis-tcpdump-packet.py --help

# All scripts support: --mode, --chunk-size, --log-path, --processing-mode, --sampling-threshold
```

#### Analysis Modes
LogSentinelAI supports two analysis modes:

##### Batch Mode (Default)
- Analyzes complete, static log files
- Processes entire files from beginning to end
- Ideal for historical analysis and one-time processing
- Uses paths from `LOG_PATH_*` configuration

##### Real-time Mode
- Monitors live log files for new entries
- Processes only new log lines as they are written
- Maintains position tracking to avoid reprocessing
- Uses paths from `LOG_PATH_REALTIME_*` configuration
- **Sampling Support**: Three processing modes for high-volume scenarios:
  - `full`: Process all log entries (auto-sampling when threshold exceeded)
  - `sampling`: Always keep only latest entries within chunk size
  - `auto-sampling`: Intelligent sampling based on log volume

#### Batch Mode (Complete log files)
```bash
# Use default configuration
python analysis-linux-system-log.py

# Override chunk size
python analysis-linux-system-log.py --chunk-size 5

# All analysis scripts support the same batch mode options
python analysis-httpd-access-log.py --chunk-size 8
python analysis-httpd-apache-log.py --log-path /path/to/custom/error.log
python analysis-tcpdump-packet.py --chunk-size 3
```

#### Real-time Mode (Live log monitoring)
```bash
# Monitor /var/log/messages in real-time (full processing mode)
python analysis-linux-system-log.py --mode realtime

# Monitor with sampling mode (for high-volume logs)
python analysis-linux-system-log.py --mode realtime --processing-mode sampling

# Monitor with custom sampling threshold
python analysis-linux-system-log.py --mode realtime --processing-mode full --sampling-threshold 200

# Monitor custom log file
python analysis-linux-system-log.py --mode realtime --log-path /var/log/messages

# Monitor with custom chunk size
python analysis-linux-system-log.py --mode realtime --chunk-size 15

# All analysis scripts support the same real-time options
python analysis-httpd-access-log.py --mode realtime --processing-mode sampling
python analysis-httpd-apache-log.py --mode realtime --log-path /var/log/apache2/error.log
python analysis-tcpdump-packet.py --mode realtime --chunk-size 5

# Monitor with root permissions (often required for system logs)
sudo python analysis-linux-system-log.py --mode realtime
```

### 6. Import Kibana Dashboard/Settings

```bash
# 1. Access Kibana: http://localhost:5601
# 2. Login: elastic / changeme
# 3. Stack Management > Saved Objects > Import
#    - Kibana-9.0.3-Advanced-Settings.ndjson (first)
#    - Kibana-9.0.3-Dashboard-LogSentinelAI.ndjson (second)
# 4. Check results at Analytics > Dashboard > LogSentinelAI Dashboard
```

---
## 🔄 Change LLM Provider/Advanced Options (Optional)

To change from OpenAI API to Ollama (local), vLLM (local/GPU), etc., please refer to the guide below.

### LLM Provider & Model Configuration (`config` file modification)

LogSentinelAI centrally manages LLM Provider and model in the `config` file.

#### OpenAI API Configuration (Default)
```bash
# Configure in config file
LLM_PROVIDER=openai
LLM_MODEL_OPENAI=gpt-4o-mini

# API key configuration required
OPENAI_API_KEY=your_openai_api_key_here
```

#### Ollama (Local LLM) Configuration
```bash
# 1. Install Ollama and download model
ollama pull qwen2.5-coder:3b
ollama serve
```

```bash
# Change configuration in config file
LLM_PROVIDER=ollama
LLM_MODEL_OLLAMA=qwen2.5-coder:3b
```

#### vLLM (Local GPU) Configuration
```bash
# Option A: Clone and use vLLM-Tutorial (recommended)
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
# Change configuration in config file
LLM_PROVIDER=vllm
LLM_MODEL_VLLM=Qwen/Qwen2.5-1.5B-Instruct
```

### Additional Configuration Options (`config` file)

#### Response Language Configuration
```bash
# Configure analysis result language
RESPONSE_LANGUAGE=english   # English
# RESPONSE_LANGUAGE=korean  # Korean (default)
```

#### Analysis Mode Configuration
```bash
# Configure analysis mode
ANALYSIS_MODE=batch         # Batch mode - analyze complete files (default)
# ANALYSIS_MODE=realtime    # Real-time mode - monitor live logs
```

#### Log File Path and Chunk Size Configuration
```bash
# Batch mode log file paths
LOG_PATH_HTTPD_ACCESS=sample-logs/access-10k.log      # 10k entries (default)
LOG_PATH_HTTPD_APACHE_ERROR=sample-logs/apache-10k.log
LOG_PATH_LINUX_SYSTEM=sample-logs/linux-2k.log
LOG_PATH_TCPDUMP_PACKET=sample-logs/tcpdump-packet-2k.log

# Real-time mode log file paths (live logs)
LOG_PATH_REALTIME_HTTPD_ACCESS=/var/log/apache2/access.log
LOG_PATH_REALTIME_HTTPD_APACHE_ERROR=/var/log/apache2/error.log
LOG_PATH_REALTIME_LINUX_SYSTEM=/var/log/messages
LOG_PATH_REALTIME_TCPDUMP_PACKET=/var/log/tcpdump.log

# Configure chunk sizes (number of log entries to process at once)
CHUNK_SIZE_HTTPD_ACCESS=10        # HTTP access logs
CHUNK_SIZE_HTTPD_APACHE_ERROR=10  # Apache error logs
CHUNK_SIZE_LINUX_SYSTEM=10       # Linux system logs
CHUNK_SIZE_TCPDUMP_PACKET=5       # Network packets (smaller chunks recommended)
```

#### Real-time Monitoring Configuration
```bash
# Polling interval for checking new log entries (seconds)
REALTIME_POLLING_INTERVAL=5

# Maximum number of new lines to process at once
REALTIME_MAX_LINES_PER_BATCH=50

# Position file directory for tracking file read positions
REALTIME_POSITION_FILE_DIR=.positions

# Buffer time to wait for complete log lines (seconds)
REALTIME_BUFFER_TIME=2

# Processing mode for real-time monitoring
REALTIME_PROCESSING_MODE=full     # full, sampling, or auto-sampling

# Sampling threshold for auto-sampling mode (number of lines)
REALTIME_SAMPLING_THRESHOLD=100   # When exceeded, triggers sampling in 'full' mode
```

### Verify Configuration Changes
```bash
# Run analysis after configuration changes to verify operation
python analysis-httpd-access-log.py
```

---
## 🔧 Configuration Options

### Change LLM Provider

You can change the LLM provider in each analysis script:

```bash
# In config file
LLM_PROVIDER=vllm  # Choose from "ollama", "vllm", "openai"
LLM_MODEL_VLLM=Qwen/Qwen2.5-1.5B-Instruct
```

Available providers:
- **Ollama**: Local model execution with models like `qwen2.5-coder:3b`
- **vLLM**: GPU-accelerated local inference with OpenAI-compatible API
- **OpenAI**: Cloud-based API using models like `gpt-4o-mini`

### Position Tracking for Real-time Monitoring

Real-time monitoring uses position files to track reading progress:

```bash
# Position files are stored in .positions/ directory
.positions/
├── linux_system_position.txt    # Tracks position for Linux system logs
├── httpd_access_position.txt     # Tracks position for HTTP access logs
└── ...
```

- Position files are automatically created and maintained
- Delete position files to restart monitoring from beginning
- Position files prevent duplicate processing during restarts

### Log File Rotation Handling

Real-time monitoring handles log rotation gracefully:

1. **Detection**: Monitors file size and inode changes
2. **Reset**: Automatically resets to beginning of new log file
3. **Continuation**: Seamless processing without data loss
4. **Position Update**: Updates position tracking for new file

### Adjust Chunk Size

You can adjust chunk size for log processing performance:

```python
# In each analysis script
chunk_size = 5  # Default value, adjust as needed (typically 5-10)
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
  "@chunk_analysis_start_utc": "2025-07-18T10:00:00Z",
  "@chunk_analysis_end_utc": "2025-07-18T10:00:05Z", 
  "@processing_result": "success",
  "@processing_mode": "realtime",
  "@sampling_threshold": 100,
  "@log_count": 15,
  "@timestamp": "2025-07-18T10:00:05.123Z",
  "@log_type": "httpd_access",
  "@document_id": "httpd_access_20250718_100005_123456_chunk_1",
  "@log_raw_data": {
    "LOGID-7DD17B008706AC22C60AD6DF9AC5E2E9": "192.168.1.100 - - [18/Jul/2025:10:00:01] GET /api/users",
    "LOGID-F3B6E3F03EC9E5BC1F65624EB65C6C51": "192.168.1.100 - - [18/Jul/2025:10:00:02] POST /api/login"
  },
  "summary": "Analysis summary in English",
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