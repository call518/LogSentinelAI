# LogSentinelAI Installation & Usage Guide (RHEL & Ubuntu)

This document provides a detailed step-by-step guide for installing, configuring, and testing LogSentinelAI on RHEL (RockyLinux, CentOS, etc.) and Ubuntu environments. Each step includes clear commands, notes, and practical examples.

---

## 1. System Requirements

- **OS**: RHEL 8/9, RockyLinux 8/9, CentOS 8/9, Ubuntu 20.04/22.04 (including WSL2)
- **Python**: 3.11+ (3.12 recommended)
- **Memory**: Minimum 4GB (8GB+ recommended for local LLM)
- **Disk**: At least 2GB free space
- **Network**: Access to PyPI, GitHub, OpenAI, Ollama/vLLM, etc.
- **(Optional) Docker**: Required for running Elasticsearch/Kibana, vLLM, Ollama containers

---

## 2. Install uv & Prepare Latest Python

### 2.1 Install uv (via pip)
```bash
python3 -m pip install --user --upgrade uv
# or
pip3 install --user --upgrade uv
# If uv is not in PATH, add below
export PATH="$HOME/.local/bin:$PATH"
uv --version  # Check output
```

### 2.2 Install Latest Python (e.g., 3.11)
```bash
uv pip install -U pip  # Update uv pip (recommended)
uv python install 3.11
uv python list  # Check installed python versions
```

---

## 3. Create & Activate Virtual Environment with uv

```bash
uv venv --python=3.11 --seed ~/logsentinelai-venv
source ~/logsentinelai-venv/bin/activate
# Ensure prompt changes to (logsentinelai-venv)
```

---

## 4. Install LogSentinelAI

### 4.1 Install from PyPI (Recommended)
```bash
pip install --upgrade pip
pip install logsentinelai
```

### 4.2 Install from GitHub Source (Development/Latest)
```bash
git clone https://github.com/call518/LogSentinelAI.git
cd LogSentinelAI
pip install .
```

---

## 5. Install Required External Tools

### 5.1 (Optional) Install Docker
- [Official Docker Install Guide](https://docs.docker.com/engine/install/)
- Refer to official docs for both RHEL/Ubuntu

### 5.2 (Optional) Install Ollama (Local LLM)
- [Ollama Official Install](https://ollama.com/download)
```bash
curl -fsSL https://ollama.com/install.sh | sh
systemctl start ollama
ollama pull qwen3:1.7b
```

### 5.3 (Optional) Install vLLM (Local GPU LLM)
```bash
# (A) Install via PyPI
pip install vllm

# (B) Docker-based vLLM install & model download example
git clone https://github.com/call518/vLLM-Tutorial.git
cd vLLM-Tutorial
pip install huggingface_hub
huggingface-cli download lmstudio-community/Qwen2.5-3B-Instruct-GGUF Qwen2.5-3B-Instruct-Q4_K_M.gguf --local-dir ./models/Qwen2.5-3B-Instruct/
huggingface-cli download Qwen/Qwen2.5-3B-Instruct generation_config.json --local-dir ./config/Qwen2.5-3B-Instruct
# Run vLLM with Docker
./run-docker-vllm---Qwen2.5-1.5B-Instruct.sh
# Check API is working
curl -s -X GET http://localhost:5000/v1/models | jq
```

#### vLLM config example (recommended values)
```json
{
  "temperature": 0.1,
  "top_p": 0.5,
  "top_k": 20
}
```

---

## 6. Prepare Config File & Main Options

```bash
cd ~/LogSentinelAI  # If installed from source
curl -o config https://raw.githubusercontent.com/call518/LogSentinelAI/main/config.template
nano config  # or vim config
# Enter required fields such as OPENAI_API_KEY
```

### Example config main items
```ini
# LLM Provider & Model
LLM_PROVIDER=openai   # openai/ollama/vllm
LLM_MODEL_OPENAI=gpt-4o-mini
LLM_MODEL_OLLAMA=qwen2.5:1.5b
LLM_MODEL_VLLM=Qwen/Qwen2.5-1.5B-Instruct

# OpenAI API Key
OPENAI_API_KEY=sk-...

# Response language
RESPONSE_LANGUAGE=korean   # or english

# Analysis mode
ANALYSIS_MODE=batch        # batch/realtime

# Log file paths (batch/realtime)
LOG_PATH_HTTPD_ACCESS=sample-logs/access-10k.log
LOG_PATH_HTTPD_APACHE_ERROR=sample-logs/apache-10k.log
LOG_PATH_LINUX_SYSTEM=sample-logs/linux-2k.log
LOG_PATH_TCPDUMP_PACKET=sample-logs/tcpdump-packet-2k.log
LOG_PATH_REALTIME_HTTPD_ACCESS=/var/log/apache2/access.log
LOG_PATH_REALTIME_HTTPD_APACHE_ERROR=/var/log/apache2/error.log
LOG_PATH_REALTIME_LINUX_SYSTEM=/var/log/messages
LOG_PATH_REALTIME_TCPDUMP_PACKET=/var/log/tcpdump.log

# chunk size (analysis unit)
CHUNK_SIZE_HTTPD_ACCESS=10
CHUNK_SIZE_HTTPD_APACHE_ERROR=10
CHUNK_SIZE_LINUX_SYSTEM=10
CHUNK_SIZE_TCPDUMP_PACKET=5

# Realtime mode options
REALTIME_POLLING_INTERVAL=5
REALTIME_MAX_LINES_PER_BATCH=50
REALTIME_POSITION_FILE_DIR=.positions
REALTIME_BUFFER_TIME=2
REALTIME_PROCESSING_MODE=full     # full/sampling
REALTIME_SAMPLING_THRESHOLD=100

# GeoIP options
GEOIP_ENABLED=true
GEOIP_DATABASE_PATH=~/.logsentinelai/GeoLite2-City.mmdb
GEOIP_FALLBACK_COUNTRY=Unknown
GEOIP_INCLUDE_PRIVATE_IPS=false

# Elasticsearch integration options (optional)
ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=changeme
```

---

## 7. GeoIP DB Auto/Manual Install & Usage

- On first run, GeoIP City DB is automatically downloaded to `~/.logsentinelai/` (recommended)
- For manual download:
```bash
logsentinelai-geoip-download
# or
logsentinelai-geoip-download --output-dir ~/.logsentinelai/
```

### GeoIP main features
- City/country/coordinates (geo_point) auto assignment, Kibana map visualization supported
- Private IPs are excluded from geo_point
- Analysis works even if DB is missing (GeoIP enrich is skipped)

---

## 8. Prepare Sample Log Files (for testing)

```bash
# If you already cloned the repo, skip this
git clone https://github.com/call518/LogSentinelAI.git
cd LogSentinelAI/sample-logs
ls *.log  # Check various sample logs
```

---

## 9. Install & Integrate Elasticsearch & Kibana (Optional)

### 9.1 Install ELK Stack via Docker
```bash
git clone https://github.com/call518/Docker-ELK.git
cd Docker-ELK
docker compose up setup
docker compose up kibana-genkeys  # Key generation (recommended)
docker compose up -d
# Access http://localhost:5601, elastic/changeme
```

### 9.2 Set Elasticsearch Index/Policy/Template

Run the following commands in the terminal when Kibana/Elasticsearch is running (default: http://localhost:5601, http://localhost:9200). Default account: `elastic`/`changeme`.

#### 1) Create ILM Policy (7 days retention, 10GB/1d rollover)
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

#### 2) Create Index Template
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

#### 3) Create Initial Index & Write Alias
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

#### 4) Import Kibana Dashboard/Settings
1. Access http://localhost:5601 (elastic/changeme)
2. Stack Management → Saved Objects → Import
3. Import `Kibana-9.0.3-Advanced-Settings.ndjson` then `Kibana-9.0.3-Dashboard-LogSentinelAI.ndjson`
4. Check results in Analytics > Dashboard > LogSentinelAI Dashboard

---

## 10. LogSentinelAI Main Commands & Test

### 10.1 List All Commands
```bash
logsentinelai --help
```

### 10.2 Main Analysis Command Examples
```bash
# HTTP Access log analysis (batch)
logsentinelai-httpd-access --log-path sample-logs/access-10k.log
# Apache Error log analysis
logsentinelai-httpd-apache --log-path sample-logs/apache-10k.log
# Linux System log analysis
logsentinelai-linux-system --log-path sample-logs/linux-2k.log
# TCPDump packet log analysis
logsentinelai-tcpdump --log-path sample-logs/tcpdump-packet-10k-single-line.log
# Realtime monitoring (local)
logsentinelai-linux-system --mode realtime
# Realtime sampling mode
logsentinelai-tcpdump --mode realtime --processing-mode sampling --sampling-threshold 50
# SSH remote log analysis
logsentinelai-linux-system --remote --ssh admin@192.168.1.100 --ssh-key ~/.ssh/id_rsa --log-path /var/log/messages
# Manual GeoIP DB download/path
logsentinelai-geoip-download --output-dir ~/.logsentinelai/
```

### 10.3 CLI Option Summary

| Option | Description | config default | CLI override |
|--------|-------------|---------------|-------------|
| --log-path <path> | Log file path to analyze | LOG_PATH_* | Y |
| --mode <mode> | batch/realtime analysis mode | ANALYSIS_MODE | Y |
| --chunk-size <num> | Analysis unit (lines) | CHUNK_SIZE_* | Y |
| --processing-mode <mode> | Realtime processing (full/sampling) | REALTIME_PROCESSING_MODE | Y |
| --sampling-threshold <num> | Sampling threshold | REALTIME_SAMPLING_THRESHOLD | Y |
| --remote | Enable SSH remote analysis | REMOTE_LOG_MODE | Y |
| --ssh <user@host:port> | SSH connection info | REMOTE_SSH_* | Y |
| --ssh-key <path> | SSH key path | REMOTE_SSH_KEY_PATH | Y |
| --help | Help | - | - |

> CLI options always override config file

### 10.8 SSH Remote Log Analysis
```bash
logsentinelai-linux-system --remote --ssh admin@192.168.1.100 --ssh-key ~/.ssh/id_rsa --log-path /var/log/messages
```
- **Tip:** Register the target server in known_hosts in advance (`ssh-keyscan -H <host> >> ~/.ssh/known_hosts`)

### 10.9 Manual GeoIP DB Download/Path
```bash
logsentinelai-geoip-download --output-dir ~/.logsentinelai/
```

---


## 11. Declarative Extraction Usage

The core feature of LogSentinelAI is **Declarative Extraction**. In each analyzer, you simply declare the result structure (Pydantic class) you want, and the LLM automatically analyzes the logs and returns results in that structure as JSON. No complex parsing or post-processing is needed—just declare the fields you want, and the AI fills them in.

### 11.1 Basic Usage

1. In your analyzer script, declare the result structure (Pydantic class) you want to receive.
2. When you run the analysis command, the LLM automatically generates JSON matching that structure.

#### Example: Customizing HTTP Access Log Analyzer
```python
from pydantic import BaseModel

class MyAccessLogResult(BaseModel):
    ip: str
    url: str
    is_attack: bool
```
Just define the fields you want, and the LLM will generate results like:
```json
{
  "ip": "192.168.0.1",
  "url": "/admin.php",
  "is_attack": true
}
```

#### Example: Customizing Apache Error Log Analyzer
```python
from pydantic import BaseModel

class MyApacheErrorResult(BaseModel):
    log_level: str
    event_message: str
    is_critical: bool
```

#### Example: Customizing Linux System Log Analyzer
```python
from pydantic import BaseModel

class MyLinuxLogResult(BaseModel):
    event_type: str
    user: str
    is_anomaly: bool
```

#### Example: Customizing TCPDump Packet Log Analyzer
```python
from pydantic import BaseModel

class MyPacketResult(BaseModel):
    src_ip: str
    dst_ip: str
    is_attack: bool
```

By declaring only the result structure you want in each analyzer, the LLM automatically returns results in that structure—no manual parsing required.

---

## 12. Advanced Usage Examples

### 11.1 Set Defaults in config & Override with CLI
```bash
# Set CHUNK_SIZE_LINUX_SYSTEM=20 in config
logsentinelai-linux-system --chunk-size 10  # CLI option takes precedence
```

### 11.2 Realtime Mode Auto Sampling Operation & Principle
```bash
logsentinelai-httpd-access --mode realtime --processing-mode full --sampling-threshold 100
# Check auto-switch to sampling mode on heavy log inflow
```

#### Sampling Operation Example
1. Normal: 15 lines in → FULL mode (below threshold), analyze by chunk_size
2. Traffic spike: 250 lines in → Exceeds threshold (100), auto-switch to SAMPLING mode, analyze only latest 10 lines, skip the rest (original logs preserved)
3. Traffic normalizes: Back to FULL mode

#### Sampling Strategy
- FIFO buffer, if threshold exceeded, only latest chunk_size analyzed
- No severity/pattern-based priority (purely time order)
- Possible analysis omission (original logs preserved)

### 11.3 Import Kibana Dashboard
1. Access http://localhost:5601 (elastic/changeme)
2. Stack Management → Saved Objects → Import
3. Import `Kibana-9.0.3-Advanced-Settings.ndjson` then `Kibana-9.0.3-Dashboard-LogSentinelAI.ndjson`
4. Check results in Analytics > Dashboard > LogSentinelAI Dashboard

---

## 12. Troubleshooting FAQ

- **Permission denied on pip install**: Activate virtualenv or use `pip install --user`
- **Python 3.11 not found**: Check install path, use `python3.11` directly
- **Cannot access Elasticsearch/Kibana**: Check Docker status, port conflicts, firewall
- **GeoIP DB download failed**: Download manually and set path in config
- **SSH remote analysis error**: Check SSH key permissions, known_hosts, firewall, port
- **LLM API error**: Check OPENAI_API_KEY, Ollama/vLLM server status, network

---

## 13. Reference/Recommended Links & Contact
- [LogSentinelAI GitHub](https://github.com/call518/LogSentinelAI)
- [Docker-ELK Official](https://github.com/deviantony/docker-elk)
- [Ollama Official](https://ollama.com/)
- [vLLM Official](https://github.com/vllm-project/vllm)
- [Python Official](https://www.python.org/downloads/)

Contact/Feedback: GitHub Issue, Discussions, Pull Request welcome

---

## 13. Reference Links & Contact
- [LogSentinelAI GitHub](https://github.com/call518/LogSentinelAI)
- [Docker-ELK Official](https://github.com/deviantony/docker-elk)
- [Ollama Official](https://ollama.com/)
- [vLLM Official](https://github.com/vllm-project/vllm)
- [Python Official](https://www.python.org/downloads/)

**Contact/Feedback**: GitHub Issue, Discussions, Pull Request welcome

---

## Appendix

### A. Real-time Auto-Sampling Detailed Mechanism

This section provides a detailed explanation of how the system automatically switches processing modes when large volumes of logs are ingested in real-time mode.

#### A.1 Related Parameters and Their Roles

| Parameter | Default | Role | Impact |
|-----------|---------|------|---------|
| `REALTIME_PROCESSING_MODE` | `full` | Base processing mode (full/sampling) | Determines initial processing method |
| `REALTIME_SAMPLING_THRESHOLD` | `100` | Auto-sampling switch threshold | Based on number of pending log lines |
| `CHUNK_SIZE_*` | `10` | LLM analysis unit | Number of log lines to analyze at once |
| `REALTIME_POLLING_INTERVAL` | `5` | Polling interval (seconds) | Log file check frequency |
| `REALTIME_MAX_LINES_PER_BATCH` | `50` | Read limit | Maximum lines to read at once |
| `REALTIME_BUFFER_TIME` | `2` | Buffer time (seconds) | Prevents incomplete log line processing |

#### A.2 Auto-Sampling Trigger Scenarios

##### Scenario 1: Normal Log Processing (FULL mode maintained)
```
Configuration:
- CHUNK_SIZE_HTTPD_ACCESS = 10
- REALTIME_SAMPLING_THRESHOLD = 100
- REALTIME_POLLING_INTERVAL = 5
- REALTIME_MAX_LINES_PER_BATCH = 50

Process:
1. Check /var/log/apache2/access.log every 5 seconds
2. Find 15 new log lines → Add to internal pending buffer
3. Pending buffer: 15 lines (below threshold of 100)
4. Process CHUNK_SIZE(10): Analyze 10 lines with LLM, 5 lines remain pending
5. Check for additional logs in next polling cycle
```

##### Scenario 2: Traffic Spike - Auto-switch to Sampling
```
Configuration: Same as above

Spike situation:
1. Poll every 5 seconds, reading 50 lines each time (MAX_LINES_PER_BATCH)
2. Continuous heavy log influx over multiple polling cycles
3. Pending buffer accumulation: 20 lines → 45 lines → 85 lines → 125 lines
4. 125 lines > threshold(100) ▶️ Auto-switch to SAMPLING mode

SAMPLING mode operation:
- System outputs "AUTO-SWITCH: Pending lines (125) exceed threshold (100)"
- Displays "SWITCHING TO SAMPLING MODE" message
- Select only latest 10 lines (CHUNK_SIZE) from 125 pending lines
- Discard remaining 115 lines (original log file preserved)
- Output "SAMPLING: Discarded 115 older lines, keeping latest 10" message
- Send only latest 10 lines to LLM for analysis
- Limit memory usage, prevent system overload
```

##### Scenario 3: Traffic Normalization - Return to FULL mode
```
Normalization process:
1. Log influx decreases: around 5-15 lines per polling cycle
2. Pending buffer drops below threshold (100)
3. Automatically return to FULL mode
4. Resume sequential processing of all logs
```

#### A.3 Real-world Usage Examples

##### Web Server DDoS Attack Scenario
```bash
# Configuration: In config file
CHUNK_SIZE_HTTPD_ACCESS=15
REALTIME_SAMPLING_THRESHOLD=200
REALTIME_POLLING_INTERVAL=3

# Execution
logsentinelai-httpd-access --mode realtime

# Situational behavior:
# Normal: 10-20 requests/sec → FULL mode analyzes all logs
# Attack: 500+ requests/sec → SAMPLING mode when pending buffer exceeds 200 lines
# SAMPLING: Analyze only latest 15 lines, ignore rest to protect system
# Attack ends: Request volume normalizes → Auto return to FULL mode
```

##### System Log Mass Generation Scenario
```bash
# Configuration
CHUNK_SIZE_LINUX_SYSTEM=20
REALTIME_SAMPLING_THRESHOLD=150

# Situation: System error generating 100 error log lines per second
# Within 1-2 minutes, pending buffer exceeds 150 lines
# → Auto SAMPLING: Analyze only latest 20 lines
# → Protect system resources, prioritize latest errors
```

#### A.4 Sampling Strategy Features and Limitations

##### Advantages
- **Automation**: Control system load without user intervention
- **Memory Protection**: Prevent unlimited buffer growth
- **Recency Guarantee**: Focus on most recent logs
- **Original Preservation**: Log files themselves remain intact

##### Limitations
- **Analysis Gaps**: Some logs skipped during sampling
- **Time-based Only**: Chronological processing, no severity-based priority
- **Temporary Blind Spots**: Limited pattern analysis during spike periods

##### Recommended Tuning Methods
```bash
# High-performance system (sufficient memory)
REALTIME_SAMPLING_THRESHOLD=500
CHUNK_SIZE_*=25

# Low-spec system (memory constrained)
REALTIME_SAMPLING_THRESHOLD=50
CHUNK_SIZE_*=5

# Critical logs (minimize gaps)
REALTIME_SAMPLING_THRESHOLD=1000
REALTIME_POLLING_INTERVAL=2

# General monitoring (efficiency priority)
REALTIME_SAMPLING_THRESHOLD=100
REALTIME_POLLING_INTERVAL=10
```

Through this auto-sampling mechanism, LogSentinelAI provides stable real-time analysis even in unpredictable log traffic situations.
