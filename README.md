[![Publish to PyPI on tag](https://github.com/call518/LogSentinelAI/actions/workflows/pypi-publish.yml/badge.svg)](https://github.com/call518/LogSentinelAI/actions/workflows/pypi-publish.yml)

# LogSentinelAI - AI-Powered Log Analyzer

LogSentinelAI uses LLMs to analyze Apache, Linux, and other logs for security events, anomalies, and errors, transforming them into structured data for visualization in Elasticsearch.

## 🚀 Key Features

### AI-Powered Analysis
- **LLM Providers**: OpenAI API, Ollama, vLLM
- **Log Types**: HTTP Access, Apache Error, Linux System, TCPDump
- **Threat Detection**: SQL Injection, XSS, Brute Force, Network Anomalies
- **Output**: Structured JSON with Pydantic validation
- **Adaptive Sensitivity**: Detection sensitivity varies by LLM model capability and log-type-specific prompts

### Processing Modes
- **Batch**: Historical log analysis
- **Real-time**: Live monitoring with sampling
- **Access**: Local files, SSH remote

### Data Enrichment
- **GeoIP**: MaxMind GeoLite2 City lookup (with coordinates for Kibana geo_point)
- **Statistics**: IP counts, response codes, metrics
- **Languages**: Output in any language (configurable)

### Enterprise Integration
- **Storage**: Elasticsearch with ILM policies
- **Visualization**: Kibana dashboards
- **Deployment**: Docker containers

## Dashboard Example

![Kibana Dashboard](img/ex-dashboard.png)

## 📋 JSON Output Example

![JSON Output](img/ex-json.png)

## System Architecture

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

## 📁 Project Structure & Python Scripts

### Core Python Components

```
src/logsentinelai/
├── __init__.py                    # Package initialization
├── cli.py                         # Main CLI entry point and command routing
├── py.typed                       # Type hints marker for mypy
│
├── analyzers/                     # Log type-specific analyzers
│   ├── __init__.py               # Analyzers package init
│   ├── httpd_access.py           # HTTP access log analyzer (Apache/Nginx)
│   ├── httpd_apache.py           # Apache error log analyzer
│   ├── linux_system.py          # Linux system log analyzer (syslog/messages)
│   └── tcpdump_packet.py         # Network packet capture analyzer
│
├── core/                          # Core analysis engine (modularized)
│   ├── __init__.py               # Core package init with unified imports
│   ├── commons.py                # Main analysis functions and interfaces
│   ├── config.py                 # Configuration management and environment variables
│   ├── llm.py                    # LLM model initialization and interaction
│   ├── elasticsearch.py          # Elasticsearch integration and data transmission
│   ├── geoip.py                  # GeoIP lookup and IP enrichment functionality
│   ├── ssh.py                    # SSH remote log access functionality
│   ├── monitoring.py             # Real-time log monitoring and processing
│   ├── utils.py                  # Log processing utilities and helper functions
│   └── prompts.py                # LLM prompt templates for each log type
│
└── utils/                         # Utility functions
    ├── __init__.py               # Utils package init
    └── geoip_downloader.py       # MaxMind GeoIP database downloader
```

### CLI Command Mapping

```bash
# CLI commands map to analyzer scripts:
logsentinelai-httpd-access   → analyzers/httpd_access.py
logsentinelai-apache-error   → analyzers/httpd_apache.py  
logsentinelai-linux-system   → analyzers/linux_system.py
logsentinelai-tcpdump        → analyzers/tcpdump_packet.py
logsentinelai-geoip-download → utils/geoip_downloader.py
```

## 🚀 Quick Start: Installation & Setup

### Demo Environment Verification

LogSentinelAI has been successfully tested and validated on the following configuration:

```bash
# Test Environment Specifications
- Host OS: Windows 11
- WSL2: v2.5.9 running RockyLinux 8
- Docker Desktop: v4.39.0
- GPU Support: NVIDIA GeForce GTX 1660 with CUDA 12.9

# GPU Verification (RockyLinux8 Distro on WSL2)
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

✅ **Validation Status**: All core features including OpenAI API, local Ollama, and GPU-accelerated vLLM deployments have been thoroughly tested and verified working on this configuration.

### 1. Prerequisites

- **Operating Systems**: Linux, Windows, Mac all supported
- **Python**: 3.11 or higher
- **Elasticsearch/Kibana**: 9.0.3 or higher (Docker-based installation recommended)
- **Ollama**: 0.9.5 or higher

### 📦 Package Installation

LogSentinelAI is available on PyPI and can be installed with a single command:

```bash
# Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install LogSentinelAI
pip install logsentinelai
```

### ⚙️ Configuration Setup

```bash
# 1. Setup basic configuration (choose one)
curl -o config https://raw.githubusercontent.com/call518/LogSentinelAI/main/config.template

# 2. Edit config file and set your OPENAI_API_KEY
# Get your API key from: https://platform.openai.com/api-keys
nano config  # or vim config
```

### 🌍 GeoIP Database Setup (Automatic)

GeoIP City database will be automatically downloaded when first needed:

```bash
# The GeoIP City database is automatically downloaded to ~/.logsentinelai/ 
# when first needed - no manual setup required

# Optional: Pre-download GeoIP City database
logsentinelai-geoip-download
```

### 🚀 Quick Usage Examples

```bash
# View available commands
logsentinelai --help

# Clone repository for sample log files
git clone https://github.com/call518/LogSentinelAI.git
cd LogSentinelAI

# HTTP Access Log Analysis
logsentinelai-httpd-access --log-path sample-logs/access-10k.log

# Apache Error Log Analysis
logsentinelai-apache-error --log-path sample-logs/apache-10k.log

# Linux System Log Analysis
logsentinelai-linux-system --log-path sample-logs/linux-2k.log

# TCPDump Packet Analysis
logsentinelai-tcpdump --log-path sample-logs/tcpdump-packet-10k-single-line.log

# Real-time monitoring  
logsentinelai-linux-system --mode realtime

# Remote SSH analysis (requires host key in known_hosts)
logsentinelai-tcpdump --remote --ssh admin@server.com --ssh-key ~/.ssh/id_rsa

# Download GeoIP database
logsentinelai-geoip-download
```

### ⚙️ CLI Options Reference

All analysis commands (`logsentinelai-httpd-access`, `logsentinelai-apache-error`, `logsentinelai-linux-system`, `logsentinelai-tcpdump`) support the same CLI options:

| Option | Description | Config Default | Override |
|--------|-------------|----------------|----------|
| `--log-path <path>` | Log file path to analyze | `LOG_PATH_*` settings | ✅ Yes |
| `--mode <mode>` | Analysis mode: `batch` or `realtime` | `ANALYSIS_MODE=batch` | ✅ Yes |
| `--chunk-size <num>` | Number of log entries per analysis chunk | `CHUNK_SIZE_*=10` | ✅ Yes |
| `--processing-mode <mode>` | Real-time processing: `full` or `sampling` | `REALTIME_PROCESSING_MODE=full` | ✅ Yes |
| `--sampling-threshold <num>` | Auto-sampling threshold for real-time mode | `REALTIME_SAMPLING_THRESHOLD=100` | ✅ Yes |
| `--remote` | Enable remote SSH log access | `REMOTE_LOG_MODE=local` | ✅ Yes |
| `--ssh <user@host:port>` | SSH connection string | `REMOTE_SSH_*` settings | ✅ Yes |
| `--ssh-key <path>` | SSH private key file path | `REMOTE_SSH_KEY_PATH` | ✅ Yes |
| `--help` | Show command help and available options | N/A | N/A |

**Key Usage Patterns:**
```bash
# Override config defaults
logsentinelai-linux-system --chunk-size 20 --mode realtime

# Remote analysis with SSH (requires host key in known_hosts)
logsentinelai-httpd-access --remote --ssh admin@server.com:2222 --ssh-key ~/.ssh/id_rsa

# Real-time with sampling
logsentinelai-tcpdump --mode realtime --processing-mode sampling --sampling-threshold 50
```

**Notes:**
- CLI options always override config file settings
- Config values are used as defaults when CLI options are not specified
- Use `--help` with any command to see all available options

### 🚀 Elasticsearch & Kibana Setup (Optional)

For advanced visualization and analytics, you can set up Elasticsearch and Kibana:

> [!IMPORTANT]
> [Platinum features](https://www.elastic.co/subscriptions) are enabled by default for a [trial](https://www.elastic.co/docs/deploy-manage/license/manage-your-license-in-self-managed-cluster) duration of 30 days. After this evaluation period, you will retain access to all the free features included in the Open Basic license seamlessly, without manual intervention required, and without losing any data. Refer to the [How to disable paid features](https://github.com/deviantony/docker-elk#how-to-disable-paid-features) section to opt out of this behaviour.

```bash
# 1. Clone ELK stack repository and navigate to directory
# (Origin Repo) https://github.com/deviantony/docker-elk
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

### 📊 Elasticsearch Index/Policy Setup

If using Elasticsearch integration:

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
-d 'PUT _index_template/logsentinelai-analysis-template
{
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

### 📈 Advanced Usage Examples

#### Local File Analysis
```bash
# Batch analysis with default config settings
logsentinelai-linux-system

# Override log path and chunk size
logsentinelai-linux-system --log-path /var/log/messages --chunk-size 15

# Real-time monitoring with different processing modes
logsentinelai-linux-system --mode realtime
logsentinelai-httpd-access --mode realtime --processing-mode sampling
```

#### SSH Remote Access

> **⚠️ Important**: For SSH connections, the target host must be added to your system's known_hosts file first. Run `ssh-keyscan -H <hostname> >> ~/.ssh/known_hosts` or manually connect once to accept the host key.

```bash
# SSH key authentication (recommended)
logsentinelai-linux-system \
  --remote \
  --ssh admin@192.168.1.100 \
  --ssh-key ~/.ssh/id_rsa \
  --log-path /var/log/messages

# SSH with custom port
logsentinelai-httpd-access \
  --remote \
  --ssh webuser@web.company.com:8022 \
  --ssh-key ~/.ssh/web_key \
  --log-path /var/log/apache2/access.log
```

#### Multi-Server Monitoring
```bash
# Terminal 1: Web server logs
logsentinelai-httpd-access --remote --ssh web@web1.com --ssh-key ~/.ssh/web1 --log-path /var/log/apache2/access.log

# Terminal 2: Database server logs  
logsentinelai-linux-system --remote --ssh db@db1.com --ssh-key ~/.ssh/db1 --log-path /var/log/messages
```

### 📊 Import Kibana Dashboard/Settings

If using Kibana visualization:

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
ollama pull qwen2.5:1.5b
ollama serve
```

```bash
# Change configuration in config file
LLM_PROVIDER=ollama
LLM_MODEL_OLLAMA=qwen2.5:1.5b
```

#### vLLM (Local GPU) Configuration
```bash
# Option A: Clone and use vLLM-Tutorial (recommended)
git clone https://github.com/call518/vLLM-Tutorial.git
cd vLLM-Tutorial

# Install Hugging Face CLI for model download
pip install huggingface_hub

# Download model (Default)
huggingface-cli download lmstudio-community/Qwen2.5-3B-Instruct-GGUF Qwen2.5-3B-Instruct-Q4_K_M.gguf --local-dir ./models/Qwen2.5-3B-Instruct/
huggingface-cli download Qwen/Qwen2.5-3B-Instruct generation_config.json --local-dir ./config/Qwen2.5-3B-Instruct

# Download model (Optional)
huggingface-cli download lmstudio-community/Qwen2.5-1.5B-Instruct-GGUF Qwen2.5-1.5B-Instruct-Q4_K_M.gguf --local-dir ./models/Qwen2.5-1.5B-Instruct/
huggingface-cli download Qwen/Qwen2.5-1.5B-Instruct generation_config.json --local-dir ./config/Qwen2.5-1.5B-Instruct

# It is recommended to set the temperature to 0.1 and top_p to 0.5.
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
  "temperature": 0.1,
  "top_p": 0.5,
  "top_k": 20,
  "transformers_version": "4.37.0"
}

# Run vLLM with Docker
./run-docker-vllm---Qwen2.5-1.5B-Instruct.sh

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

#### 🔄 Real-time Sampling Logic Explained

**Scenario: High-Traffic Web Server Monitoring**

When monitoring a busy Apache access log in real-time, LogSentinelAI automatically switches to sampling mode to prevent analysis bottlenecks:

```bash
# Initial setup: Real-time monitoring with auto-sampling
logsentinelai-httpd-access --mode realtime --processing-mode full --sampling-threshold 100
```

**Example Timeline:**
```
[10:00:00] Normal traffic: 15 new log lines
           → Buffer: 15 lines pending
           → Status: FULL mode (under threshold)
           → Processing: Waiting for chunk_size=10 to accumulate

[10:00:05] Traffic spike: 250 new log lines accumulated  
           → Buffer: 265 total lines pending (15+250)
           → Trigger: Exceeds REALTIME_SAMPLING_THRESHOLD=100
           → Action: Auto-switch to SAMPLING mode
           → Sampling: Keep latest 10 lines only (chunk_size=10)
           → Skipped: 255 lines excluded from analysis (preserved in original log)
           → Processing: 10 lines analyzed by LLM

[10:00:10] Traffic continues: 180 new log lines
           → Buffer: 180 lines pending
           → Status: SAMPLING mode continues  
           → Sampling: Keep latest 10 lines only
           → Skipped: 170 lines excluded from analysis (preserved in original log)
           → Processing: 10 lines analyzed by LLM

[10:00:30] Traffic normalizes: 25 new log lines  
           → Buffer: 25 lines pending
           → Status: Back to FULL mode (under threshold)
           → Processing: ALL 25 lines will be processed in chunks of 10
```

**Sampling Strategy:**
- **FIFO Buffer**: Uses First-In-First-Out buffer (pending_lines) to accumulate logs
- **Threshold Trigger**: When buffer exceeds sampling_threshold, discards older logs
- **Simple Retention**: Keeps only latest `chunk_size` logs, discards all others
- **No Smart Selection**: Does not prioritize by severity, IP, or patterns - purely chronological
- **Original Files Intact**: Source log files remain unchanged and complete

**Configuration Impact:**
```bash
# Conservative sampling (analyze more, slower)
REALTIME_SAMPLING_THRESHOLD=50    # Trigger sampling earlier
--chunk-size 5                    # Smaller analysis chunks

# Aggressive sampling (analyze less, faster)  
REALTIME_SAMPLING_THRESHOLD=200   # Allow more accumulation
--chunk-size 20                   # Larger analysis chunks
```

**Key Benefits:**
- ✅ **Memory Control**: Prevents unlimited buffer growth during traffic spikes
- ✅ **Adaptive Behavior**: Automatically switches modes based on log volume
- ✅ **Cost Efficiency**: Reduces LLM API calls during high-traffic periods
- ⚠️ **Analysis Gaps**: Some logs excluded from AI analysis (not lost from disk)
- ⚠️ **Detection Limits**: May miss security events in unanalyzed logs

### Verify Configuration Changes
```bash
# Run analysis after configuration changes to verify operation
logsentinelai-httpd-access
```

---
## 🌍 GeoIP Enrichment (City-level, with coordinates)

LogSentinelAI automatically enriches IP addresses in analysis results with city/country/coordinates using MaxMind GeoLite2-City database. All major IP fields (source_ips, dest_ips, top_source_ips, top_dest_ips, top_event_ips 등) include a location (geo_point) for Kibana map visualization.

### 🚀 Automatic Setup (City DB)

```bash
# GeoIP City database is automatically downloaded to ~/.logsentinelai/ 
# when first needed - no manual setup required

# Optional: Pre-download GeoIP City database
logsentinelai-geoip-download
```

### 🚀 Quick Usage Examples

```bash
# View available commands
logsentinelai --help

# Clone repository for sample log files
git clone https://github.com/call518/LogSentinelAI.git
cd LogSentinelAI

# HTTP Access Log Analysis
logsentinelai-httpd-access --log-path sample-logs/access-10k.log

# Apache Error Log Analysis
logsentinelai-apache-error --log-path sample-logs/apache-10k.log

# Linux System Log Analysis
logsentinelai-linux-system --log-path sample-logs/linux-2k.log

# TCPDump Packet Analysis
logsentinelai-tcpdump --log-path sample-logs/tcpdump-packet-10k-single-line.log

# Real-time monitoring  
logsentinelai-linux-system --mode realtime

# Remote SSH analysis (requires host key in known_hosts)
logsentinelai-tcpdump --remote --ssh admin@server.com --ssh-key ~/.ssh/id_rsa

# Download GeoIP database
logsentinelai-geoip-download
```

### 📊 Feature Overview

- **Automatic download**: City DB downloads to `~/.logsentinelai/` when first needed
- **City/country/coordinates**: All enriched IPs include city, country, and location (geo_point) for Kibana
- **Kibana map ready**: All major IP fields are geo_point compatible for map visualization
- **Private IP handling**: Internal IPs are excluded from geo_point enrichment
- **Statistics enrichment**: All top IP stats include geo_point for map-based dashboards

### ⚙️ Configuration Options

```bash
# Enable/disable GeoIP enrichment  
GEOIP_ENABLED=true

# Path to MaxMind City DB file (automatically set to ~/.logsentinelai/)
GEOIP_DATABASE_PATH=~/.logsentinelai/GeoLite2-City.mmdb

# Fallback country for unknown IPs
GEOIP_FALLBACK_COUNTRY=Unknown

# Include private IPs in GeoIP processing
GEOIP_INCLUDE_PRIVATE_IPS=false

# Cache size for IP lookups (performance optimization)
```

### 🔧 Manual Database Download (If Needed)

The database downloads automatically, but if needed you can download manually:

```bash
# Download to default location
logsentinelai-geoip-download

# Download to custom location  
logsentinelai-geoip-download --output-dir /custom/path
```

If automatic download fails completely, manually download from MaxMind:

1. Visit: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
2. Download "GeoLite2 Country" in MaxMind DB format (.mmdb)
3. Extract and place as `GeoLite2-Country.mmdb` in project directory
4. Update `GEOIP_DATABASE_PATH` in config if using different location

### 📈 Performance Impact

- **Zero impact on LLM processing**: GeoIP enrichment happens after LLM analysis
- **Cached lookups**: Repeated IP addresses are cached for better performance
- **Graceful degradation**: Analysis continues normally if GeoIP is unavailable
- **Private IP optimization**: Private IPs are handled without database queries

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
- **Ollama**: Local model execution with models like `qwen3:1.7b`
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

```bash
# Method 1: Edit config file (persistent setting)
# Edit CHUNK_SIZE_* values in config file
CHUNK_SIZE_HTTPD_ACCESS=20
CHUNK_SIZE_LINUX_SYSTEM=15

# Method 2: Use CLI override (temporary setting)
python analysis-linux-system-log.py --chunk-size 5
python analysis-httpd-access-log.py --chunk-size 25
```

**Recommended values**: 5-50 depending on log complexity and LLM capacity

### Add Custom Log Analyzer

To add support for new log types, follow the established LogSentinelAI code structure with proper separation of concerns:

#### 📁 1. Add Prompt Template to Core

```python
# File: src/logsentinelai/core/prompts.py (add at the end)

PROMPT_TEMPLATE_CUSTOM_APP_LOG = """
Expert application log analyst reviewing custom application logs.

Each log line starts with LOGID-XXXXXX followed by the actual log content.
IMPORTANT: You MUST extract these LOGID values and include them in related_log_ids for each security event.

Analysis Focus:
- Application errors and exceptions
- Performance issues and slow queries
- Security-related events and authentication failures
- Database connection issues
- Memory/CPU resource problems

SEVERITY ESCALATION:
- CRITICAL: Application crashes, data corruption, security breaches
- HIGH: Multiple authentication failures, system resource exhaustion
- MEDIUM: Performance degradation, unusual patterns
- LOW: Minor warnings, configuration issues
- INFO: Normal operations, successful transactions

Logs to analyze:
{logs}

Return analysis in this JSON schema: {model_schema}
Response language: {response_language}
"""
```

#### 📁 2. Create Analyzer Module

```python
# File: src/logsentinelai/analyzers/custom_app.py
from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional

from ..core.prompts import PROMPT_TEMPLATE_CUSTOM_APP_LOG
from ..core import (
    run_generic_batch_analysis, 
    run_generic_realtime_analysis,
    create_argument_parser,
    handle_ssh_arguments
)

#---------------------- Custom App Log용 Enums 및 Models ----------------------
class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class EventType(str, Enum):
    APPLICATION_ERROR = "APPLICATION_ERROR"
    PERFORMANCE_ISSUE = "PERFORMANCE_ISSUE"
    AUTHENTICATION_EVENT = "AUTHENTICATION_EVENT"
    DATABASE_EVENT = "DATABASE_EVENT"
    SECURITY_EVENT = "SECURITY_EVENT"
    UNKNOWN = "UNKNOWN"

class SecurityEvent(BaseModel):
    event_type: EventType
    severity: SeverityLevel
    description: str = Field(description="Detailed event description")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Confidence level (0.0-1.0)")
    username: Optional[str] = Field(description="Related username/user ID")
    error_code: Optional[str] = Field(description="Application error code")
    recommended_actions: list[str] = Field(description="Recommended actions")
    requires_human_review: bool = Field(description="Whether human review is required")
    related_log_ids: list[str] = Field(description="Related LOGID list")

class Statistics(BaseModel):
    total_events: int = Field(description="Total number of events")
    unique_users: int = Field(description="Number of unique users")
    error_rate: float = Field(description="Error rate (0.0-1.0)")
    top_error_types: dict[str, int] = Field(default_factory=dict, description="Top error types")

class LogAnalysis(BaseModel):
    summary: str = Field(description="Analysis summary")
    events: list[SecurityEvent] = Field(min_items=1, description="List of security events")
    statistics: Statistics
    highest_severity: SeverityLevel
    requires_immediate_attention: bool = Field(description="Requires immediate attention")

def main():
    """Main function with argument parsing"""
    parser = create_argument_parser('Custom Application Log Analysis')
    args = parser.parse_args()
    
    ssh_config = handle_ssh_arguments(args)
    remote_mode = "ssh" if ssh_config else "local"
    
    if args.mode == 'realtime':
        run_generic_realtime_analysis(
            log_type="custom_app",
            analysis_schema_class=LogAnalysis,
            prompt_template=PROMPT_TEMPLATE_CUSTOM_APP_LOG,
            analysis_title="Custom Application Log Analysis",
            chunk_size=args.chunk_size,
            log_path=args.log_path,
            processing_mode=args.processing_mode,
            sampling_threshold=args.sampling_threshold,
            remote_mode=remote_mode,
            ssh_config=ssh_config
        )
    else:
        run_generic_batch_analysis(
            log_type="custom_app",
            analysis_schema_class=LogAnalysis,
            prompt_template=PROMPT_TEMPLATE_CUSTOM_APP_LOG,
            analysis_title="Custom Application Log Analysis",
            log_path=args.log_path,
            remote_mode=remote_mode,
            ssh_config=ssh_config
        )

if __name__ == "__main__":
    main()
```

#### ⚙️ 3. Update Configuration

```bash
# File: config (add these lines)

# Custom app log configuration
LOG_PATH_CUSTOM_APP=sample-logs/custom-app.log
LOG_PATH_REALTIME_CUSTOM_APP=/var/log/myapp/application.log
CHUNK_SIZE_CUSTOM_APP=15

# Optional: Custom response settings
# RESPONSE_LANGUAGE=english
```

#### 🚀 4. Usage Examples

```bash
# Run the analyzer directly (following existing pattern)
python src/logsentinelai/analyzers/custom_app.py

# Override log path and chunk size
python src/logsentinelai/analyzers/custom_app.py --log-path /var/log/myapp/app.log --chunk-size 20

# Real-time monitoring
python src/logsentinelai/analyzers/custom_app.py --mode realtime

# Remote analysis via SSH
python src/logsentinelai/analyzers/custom_app.py --remote --ssh user@server.com --ssh-key ~/.ssh/key

# Install as package and use CLI (after adding to pyproject.toml)
logsentinelai-custom-app --log-path /var/log/myapp/app.log
```

#### 🔧 5. Customization Options

**Modify Event Types for your application:**
```python
class EventType(str, Enum):
    PAYMENT_FAILURE = "PAYMENT_FAILURE"
    API_RATE_LIMIT = "API_RATE_LIMIT"
    # ... your custom types
```

**Add application-specific fields:**
```python
class SecurityEvent(BaseModel):
    transaction_id: Optional[str] = Field(description="Transaction ID")
    api_endpoint: Optional[str] = Field(description="API endpoint")
    # ... your custom fields
```

**Customize prompt for your log format:**
```python
PROMPT_TEMPLATE_CUSTOM_APP_LOG = """
Focus on {your_application_type} specific patterns:
- Payment processing errors
- API authentication failures
- Data validation issues
...
"""
```

#### 📦 6. Package Integration (Optional)

```toml
# File: pyproject.toml (add to [project.scripts] section)
logsentinelai-custom-app = "logsentinelai.analyzers.custom_app:main"
```

**Steps to add custom analyzer:**
1. **Add Prompt**: Add `PROMPT_TEMPLATE_*` to `src/logsentinelai/core/prompts.py`
2. **Create Analyzer**: Create analyzer module in `src/logsentinelai/analyzers/`
3. **Configure**: Add log paths to `config` file with appropriate prefixes
4. **Test**: Run analyzer and refine prompt based on results

## 📊 Output Data Schema

### Elasticsearch Document Structure

```json
{
  "@chunk_analysis_start_utc": "2025-07-25T10:00:00Z",
  "@chunk_analysis_end_utc": "2025-07-25T10:00:05Z", 
  "@processing_result": "success",
  "@processing_mode": "realtime",
  "@access_mode": "ssh",
  "@sampling_threshold": 100,
  "@log_count": 15,
  "@timestamp": "2025-07-25T10:00:05.123Z",
  "@log_type": "httpd_access",
  "@document_id": "httpd_access_20250725_100005_123456_chunk_1",
  "@llm_provider": "vllm",
  "@llm_model": "Qwen/Qwen2.5-1.5B-Instruct",
  "@log_path": "/var/log/apache2/access.log",
  "@log_raw_data": {
    "LOGID-7DD17B008706AC22C60AD6DF9AC5E2E9": "203.0.113.45 - - [25/Jul/2025:10:00:01 +0000] \"GET /api/users?id=1' OR '1'='1 HTTP/1.1\" 403 2847",
    "LOGID-F3B6E3F03EC9E5BC1F65624EB65C6C51": "198.51.100.23 - - [25/Jul/2025:10:00:02 +0000] \"POST /api/login HTTP/1.1\" 200 1205"
  },
  "summary": "Analysis detected SQL injection attempts and suspicious authentication patterns from multiple international sources. Immediate review recommended.",
  "events": [
    {
      "event_type": "SQL_INJECTION",
      "severity": "HIGH", 
      "description": "SQL injection attack attempt detected in GET parameter from US-based IP",
      "confidence_score": 0.92,
      "source_ips": ["203.0.113.45 (US - United States)"],
      "url_pattern": "/api/users",
      "http_method": "GET",
      "response_codes": ["403"],
      "attack_patterns": ["SQL_INJECTION", "PARAMETER_MANIPULATION"],
      "recommended_actions": ["Block IP immediately", "Add WAF rule", "Review user account security"],
      "requires_human_review": true,
      "related_log_ids": ["LOGID-7DD17B008706AC22C60AD6DF9AC5E2E9"]
    },
    {
      "event_type": "SUSPICIOUS_LOGIN",
      "severity": "MEDIUM",
      "description": "Multiple authentication attempts from France-based IP within short timeframe",
      "confidence_score": 0.75,
      "source_ips": ["198.51.100.23 (FR - France)"],
      "url_pattern": "/api/login",
      "http_method": "POST", 
      "response_codes": ["200"],
      "attack_patterns": ["BRUTE_FORCE", "CREDENTIAL_STUFFING"],
      "recommended_actions": ["Monitor IP", "Enable 2FA", "Check user account activity"],
      "requires_human_review": false,
      "related_log_ids": ["LOGID-F3B6E3F03EC9E5BC1F65624EB65C6C51"]
    }
  ],
  "statistics": {
    "total_requests": 15,
    "unique_ips": 8,
    "error_rate": 0.13,
    "top_source_ips": {
      "203.0.113.45 (US - United States)": 3,
      "198.51.100.23 (FR - France)": 2,
      "192.168.1.100 (Private)": 5,
      "10.0.0.50 (Private)": 3,
      "172.16.0.25 (Private)": 2
    },
    "response_code_dist": {
      "200": 11,
      "403": 2,
      "404": 1,
      "500": 1
    },
    "event_by_type": {
      "SQL_INJECTION": 1,
      "SUSPICIOUS_LOGIN": 1,
      "INFO": 2
    }
  },
  "highest_severity": "HIGH",
  "requires_immediate_attention": true
}
```

---

## 🙏 Acknowledgments

We would like to express our sincere gratitude to the following projects and communities that provided inspiration, guidance, and foundational technologies for LogSentinelAI:

### 🔧 Core Technologies & Frameworks
- **[Outlines](https://dottxt-ai.github.io/outlines/latest/)** - Structured LLM output generation framework that powers our reliable AI analysis
- **[dottxt-ai Demos](https://github.com/dottxt-ai/demos/tree/main/logs)** - Excellent log analysis examples and implementation patterns
- **[Docker ELK Stack](https://github.com/deviantony/docker-elk)** - Comprehensive Elasticsearch, Logstash, and Kibana Docker setup
- **[Elastic Stack Docker-Compose Part 1](https://www.elastic.co/blog/getting-started-with-the-elastic-stack-and-docker-compose)** - Official Elastic documentation for Docker deployment
- **[Elastic Stack Docker-Compose Part 2](https://www.elastic.co/blog/getting-started-with-the-elastic-stack-and-docker-compose-part-2)** - Advanced configuration and security setup

### 🤖 LLM Infrastructure & Deployment
- **[vLLM](https://github.com/vllm-project/vllm)** - High-performance LLM inference engine for GPU-accelerated local deployment
- **[Ollama](https://ollama.com/)** - Simplified local LLM deployment and management platform

### 🌟 Open Source Community
We are deeply grateful to the broader open source community and the countless projects that have contributed to making AI-powered log analysis accessible and practical. This project stands on the shoulders of many innovative open source initiatives that continue to push the boundaries of what's possible.

---

## 🤝 Contributing

LogSentinelAI is just getting started and there's much room for improvement. Contributions, bug reports, feature requests, and feedback are all welcome! Whether you're fixing a typo, adding a feature, or sharing ideas - every contribution helps make this project better for everyone.

Feel free to:
- 🐛 Report bugs or issues
- 💡 Suggest new features or improvements  
- 🔧 Submit pull requests
- 📖 Improve documentation
- ⭐ Star the project if you find it useful!