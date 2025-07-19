# SonarLog - AI-Powered Log Security Analysis

SonarLog is a system that leverages LLM (Large Language Model) to analyze various log files and detect security events. It automatically analyzes Apache HTTP logs, Linux system logs, and other log types to identify security threats and stores them as structured data in Elasticsearch for visualization and analysis.

## 🌟 Key Features

- **Multi-format Log Support**: HTTP Access Log, Apache Error Log, Linux System Log, Network Packet Analysis
- **AI-based Security Analysis**: Intelligent security event detection through LLM
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
│   Log Files     │───▶│   SonarLog      │───▶│ Elasticsearch   │
│                 │    │   Analysis      │    │                 │
│ • HTTP Access   │    │                 │    │ • Security      │
│ • Apache Error  │    │ • LLM Analysis  │    │   Events        │
│ • System Logs   │    │ • Pydantic      │    │ • Raw Logs      │
│ • Network Pcap  │    │   Validation    │    │ • Metadata      │
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

## 🚀 Installation & Setup

### 1. Basic Requirements

- **Tested Environment**: Windows 11 + WSL2 (v2.5.9) + Docker Desktop (v4.39.0)
- **Hardware**: NVIDIA GeForce GTX 1660 SUPER GPU
- **Software**: Python 3.11.13

### 2. QuickStart Guide

#### Step 1: Project Setup

```bash
# Clone repository
git clone https://github.com/call518/SonarLog.git
cd SonarLog

# Create Python virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install packages
pip install -r requirements.txt

# Configure environment variables
cp .env.template .env
# Edit .env file to add required settings (e.g., OPENAI_API_KEY if using OpenAI)
```

#### Step 2: Set up vLLM Server (GPU Acceleration)

```bash
# Option A: Clone and use vLLM-Tutorial
git clone https://github.com/call518/vLLM-Tutorial.git
cd vLLM-Tutorial

# Install Hugging Face CLI for model download
pip install huggingface_hub

# Download model (optional)
huggingface-cli download lmstudio-community/Qwen2.5-3B-Instruct-GGUF Qwen2.5-3B-Instruct-Q4_K_M.gguf --local-dir ./models/Qwen2.5-3B-Instruct/
huggingface-cli download Qwen/Qwen2.5-3B-Instruct generation_config.json --local-dir ./config

# Run vLLM with Docker
./run-docker-vllm---Qwen2.5-3B-Instruct.sh

# Verify API is working
curl -s -X GET http://localhost:5000/v1/models | jq

# Option B: Alternative LLM setups
# Ollama (Local Execution)
ollama pull qwen2.5-coder:3b
ollama serve

# OR simple vLLM setup (without Docker)
pip install vllm
python -m vllm.entrypoints.openai.api_server --model qwen2.5-coder:3b

# OR use OpenAI API (cloud)
# Set OPENAI_API_KEY in .env file
```

#### Step 3: Set up Elasticsearch and Kibana

```bash
# Clone Docker-ELK repository
git clone https://github.com/call518/Docker-ELK.git
cd Docker-ELK

# Initialize ELK stack
docker compose up setup

# Generate Kibana encryption keys (recommended)
docker compose up kibana-genkeys
# Copy the output keys to kibana/config/kibana.yml

# Start ELK stack
docker compose up -d

# Access Kibana at http://localhost:5601
# Default credentials: elastic / changeme
```

#### Step 4: Run SonarLog Analysis

```bash
# Run HTTP access log analysis
python analysis-httpd-access-log.py

# Run Apache error log analysis
python analysis-httpd-apache-log.py

# Run Linux system log analysis
python analysis-linux-system-log.py

# Run network packet analysis (tcpdump)
python analysis-tcpdump-packet.py
```

#### Step 5: Import Kibana Dashboard

```bash
# Log into Kibana
# Navigate to Stack Management > Saved Objects > Import
# Import the Kibana-Dashboard-SonarLog.ndjson file
```

## 📁 Project Structure

```
SonarLog/
├── analysis-httpd-access-log.py    # HTTP access log analyzer
├── analysis-httpd-apache-log.py    # Apache error log analyzer
├── analysis-linux-system-log.py    # Linux system log analyzer
├── analysis-tcpdump-packet.py      # Network packet analyzer (tcpdump)
├── commons.py                      # Common functions and utilities
├── prompts.py                      # LLM prompt templates
├── requirements.txt                # Python dependencies
├── .env                           # Environment variables (created from template)
├── .env.template                  # Environment variables template
├── .gitignore                     # Git ignore file
├── LICENSE                        # MIT License
├── README.md                      # This file
├── README-Outlines.md             # Documentation outlines
├── sample-logs/                   # Sample log files
│   ├── access-100.log             # 100 HTTP access log entries
│   ├── access-10k.log             # 10,000 HTTP access log entries
│   ├── apache-100.log             # 100 Apache error log entries
│   ├── apache-10k.log             # 10,000 Apache error log entries
│   ├── linux-100.log              # 100 Linux system log entries
│   ├── linux-2k.log               # 2,000 Linux system log entries
│   └── tcpdump-packet-39.log      # Sample tcpdump packet capture (39 packets)
├── img/                           # Documentation images
│   ├── ex-dashboard.png           # Kibana dashboard example
│   └── ex-json.png                # JSON output example
└── Kibana-Dashboard-SonarLog.ndjson # Kibana dashboard configuration
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

### 1. Intelligent Security Detection
- **Various Attack Pattern Recognition**: SQL Injection, XSS, Brute Force, Command Injection, etc.
- **Context-based Analysis**: Analysis considering log patterns and correlations
- **Confidence Score**: Confidence level for each detection result
- **Mandatory Event Generation**: Every log chunk generates at least one security event
- **Balanced Severity Assessment**: Enhanced sensitivity for security pattern detection

### 2. Complete Traceability  
- **LOGID System**: Unique MD5-based identifier for each log line (e.g., `LOGID-7DD17B008706AC22C60AD6DF9AC5E2E9`)
- **Original Data Preservation**: Raw log data stored with `@log_raw_data` field in Elasticsearch
- **Related Log Mapping**: LLM specifies which LOGIDs are related to each security event
- **Full Audit Trail**: Complete traceability from original logs to analysis results

### 3. Scalable Architecture
- **Modular Design**: Independent analyzer for each log type
- **Shared Commons Library**: Centralized functions in `commons.py` for code reusability
- **Chunk-based Processing**: Memory-efficient processing of large log files
- **Error Handling**: Robust error handling with failure tracking in Elasticsearch

## 📈 Performance Optimization

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

- **Issues**: [GitHub Issues](https://github.com/call518/SonarLog/issues)
- **Documentation**: [GitHub Wiki](https://github.com/call518/SonarLog/wiki)
- **Repository**: [GitHub Repository](https://github.com/call518/SonarLog)
- **Email**: support@sonarlog.dev

## 🏷️ Version Information

- **Current Version**: v1.3.2
- **Python**: 3.11+
- **Elasticsearch**: 8.16+
- **Kibana**: 8.16+
- **Key Dependencies**: 
  - `outlines` for structured LLM output
  - `pydantic` for data validation
  - `elasticsearch` for data storage
  - `ollama`, `openai` for LLM providers

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

#### Network Log Analysis
- **tcpdump Packet Analysis**: Support for network packet capture analysis
- **Enhanced Network Security Events**: Detect network-based attacks and anomalies
- **Protocol Support**: Analysis of various network protocols and traffic patterns
- **Traffic Pattern Recognition**: Identify suspicious network behavior patterns

### 🚀 Future Enhancements
- **Machine Learning Integration**: Anomaly detection using ML models
- **Custom Rule Engine**: User-defined security rules and patterns
- **Multi-tenant Support**: Support for multiple organizations/tenants
- **Advanced Visualization**: Enhanced Kibana dashboards with geo-mapping
- **API Integration**: RESTful API for external system integration

---

**SonarLog** - Intelligent Log Security Analysis with AI 🔍🛡️