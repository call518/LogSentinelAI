# SonarLog - AI-Powered Log Security Analysis

SonarLog is a system that leverages LLM (Large Language Model) to analyze various log files and detect security events. It automatically analyzes Apache HTTP logs, Linux system logs, and other log types to identify security threats and stores them as structured data in Elasticsearch.

## 🌟 Key Features

- **Multi-format Log Support**: HTTP Access Log, Apache Error Log, Linux System Log
- **AI-based Security Analysis**: Intelligent security event detection through LLM
- **Structured Data Output**: JSON schema validation using Pydantic models
- **Elasticsearch Integration**: Real-time log analysis result storage and search
- **Kibana Dashboard**: Visualized security analysis result monitoring
- **LOGID Tracking**: Complete traceability between original logs and analysis results

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

## 🚀 Installation & Setup

### 1. Install Dependencies

```bash
# Create Python virtual environment (optional)
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install packages
pip install -r requirements.txt
```

### 2. Environment Variable Setup

```bash
# Create .env file
cp .env.template .env

# Set OpenAI API key (when using OpenAI)
echo "OPENAI_API_KEY=your_api_key_here" >> .env
```

### 3. LLM Model Setup

#### Option 1: Ollama (Local Execution)
```bash
# Install Ollama and download model
ollama pull qwen2.5-coder:3b
ollama serve
```

#### Option 2: vLLM (GPU Acceleration)
```bash
# Install vLLM and run server
pip install vllm
python -m vllm.entrypoints.openai.api_server --model qwen2.5-coder:3b
```

#### Option 3: OpenAI API
- Set `OPENAI_API_KEY` in `.env` file

### 4. Elasticsearch Setup

- Github: https://github.com/call518/Docker-ELK

```bash
# Run Elasticsearch + Kibana with Docker Compose
docker-compose up -d

# Or install local Elasticsearch
# Check Elasticsearch port 9200, Kibana port 5601
```

## 💻 Usage

### HTTP Access Log Analysis

```bash
python analysis-httpd-access-log.py
```

### Apache Error Log Analysis

```bash
python analysis-httpd-apache-log.py
```

### Linux System Log Analysis

```bash
python analysis-linux-system-log.py
```

## 📁 Project Structure

```
SonarLog/
├── analysis-httpd-access-log.py    # HTTP access log analyzer
├── analysis-httpd-apache-log.py    # Apache error log analyzer
├── analysis-linux-system-log.py    # Linux system log analyzer
├── commons.py                      # Common functions and utilities
├── requirements.txt                # Python dependencies
├── .env.template                   # Environment variables template
├── sample-logs/                    # Sample log files
│   ├── access-10.log
│   ├── apache-10.log
│   └── linux-10.log
├── img/                           # Documentation images
│   ├── ex-dashboard.png
│   └── ex-json.png
└── Kibana-Dashboard-SonarLog.ndjson # Kibana dashboard configuration
```

## 🔧 Configuration Options

### Change LLM Provider

You can change the LLM provider in `commons.py`:

```python
# Set in initialize_llm_model function
model = initialize_llm_model("ollama")    # Ollama
model = initialize_llm_model("vllm")      # vLLM
model = initialize_llm_model("openai")    # OpenAI
```

### Adjust Chunk Size

You can adjust chunk size for log processing performance:

```python
# In each analysis script
chunk_size = 10  # Default value, adjust as needed
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
  "related_log_ids": ["LOGID-ABC123", "LOGID-DEF456"]
}
```

### Elasticsearch Document Structure

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

## 🎯 Key Features

### 1. Intelligent Security Detection
- **Various Attack Pattern Recognition**: SQL Injection, XSS, Brute Force, Command Injection, etc.
- **Context-based Analysis**: Analysis considering log patterns and correlations
- **Confidence Score**: Confidence level for each detection result

### 2. Complete Traceability
- **LOGID System**: Unique identifier assignment for each log line
- **Original Data Preservation**: Original log data stored with analysis results
- **Related Log Mapping**: Connection between security events and related log lines

### 3. Scalable Architecture
- **Modular Design**: Independent analyzer for each log type
- **Common Function Library**: Reduced code duplication and improved maintainability
- **Plugin Approach**: Easy addition of new log formats

## 📈 Performance Optimization

### Chunk-based Processing
- Process large log files by dividing into small chunks
- Memory efficiency and parallel processing support

### Token Optimization
- Prompt optimization to minimize LLM input tokens
- Parsing efficiency improvement through structured output

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
- **Documentation**: [Wiki](https://github.com/call518/SonarLog/wiki)
- **Email**: call518@gmail.com

## 🏷️ Version Information

- **Current Version**: 1.0.0
- **Python**: 3.11+
- **Elasticsearch**: 8.16+
- **Kibana**: 8.16+

---

**SonarLog** - Intelligent Log Security Analysis with AI 🔍🛡️