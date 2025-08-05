# LogSentinelAI Wiki

Welcome to the LogSentinelAI Wiki! This comprehensive guide covers everything you need to know about using LogSentinelAI for intelligent log analysis.

## 📚 Table of Contents

### Core Concepts
- [Declarative Extraction](#declarative-extraction-schema-driven-ai-log-structuring)

### User Guides
- [Analyzing Different Log Types](#analyzing-different-log-types)
- [LLM Provider Setup](#llm-provider-setup)
- [Elasticsearch Integration](#elasticsearch-integration)
- [Kibana Dashboard Setup](#kibana-dashboard-setup)

### Advanced Usage
- [Remote Log Analysis via SSH](#remote-log-analysis-via-ssh)
- [Real-time Monitoring](#real-time-monitoring)
- [Custom Prompts](#custom-prompts)
- [Performance Optimization](#performance-optimization)

### Reference
- [CLI Commands Reference](#cli-commands-reference)
- [Configuration Options](#configuration-options)
- [Output Format](#output-format)
- [Troubleshooting](#troubleshooting)

### Development
- [Contributing](#contributing)

---

## Declarative Extraction: Schema-Driven AI Log Structuring

LogSentinelAI's core feature is **Declarative Extraction**. In each analyzer, you simply declare the result structure (Pydantic class) you want, and the LLM automatically analyzes logs and returns results in that structure as JSON. No complex parsing or post-processing—just declare the fields you want, and the AI fills them in.

### Basic Usage

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

By declaring only the result structure you want in each analyzer, the LLM automatically returns results in that structure—no manual parsing required.

---

## Analyzing Different Log Types

### Apache/Nginx Access Logs
```bash
# Basic analysis
logsentinelai-httpd-access /var/log/apache2/access.log

# With Elasticsearch output
logsentinelai-httpd-access /var/log/nginx/access.log --output elasticsearch

# Real-time monitoring
logsentinelai-httpd-access /var/log/apache2/access.log --monitor
```

**What it detects:**
- SQL injection attempts
- XSS attacks
- Brute force attacks
- Suspicious user agents
- Unusual request patterns
- Geographic anomalies

### Apache Error Logs
```bash
logsentinelai-httpd-server /var/log/apache2/error.log
```

**What it detects:**
- Configuration errors
- Module failures
- Security-related errors
- Performance issues

### Linux System Logs
```bash
logsentinelai-linux-system /var/log/syslog
```

**What it detects:**
- Authentication failures
- Service crashes
- Security events
- System anomalies

---

## LLM Provider Setup

### OpenAI Setup Guide

1. **Get API Key**
   - Visit https://platform.openai.com/api-keys
   - Create new API key
   - Copy the key

2. **Configure LogSentinelAI**
   ```toml
   [llm]
   provider = "openai"
   model = "gpt-4o-mini"
   api_key = "sk-your-key-here"
   ```

3. **Test Configuration**
   ```bash
   logsentinelai-httpd-access sample-logs/access-100.log
   ```

### Ollama Setup Guide

1. **Install Ollama**
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```

2. **Pull Model**
   ```bash
   ollama pull llama3.1:8b
   ```

3. **Configure LogSentinelAI**
   ```toml
   [llm]
   provider = "ollama"
   model = "llama3.1:8b"
   base_url = "http://localhost:11434"
   ```

### Model Recommendations

| Use Case | OpenAI | Ollama | Performance |
|----------|--------|--------|-------------|
| **High Accuracy** | gpt-4o | llama3.1:70b | Excellent |
| **Balanced** | gpt-4o-mini | llama3.1:8b | Good |
| **Fast/Local** | gpt-3.5-turbo | mistral:7b | Fast |

---

## Elasticsearch Integration

> **📋 Installation**: See [INSTALL.ko.md](../INSTALL.ko.md) for complete Docker-ELK setup instructions.

### Quick Usage After Installation

Once your Elasticsearch is running (via Docker-ELK or standalone), configure LogSentinelAI:

```toml
[elasticsearch]
enabled = true
host = "localhost"
port = 9200
index_prefix = "logsentinelai"
```

### Automatic Index Management

LogSentinelAI automatically creates optimized index templates:
- **Security Events**: `logsentinelai-security-YYYY.MM.DD`
- **Raw Logs**: `logsentinelai-logs-YYYY.MM.DD`
- **Metadata**: `logsentinelai-metadata-YYYY.MM.DD`

### Index Lifecycle Management (ILM)

Default retention policy automatically applied:
- **Hot Phase**: 7 days (frequent searches)
- **Warm Phase**: 30 days (occasional searches)
- **Cold Phase**: 90 days (rare searches)
- **Delete**: 365 days (automatic cleanup)

### Usage Tips

**Real-time Indexing**:
```bash
# Stream analysis results directly to Elasticsearch
logsentinelai-httpd-access /var/log/apache2/access.log --output elasticsearch --mode realtime
```

**Bulk Processing**:
```bash
# Process multiple log files into Elasticsearch
logsentinelai-httpd-access /var/log/apache2/access.log.* --output elasticsearch
```

**Index Monitoring**:
```bash
# Check index status
curl "http://localhost:9200/_cat/indices/logsentinelai-*?v"

# View today's security events count
curl "http://localhost:9200/logsentinelai-security-$(date +%Y.%m.%d)/_count"
```

---

## Kibana Dashboard Setup

> **📋 Installation**: See [INSTALL.ko.md](../INSTALL.ko.md) for complete Kibana setup with Docker-ELK.

### Quick Setup After Installation

1. **Import Pre-built Dashboard**
   ```bash
   # Dashboard file is included in the repository
   curl -X POST "localhost:5601/api/saved_objects/_import" \
     -H "kbn-xsrf: true" \
     -H "Content-Type: application/json" \
     --form file=@Kibana-9.0.3-Dashboard-LogSentinelAI.ndjson
   ```

2. **Configure Index Patterns**
   - Go to Kibana → Stack Management → Index Patterns
   - Create pattern: `logsentinelai-*`
   - Set time field: `@timestamp`

### Dashboard Features

- **🚨 Security Overview**: Real-time threat detection with severity breakdown
- **🌍 Geographic Analysis**: Attack origin mapping with coordinates
- **📈 Timeline Analysis**: Event chronology and trend analysis
- **👥 Top Attackers**: Most active threat sources ranked
- **🎯 Attack Types**: Categorized threat analysis with drill-down

### Usage Tips

**Custom Time Ranges**:
- Use Kibana's time picker for specific analysis periods
- Set up auto-refresh for real-time monitoring

**Filtering and Searching**:
```bash
# Example KQL queries for LogSentinelAI data
severity: "high" OR severity: "critical"
source_ips: "192.168.*"
event_type: "sql_injection"
```

**Dashboard Customization**:
- Clone existing dashboard for custom views
- Add new visualizations based on your specific log patterns
- Set up custom alerts based on threat patterns

---

## Remote Log Analysis via SSH

> **⚠️ Important**: For SSH connections, the target host must be added to your system's known_hosts file first. Run `ssh-keyscan -H <hostname> >> ~/.ssh/known_hosts` or manually connect once to accept the host key.

### Configuration
```toml
[ssh]
enabled = true
host = "remote-server.com"
username = "loguser"
key_file = "~/.ssh/id_rsa"
```

### Usage
```bash
# Analyze remote logs
logsentinelai-httpd-access \
  --ssh-host remote-server.com \
  --ssh-user loguser \
  --ssh-key ~/.ssh/id_rsa \
  /var/log/apache2/access.log
```

### Security Best Practices
- Use SSH keys, not passwords
- Limit SSH user permissions
- Use dedicated log analysis user
- Consider SSH tunneling for security

---

## Real-time Monitoring

### Real-time Mode Behavior
Real-time monitoring in LogSentinelAI works with **new logs only**:
- Starts monitoring from the **current end of the log file**
- Only processes **newly added log entries** after the monitoring starts
- **Past logs are never processed** - this ensures true real-time behavior
- If monitoring is stopped and restarted, it continues from the current file position (not from where it was previously stopped)

### Monitor Mode
```bash
# Monitor Apache logs in real-time
logsentinelai-httpd-access --mode realtime

# With custom sampling threshold
logsentinelai-httpd-access --mode realtime --sampling-threshold 200
```

### Monitoring Features
- **Live Analysis**: Process logs as they're written
- **Sampling**: Reduce load on high-traffic systems  
- **Real-time Alerts**: Immediate threat detection
- **Continuous Indexing**: Stream to Elasticsearch

---

## Custom Prompts

### Modifying Prompts

Edit `src/logsentinelai/core/prompts.py`:

```python
HTTPD_ACCESS_PROMPT = """
Analyze this Apache/Nginx access log for security threats:

Focus on:
1. SQL injection patterns
2. XSS attempts
3. Your custom criteria here

Log entry: {log_entry}
"""
```

### Language Support

Change analysis language in config:
```toml
[analysis]
language = "korean"  # korean, japanese, spanish, etc.
```

---

## Performance Optimization

### Batch Processing
```bash
# Process multiple files
logsentinelai-httpd-access /var/log/apache2/access.log.* --batch

# Parallel processing
logsentinelai-httpd-access /var/log/*.log --parallel 4
```

### Memory Optimization
```toml
[analysis]
batch_size = 100  # Process 100 entries at once
max_tokens = 2000  # Reduce token limit
```

### LLM Optimization
- **Use smaller models** for high-volume analysis
- **Enable sampling** for real-time monitoring
- **Cache results** for repeated patterns

---

## CLI Commands Reference

### Core Commands

#### logsentinelai-httpd-access
```bash
logsentinelai-httpd-access [OPTIONS] LOG_FILE

Options:
  --output [json|elasticsearch|stdout]  Output format
  --monitor                            Real-time monitoring
  --sample-rate INTEGER               Sampling rate for monitoring
  --ssh-host TEXT                     SSH hostname
  --ssh-user TEXT                     SSH username
  --ssh-key TEXT                      SSH key file path
  --help                              Show help message
```

#### logsentinelai-httpd-server
```bash
logsentinelai-httpd-server [OPTIONS] LOG_FILE
# Similar options to httpd-access
```

#### logsentinelai-linux-system
```bash
logsentinelai-linux-system [OPTIONS] LOG_FILE
# Similar options to httpd-access
```

### Utility Commands

#### logsentinelai-geoip-download
```bash
logsentinelai-geoip-download [OPTIONS]

Options:
  --force    Force re-download even if database exists
  --help     Show help message
```

### Global Options
All commands support:
- `--config PATH`: Custom configuration file
- `--verbose`: Enable verbose logging
- `--quiet`: Suppress output except errors

---

## Configuration Options

### Complete Configuration Reference

LogSentinelAI uses environment variables for configuration. Copy `config.template` to `config` and customize:

```bash
# Copy configuration template
cp config.template config
# Edit configuration
nano config
```

**Key Configuration Sections:**

**LLM Provider Configuration:**
```bash
# Provider Selection
LLM_PROVIDER=openai          # openai, ollama, vllm, gemini

# Model Selection (per provider)
LLM_MODEL_OPENAI=gpt-4o-mini
LLM_MODEL_OLLAMA=qwen2.5-coder:3b
LLM_MODEL_GEMINI=gemini-1.5-pro

# API Configuration
OPENAI_API_KEY=sk-your-key-here
LLM_API_HOST_OPENAI=https://api.openai.com/v1
LLM_API_HOST_OLLAMA=http://127.0.0.1:11434

# Generation Parameters
LLM_TEMPERATURE=0.1          # Consistency for log analysis
LLM_TOP_P=0.3               # Focus on high-probability tokens
```

**Analysis Configuration:**
```bash
# Language and Mode
RESPONSE_LANGUAGE=english    # korean, japanese, etc.
ANALYSIS_MODE=batch         # batch or realtime

# Chunk Sizes (entries per LLM request)
CHUNK_SIZE_HTTPD_ACCESS=10
CHUNK_SIZE_LINUX_SYSTEM=10
CHUNK_SIZE_GENERAL_LOG=10

# Default Log Paths
LOG_PATH_HTTPD_ACCESS=sample-logs/access-10k.log
LOG_PATH_LINUX_SYSTEM=sample-logs/linux-2k.log
```

**Real-time Monitoring:**
```bash
# Polling Configuration
REALTIME_POLLING_INTERVAL=5      # Check interval (seconds)
REALTIME_MAX_LINES_PER_BATCH=50  # Max lines per poll
REALTIME_BUFFER_TIME=2           # Wait for complete lines

# Sampling Control
REALTIME_SAMPLING_THRESHOLD=100  # Auto-sampling trigger
```

**GeoIP Configuration:**
```bash
GEOIP_ENABLED=true
GEOIP_DATABASE_PATH=~/.logsentinelai/GeoLite2-City.mmdb
GEOIP_INCLUDE_PRIVATE_IPS=false
GEOIP_CACHE_SIZE=1000
```

**Elasticsearch Configuration:**
```bash
ELASTICSEARCH_HOST=http://localhost:9200
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=changeme
ELASTICSEARCH_INDEX=logsentinelai-analysis
```

**SSH Remote Access:**
```bash
REMOTE_LOG_MODE=local       # local or ssh
REMOTE_SSH_HOST=server.com
REMOTE_SSH_USER=loguser
REMOTE_SSH_KEY_PATH=~/.ssh/id_rsa
REMOTE_SSH_TIMEOUT=10
```

> **📋 Full Reference**: See `config.template` in the repository for all available options with detailed comments.

---

## Output Format

> **🚀 Key Advantage**: LogSentinelAI uses **Declarative Extraction** - you simply declare the output structure you want (Pydantic models), and the LLM automatically extracts relevant information from logs to match that structure. No manual parsing or field mapping required!

### How Declarative Extraction Works

**Traditional Log Analysis:**
```bash
# Manual parsing, regex patterns, field mapping
grep "ERROR" /var/log/app.log | awk '{print $1, $3}' | sed 's/[^a-zA-Z0-9]//g'
```

**LogSentinelAI Approach:**
```python
# Just declare what you want
class SecurityEvent(BaseModel):
    severity: str
    threat_type: str
    source_ip: str
    confidence_score: float
    description: str
```

The LLM automatically fills these fields from any log format - no parsing rules needed!

### Example Output Structures

Each analyzer produces structured output based on its declared Pydantic model:

**HTTP Access Log Analysis:**
```json
{
  "events": [
    {
      "event_type": "suspicious_access",
      "severity": "high", 
      "source_ips": ["192.168.1.100"],
      "url_pattern": "/admin.php",
      "attack_patterns": ["sql_injection"],
      "confidence_score": 0.85,
      "description": "SQL injection attempt detected",
      "recommended_actions": ["Block IP", "Review security rules"]
    }
  ],
  "statistics": {
    "total_requests": 1500,
    "unique_ips": 45,
    "error_rate": 0.12
  }
}
```

**Linux System Log Analysis:**
```json
{
  "events": [
    {
      "event_type": "auth_failure", 
      "severity": "medium",
      "username": "admin",
      "source_ips": ["10.0.0.5"],
      "process": "sshd",
      "confidence_score": 0.9,
      "description": "Multiple authentication failures detected"
    }
  ],
  "statistics": {
    "total_events": 25,
    "auth_failures": 8,
    "unique_users": 3
  }
}
```

### JSON Output Structure

```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "log_type": "httpd_access",
  "original_log": "192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] \"GET /admin.php HTTP/1.1\" 200 1234",
  "analysis": {
    "threat_detected": true,
    "threat_type": "suspicious_access",
    "severity": "medium",
    "confidence": 0.85,
    "description": "Access to admin interface from unusual IP",
    "recommendations": [
      "Monitor this IP for further suspicious activity",
      "Consider implementing IP-based access controls"
    ]
  },
  "parsed_fields": {
    "ip_address": "192.168.1.100",
    "timestamp": "15/Jan/2024:10:30:45 +0000",
    "method": "GET",
    "path": "/admin.php",
    "status_code": 200,
    "response_size": 1234
  },
  "enrichment": {
    "geoip": {
      "ip": "192.168.1.100",
      "country_code": "US",
      "country_name": "United States",
      "city": "New York",
      "latitude": 40.7128,
      "longitude": -74.0060
    },
    "reputation": {
      "is_known_bad": false,
      "threat_score": 0.3
    }
  },
  "metadata": {
    "analyzer_version": "0.2.3",
    "model_used": "gpt-4o-mini",
    "processing_time": 1.2
  }
}
```

### Customizing Output Fields

**The Power of Declaration**: Want different fields? Just declare them in your analyzer's Pydantic model:

```python
# Custom Security Event Structure
class MySecurityEvent(BaseModel):
    timestamp: str
    risk_level: int  # 1-10 scale
    attack_vector: str
    affected_service: str
    remediation_steps: List[str]
    business_impact: str
```

The LLM will automatically extract and populate these fields from your logs, regardless of the original log format!

### Security Event Fields

| Field | Type | Description | Auto-Extracted |
|-------|------|-------------|----------------|
| `threat_detected` | boolean | Whether a threat was detected | ✅ From log patterns |
| `threat_type` | string | Type of threat (sql_injection, xss, brute_force, etc.) | ✅ From attack signatures |
| `severity` | string | Severity level (low, medium, high, critical) | ✅ From impact analysis |
| `confidence` | float | Confidence score (0.0-1.0) | ✅ From pattern matching |
| `description` | string | Human-readable description | ✅ From log context |
| `recommendations` | array | Recommended actions | ✅ From threat intelligence |

**✨ Key Insight**: All these fields are automatically extracted by the LLM based on your declared structure. Change the structure, get different data - no code changes needed!

---

## Troubleshooting

### Common Issues

#### 1. "LLM API Error"
**Problem**: API calls to LLM provider failing

**Solutions**:
- Check API key validity
- Verify network connectivity
- Check provider status page
- Increase timeout in config

```bash
# Test connectivity
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
  https://api.openai.com/v1/models
```

#### 2. "GeoIP Database Not Found"
**Problem**: GeoIP lookups failing

**Solutions**:
```bash
# Re-download database (City database includes coordinates)
logsentinelai-geoip-download

# Check database location and verify it's the City database
ls -la ~/.logsentinelai/GeoLite2-City.mmdb

# Test GeoIP functionality
python -c "from logsentinelai.core.geoip import get_geoip_lookup; g=get_geoip_lookup(); print(g.lookup_geoip('8.8.8.8'))"
```

#### 3. "Elasticsearch Connection Failed"
**Problem**: Cannot connect to Elasticsearch

**Solutions**:
- Check Elasticsearch status: `curl http://localhost:9200`
- Verify configuration in config file
- Check network connectivity

#### 4. "Permission Denied on Log Files"
**Problem**: Cannot read log files

**Solutions**:
```bash
# Add user to log group
sudo usermod -a -G adm $USER

# Change log file permissions
sudo chmod 644 /var/log/apache2/access.log
```

### Performance Issues

#### High Memory Usage
- Reduce `batch_size` in config
- Use smaller LLM models
- Enable sampling for large files

#### Slow Processing
- Use local LLM (Ollama) instead of API
- Reduce `max_tokens`
- Enable parallel processing

---

## Contributing

### Adding New Analyzers

1. **Create analyzer file**: `src/logsentinelai/analyzers/your_analyzer.py`
2. **Define Pydantic models** for structured output
3. **Create LLM prompts** in `src/logsentinelai/core/prompts.py`
4. **Add CLI entry point** in `pyproject.toml`
5. **Add tests** in `tests/`

### Submitting Changes
1. Fork the repository
2. Create feature branch
3. Make changes following style guide
4. Add tests
5. Submit pull request

---

### Data Flow

1. **Input**: Log files (local/remote)
2. **Parsing**: Extract structured data
3. **Analysis**: LLM-powered threat detection
4. **Enrichment**: GeoIP, reputation data
5. **Output**: JSON, Elasticsearch, stdout
6. **Visualization**: Kibana dashboards

---

This wiki provides comprehensive documentation for LogSentinelAI. For specific questions or issues, please:

- 📋 [Create an Issue](https://github.com/call518/LogSentinelAI/issues)
- 💬 [Join Discussions](https://github.com/call518/LogSentinelAI/discussions)
- 📧 [Email Support](mailto:call518@gmail.com)

**Happy Log Analyzing!** 🚀