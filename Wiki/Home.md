
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
- [API Reference](#api-reference)
- [Architecture](#architecture)

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
logsentinelai-httpd-apache /var/log/apache2/error.log
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

### Setup Elasticsearch

#### Docker Setup
```bash
# Start Elasticsearch
docker run -d \
  --name elasticsearch \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  elasticsearch:8.11.0
```

#### Configuration
```toml
[elasticsearch]
enabled = true
host = "localhost"
port = 9200
index_prefix = "logsentinelai"
use_ssl = false
verify_certs = false
```

### Index Templates

LogSentinelAI automatically creates optimized index templates for:
- **Security Events**: `logsentinelai-security-*`
- **Raw Logs**: `logsentinelai-logs-*`
- **Metadata**: `logsentinelai-metadata-*`

### Index Lifecycle Management (ILM)

Default ILM policy:
- **Hot Phase**: 7 days
- **Warm Phase**: 30 days
- **Cold Phase**: 90 days
- **Delete**: 365 days

---

## Kibana Dashboard Setup

### Import Dashboard

1. **Download Dashboard**
   - Get `Kibana-9.0.3-Dashboard-LogSentinelAI.ndjson` from repository

2. **Import in Kibana**
   - Go to Stack Management → Saved Objects
   - Click "Import"
   - Select the `.ndjson` file

3. **Configure Index Patterns**
   - Go to Stack Management → Index Patterns
   - Create pattern: `logsentinelai-*`

### Dashboard Features

- **Security Overview**: Real-time threat detection
- **Geographic Analysis**: Attack origin mapping
- **Timeline Analysis**: Event chronology
- **Top Attackers**: Most active threat sources
- **Attack Types**: Categorized threat analysis

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

### Monitor Mode
```bash
# Monitor Apache logs in real-time
logsentinelai-httpd-access /var/log/apache2/access.log --monitor

# With sampling (analyze every 100th entry)
logsentinelai-httpd-access /var/log/apache2/access.log --monitor --sample-rate 100
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

#### logsentinelai-httpd-apache
```bash
logsentinelai-httpd-apache [OPTIONS] LOG_FILE
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

```toml
[llm]
# LLM Provider Configuration
provider = "openai"           # openai, ollama, vllm
model = "gpt-4o-mini"        # Model name
api_key = ""                 # API key (OpenAI only)
base_url = ""                # Base URL (Ollama/vLLM)
timeout = 30                 # Request timeout (seconds)
max_retries = 3              # Maximum retry attempts

[elasticsearch]
# Elasticsearch Configuration
enabled = true               # Enable Elasticsearch output
host = "localhost"           # Elasticsearch host
port = 9200                  # Elasticsearch port
index_prefix = "logsentinelai"  # Index prefix
use_ssl = false              # Use SSL connection
verify_certs = true          # Verify SSL certificates
username = ""                # Authentication username
password = ""                # Authentication password

[geoip]
# GeoIP Configuration
enabled = true               # Enable GeoIP lookups
database_path = "~/.logsentinelai/GeoLite2-City.mmdb"  # City database includes coordinates
fallback_country = "Unknown" # Fallback for unknown IPs
cache_size = 1000           # Cache size for performance
include_private_ips = false # Include private IPs in processing

[analysis]
# Analysis Configuration
language = "english"         # Output language
max_tokens = 4000           # Maximum tokens per request
temperature = 0.1           # LLM temperature (creativity)
batch_size = 50             # Batch processing size
enable_cache = true         # Enable result caching

[ssh]
# SSH Configuration
enabled = false             # Enable SSH functionality
default_host = ""           # Default SSH host
default_user = ""           # Default SSH user
default_key = "~/.ssh/id_rsa"  # Default SSH key

[logging]
# Logging Configuration
level = "INFO"              # Log level (DEBUG, INFO, WARNING, ERROR)
format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
file = ""                   # Log file path (empty = stdout)
```

---

## Output Format

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

### Security Event Fields

| Field | Type | Description |
|-------|------|-------------|
| `threat_detected` | boolean | Whether a threat was detected |
| `threat_type` | string | Type of threat (sql_injection, xss, brute_force, etc.) |
| `severity` | string | Severity level (low, medium, high, critical) |
| `confidence` | float | Confidence score (0.0-1.0) |
| `description` | string | Human-readable description |
| `recommendations` | array | Recommended actions |

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

### Debug Mode

Enable debug logging:
```toml
[logging]
level = "DEBUG"
```

Or use command line:
```bash
logsentinelai-httpd-access --verbose /var/log/apache2/access.log
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

### Development Setup
```bash
# Clone repository
git clone https://github.com/call518/LogSentinelAI.git
cd LogSentinelAI

# Install development dependencies
uv sync

# Setup pre-commit hooks
pre-commit install
```

### Code Style
```bash
# Format code
black src/
isort src/

# Type checking
mypy src/

# Linting
flake8 src/
```

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

## API Reference

### Core Classes

#### `LogAnalyzer`
```python
from logsentinelai.core.commons import LogAnalyzer

analyzer = LogAnalyzer(config_path="config")
results = analyzer.analyze_file("access.log", log_type="httpd_access")
```

#### `ElasticsearchClient`
```python
from logsentinelai.core.elasticsearch import ElasticsearchClient

es_client = ElasticsearchClient(config)
es_client.index_security_event(event_data)
```

#### `GeoIPLookup`
```python
from logsentinelai.core.geoip import GeoIPLookup

geoip = GeoIPLookup()
# Get comprehensive location data including coordinates
location = geoip.lookup_geoip("8.8.8.8")
# Returns: {"ip": "8.8.8.8", "country_code": "US", "country_name": "United States", 
#           "city": "Mountain View", "latitude": 37.406, "longitude": -122.078}

# Legacy method for backward compatibility (country only)
country = geoip.lookup_country("8.8.8.8")
```

### Custom Analysis

```python
from logsentinelai.analyzers.httpd_access import analyze_httpd_access_logs

# Analyze logs programmatically
results = analyze_httpd_access_logs(
    log_file="access.log",
    output_format="json",
    config_path="config"
)

for result in results:
    if result.analysis.threat_detected:
        print(f"Threat detected: {result.analysis.description}")
```

---

## Architecture

### System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Log Sources   │───▶│ LogSentinelAI   │───▶│ Elasticsearch   │
│                 │    │                 │    │                 │
│ • Local Files   │    │ ┌─────────────┐ │    │ • Security      │
│ • Remote SSH    │    │ │ Log Parser  │ │    │   Events        │
│ • Real-time     │    │ └─────────────┘ │    │ • Raw Logs      │
│                 │    │ ┌─────────────┐ │    │ • Metadata      │
│                 │    │ │ LLM         │ │    │                 │
│                 │    │ │ Analysis    │ │    │                 │
│                 │    │ └─────────────┘ │    │                 │
│                 │    │ ┌─────────────┐ │    │                 │
│                 │    │ │ GeoIP       │ │    │                 │
│                 │    │ │ Enrichment  │ │    │                 │
│                 │    │ └─────────────┘ │    │                 │
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

### Code Structure

```
src/logsentinelai/
├── analyzers/              # Log type-specific analyzers
│   ├── httpd_access.py     # Apache/Nginx access logs
│   ├── httpd_apache.py     # Apache error logs
│   └── linux_system.py    # Linux system logs
├── core/                   # Core functionality
│   ├── commons.py          # Common analysis functions
│   ├── config.py           # Configuration management
│   ├── elasticsearch.py    # Elasticsearch integration
│   ├── geoip.py           # GeoIP functionality
│   ├── llm.py             # LLM provider interface
│   ├── monitoring.py       # Real-time monitoring
│   ├── prompts.py         # LLM prompt templates
│   ├── ssh.py             # SSH remote access
│   └── utils.py           # Utility functions
├── utils/                  # Additional utilities
│   └── geoip_downloader.py # GeoIP database management
└── cli.py                 # Command-line interface
```

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