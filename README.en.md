[![Deploy to PyPI with tag](https://github.com/call518/LogSentinelAI/actions/workflows/pypi-publish.yml/badge.svg)](https://github.com/call518/LogSentinelAI/actions/workflows/pypi-publish.yml)

# LogSentinelAI - AI-Powered Log Analyzer

LogSentinelAI leverages LLM to analyze security events, anomalies, and errors from various logs including Apache, Linux, and converts them into structured data that can be visualized with Elasticsearch/Kibana.

## 🚀 Key Features

### AI-Based Analysis
- **LLM Providers**: OpenAI API, Ollama, vLLM
- **Supported Log Types**: HTTP Access, Apache Error, Linux System, TCPDump
- **Threat Detection**: SQL Injection, XSS, Brute Force, Network Anomaly Detection
- **Output**: Structured JSON with Pydantic validation
- **Adaptive Sensitivity**: Automatic detection sensitivity adjustment based on LLM models and log type-specific prompts

### Processing Modes
- **Batch**: Bulk analysis of historical logs
- **Real-time**: Sampling-based live monitoring
- **Access Methods**: Local files, SSH remote

### Data Enrichment
- **GeoIP**: MaxMind GeoLite2 City lookup (including coordinates, Kibana geo_point support)
- **Statistics**: IP counts, response codes, various metrics
- **Multi-language Support**: Configurable result language (default: Korean)

### Enterprise Integration
- **Storage**: Elasticsearch (ILM policy support)
- **Visualization**: Kibana dashboard
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
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │ LLM Provider    │    │     Kibana      │
                       │                 │    │   Dashboard     │
                       │ • OpenAI        │    │                 │
                       │ • Ollama        │    │ • Visualization │
                       │ • vLLM          │    │ • Alerts        │
                       │                 │    │ • Analytics     │
                       │                 │    │ • Geo-Map       │
                       └─────────────────┘    └─────────────────┘
```

## 📁 Project Structure and Main Python Scripts

### Core Python Components

```
src/logsentinelai/
├── __init__.py                    # Package initialization
├── cli.py                         # Main CLI entry point and command routing
├── py.typed                       # mypy type hint marker
│
├── analyzers/                     # Log type-specific analyzers
│   ├── __init__.py                # Analyzer package initialization
│   ├── httpd_access.py            # HTTP access log analyzer (Apache/Nginx)
│   ├── httpd_apache.py            # Apache error log analyzer
│   ├── linux_system.py            # Linux system log analyzer (syslog/messages)
│   └── tcpdump_packet.py          # Network packet capture analyzer
│
├── core/                          # Core analysis engine (modularized)
│   ├── __init__.py                # Core package initialization and integrated import
│   ├── commons.py                 # Batch/real-time analysis common functions, processing flow definition
│   ├── config.py                  # Environment variable-based configuration management
│   ├── llm.py                     # LLM model initialization and interaction
│   ├── elasticsearch.py           # Elasticsearch integration and data transmission
│   ├── geoip.py                   # GeoIP lookup and IP enrichment
│   ├── ssh.py                     # SSH remote log access
│   ├── monitoring.py              # Real-time log monitoring and processing
│   ├── utils.py                   # Log processing utilities and helpers
│   └── prompts.py                 # Log type-specific LLM prompt templates
│
└── utils/                         # Utility functions
    ├── __init__.py                # Utils package initialization
    └── geoip_downloader.py        # MaxMind GeoIP DB downloader
```

### CLI Command Mapping

```bash
# CLI commands are mapped to analyzer scripts:
logsentinelai-httpd-access   → analyzers/httpd_access.py
logsentinelai-apache-error   → analyzers/httpd_apache.py  
logsentinelai-linux-system   → analyzers/linux_system.py
logsentinelai-tcpdump        → analyzers/tcpdump_packet.py
logsentinelai-geoip-download → utils/geoip_downloader.py
```


## 🚀 Installation Guide

For installation, environment setup, CLI usage, Elasticsearch/Kibana integration, and all practical guides for LogSentinelAI, please refer to the installation documentation below.

📖 **[Go to Installation and Usage Guide: INSTALL.en.md](./INSTALL.en.md)**

> ⚡️ For additional inquiries, please use GitHub Issues/Discussions!
