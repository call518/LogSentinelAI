# LogSentinelAI — AI Log Analyzer

**Declarative LLM-Based Log Analyzer for Security Events, System Errors, and Anomalies**

> **Benefits**: Transform unstructured logs into structured security intelligence by simply defining a Pydantic model—the LLM automatically extracts and validates data without manual parsing or regex rules.

**Keywords**: `AI log analysis` • `cybersecurity automation` • `SIEM integration` • `threat detection` • `DevSecOps` • `log monitoring` • `security intelligence` • `anomaly detection`

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Deploy to PyPI with tag](https://github.com/call518/LogSentinelAI/actions/workflows/pypi-publish.yml/badge.svg)](https://github.com/call518/LogSentinelAI/actions/workflows/pypi-publish.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/call518/LogSentinelAI)
[![BuyMeACoffee](https://raw.githubusercontent.com/pachadotdev/buymeacoffee-badges/main/bmc-donate-yellow.svg)](https://www.buymeacoffee.com/call518)

LogSentinelAI is an **AI-powered cybersecurity tool** that leverages LLM with **Declarative Extraction** to analyze security events, anomalies, and errors from various logs including Apache, Linux, and converts them into structured data for **SIEM integration** with Elasticsearch/Kibana. This **DevSecOps automation solution** enables **real-time threat detection** and **security monitoring** by simply declaring your desired result structure as a Pydantic class, and the AI automatically analyzes logs to return JSON matching that schema. No complex parsing or regex rules required.

---

## Dashboard Example

![LogSentinelAI Kibana Dashboard showing security events, threat detection, and log analysis visualization](img/ex-dashboard.png)

## JSON Output Example

![Structured JSON output from LogSentinelAI showing security event analysis results](img/ex-json.png)

## Telegram Alert Example

When critical security events are detected, LogSentinelAI can automatically send real-time alerts to Telegram:

```text
🚨 [CRITICAL+ EVENTS] 🚨
  • Highest Severity: CRITICAL
  • Immediate Attention: Not Required

📊 Alert Events Summary (1 total):
  • CRITICAL: 1

📋 Summary
  ➤ The analysis indicates several potential security events in the system logs.

🔥 Event-1
  • Severity: CRITICAL
  • Event Type: AUTH_FAILURE
  • Description: Multiple authentication failures attempted against the SSH daemon.
  • Confidence: 0.9
  • Human Review: Required
  • Related Logs:
      1. Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEV...
      2. Jun 14 15:16:02 combo sshd(pam_unix)[19937]: check pass; user unknown
      3. Jun 15 02:04:59 combo sshd(pam_unix)[20882]: authentication failure; logname= uid=0 euid=0 tty=NODEV...
      ... and 5 more log entries
  • Recommended Actions:
      ➤ Review login history and account activity for suspicious patterns.
      ➤ Implement multi-factor authentication to enhance security.
      ➤ Monitor network traffic for unauthorized connections.

📊 Statistics:
  • total_events: 8
  • auth_failures: 8
  • unique_ips: 0
  • unique_users: 0

🔍 ES/Kibana Metadata:
  • Index: logsentinelai-analysis
  • @chunk_analysis_start_utc: 2025-08-17T22:42:32Z
  • @chunk_analysis_end_utc: 2025-08-17T22:43:02Z
  • @chunk_analysis_elapsed_time: 30
  • @processing_result: success
  • @log_count: 10
  • @processing_mode: batch
  • @access_mode: local
  • @llm_provider: vllm
  • @llm_model: Qwen/Qwen2.5-1.5B-Instruct
  • @log_path: /var/log/messages
  • @token_size_input: 1834
  • @token_size_output: 618
  • @timestamp: 2025-08-17T22:43:02.261161
  • @log_type: linux_system
  • @document_id: linux_system_20250817_224302_261129_chunk_1
  • @host: {"hostname":"linux.foo.com","ip_addresses":["123.123.123.123/24"]}
```

> Configure Telegram alerts by setting `TELEGRAM_ENABLED=true`, `TELEGRAM_TOKEN`, and `TELEGRAM_CHAT_ID` in your config file. Alerts are automatically sent for CRITICAL+ events (configurable via `TELEGRAM_ALERT_LEVEL`).

## Key Features

> ⚡️ **Declarative Extraction**
>
> In each analyzer script, simply declare the desired result structure as a Pydantic class, and the LLM will automatically analyze logs and return results as JSON matching that schema. No complex parsing or post-processing—just declare what you want, and the AI handles the rest. This approach enables developers to focus on "what to extract" declaratively, while the LLM takes care of "how to extract"—a modern paradigm for information extraction.

```python
# Example: Just declare the result structure you want in your HTTP Access log analyzer
from pydantic import BaseModel

class MyAccessLogResult(BaseModel):
    ip: str
    url: str
    is_attack: bool

# By defining only the result structure (Pydantic class) like above,
# the LLM automatically analyzes each log and returns JSON like this:
# {
#   "ip": "192.168.0.1",
#   "url": "/admin.php",
#   "is_attack": true
# }
```

## System Architecture

![LogSentinelAI System Architecture - AI-powered log analysis workflow with LLM integration, Elasticsearch SIEM, and real-time cybersecurity monitoring](img/system-architecture.png)

- **Log Sources**: Logs are collected from various sources, including local files, remote SSH connections, HTTP endpoints, Apache error logs, system logs, and TCPDump outputs.
- **LogSentinelAI Core**: Handles parsing and extraction using a declarative approach. Log structures are defined using Pydantic models, and the actual extraction is performed by LLMs. The system validates and structures the extracted data.
- **LLM Provider**: Integrates with external or local LLMs (e.g., OpenAI, vLLM, Ollama) to interpret and transform raw logs into structured JSON, based on user-defined schemas.
- **Elasticsearch**: Structured outputs, raw logs, and metadata are indexed into Elasticsearch for searchability and event correlation.
- **Kibana**: Provides visualization and dashboards for immediate insight into security events and operational data.
- **Telegram Alerts**: Automatically sends real-time notifications to Telegram groups/channels when CRITICAL security events are detected or processing failures occur, enabling immediate incident response.

### AI-powered Analysis

- **Declarative Extraction**: Just declare your desired result structure (Pydantic class) and the LLM analyzes logs automatically
- **LLM Providers**: OpenAI API, Ollama, vLLM
- **Supported Log Types**: HTTP Access, Apache Error, Linux System
- **Threat Detection**: SQL Injection, XSS, Brute Force, Network Anomaly Detection
- **Output**: Structured JSON validated by Pydantic
- **Just define a Pydantic class and the LLM generates results in that structure automatically**
- **Adaptive Sensitivity**: Detection sensitivity auto-adjusted by LLM model and log type prompt

### Processing Modes

- **Batch**: Bulk analysis of historical logs
- **Real-time**: Sampling-based live monitoring
- **Access Methods**: Local files, SSH remote

### Data Enrichment

- **GeoIP**: MaxMind GeoLite2 City lookup (including coordinates, Kibana geo_point support)
- **Statistics**: IP counts, response codes, various metrics
- **Multi-language Support**: Configurable result language (default: Korean)

### Integration & Output

- **Storage**: Elasticsearch (ILM policy support)
- **Visualization**: Kibana dashboard
- **Deployment**: Docker containers
- **Real-time Alerts**: Telegram notifications for CRITICAL security events and system failures

### CLI Command Mapping

```bash
# CLI commands mapped to analyzer scripts:
logsentinelai-httpd-access   → analyzers/httpd_access.py
logsentinelai-httpd-server   → analyzers/httpd_server.py  
logsentinelai-linux-system   → analyzers/linux_system.py
logsentinelai-geoip-download → utils/geoip_downloader.py
```

### Sample Log Preview

#### HTTP Access Log

```log
54.36.149.41 - - [22/Jan/2019:03:56:14 +0330] "GET /filter/27|13%20%D9%85%DA%AF%D8%A7%D9%BE%DB%8C%DA%A9%D8%B3%D9%84,27|%DA%A9%D9%85%D8%AA%D8%B1%20%D8%A7%D8%B2%205%20%D9%85%DA%AF%D8%A7%D9%BE%DB%8C%DA%A9%D8%B3%D9%84,p53 HTTP/1.1" 200 30577 "-" "Mozilla/5.0 (compatible; AhrefsBot/6.1; +http://ahrefs.com/robot/)" "-"
31.56.96.51 - - [22/Jan/2019:03:56:16 +0330] "GET /image/60844/productModel/200x200 HTTP/1.1" 200 5667 "https://www.zanbil.ir/m/filter/b113" "Mozilla/5.0 (Linux; Android 6.0; ALE-L21 Build/HuaweiALE-L21) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.158 Mobile Safari/537.36" "-"
31.56.96.51 - - [22/Jan/2019:03:56:16 +0330] "GET /image/61474/productModel/200x200 HTTP/1.1" 200 5379 "https://www.zanbil.ir/m/filter/b113" "Mozilla/5.0 (Linux; Android 6.0; ALE-L21 Build/HuaweiALE-L21) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.158 Mobile Safari/537.36" "-"
40.77.167.129 - - [22/Jan/2019:03:56:17 +0330] "GET /image/14925/productModel/100x100 HTTP/1.1" 200 1696 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "-"
91.99.72.15 - - [22/Jan/2019:03:56:17 +0330] "GET /product/31893/62100/%D8%B3%D8%B4%D9%88%D8%A7%D8%B1-%D8%AE%D8%A7%D9%86%DA%AF%DB%8C-%D9%BE%D8%B1%D9%86%D8%B3%D9%84%DB%8C-%D9%85%D8%AF%D9%84-PR257AT HTTP/1.1" 200 41483 "-" "Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0)Gecko/16.0 Firefox/16.0" "-"
40.77.167.129 - - [22/Jan/2019:03:56:17 +0330] "GET /image/23488/productModel/150x150 HTTP/1.1" 200 2654 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "-"
40.77.167.129 - - [22/Jan/2019:03:56:18 +0330] "GET /image/45437/productModel/150x150 HTTP/1.1" 200 3688 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "-"
40.77.167.129 - - [22/Jan/2019:03:56:18 +0330] "GET /image/576/article/100x100 HTTP/1.1" 200 14776 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "-"
66.249.66.194 - - [22/Jan/2019:03:56:18 +0330] "GET /filter/b41,b665,c150%7C%D8%A8%D8%AE%D8%A7%D8%B1%D9%BE%D8%B2,p56 HTTP/1.1" 200 34277 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "-"
40.77.167.129 - - [22/Jan/2019:03:56:18 +0330] "GET /image/57710/productModel/100x100 HTTP/1.1" 200 1695 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "-"
```

#### Apache Server Log

```log
[Thu Jun 09 06:07:04 2005] [notice] LDAP: Built with OpenLDAP LDAP SDK
[Thu Jun 09 06:07:04 2005] [notice] LDAP: SSL support unavailable
[Thu Jun 09 06:07:04 2005] [notice] suEXEC mechanism enabled (wrapper: /usr/sbin/suexec)
[Thu Jun 09 06:07:05 2005] [notice] Digest: generating secret for digest authentication ...
[Thu Jun 09 06:07:05 2005] [notice] Digest: done
[Thu Jun 09 06:07:05 2005] [notice] LDAP: Built with OpenLDAP LDAP SDK
[Thu Jun 09 06:07:05 2005] [notice] LDAP: SSL support unavailable
[Thu Jun 09 06:07:05 2005] [error] env.createBean2(): Factory error creating channel.jni:jni ( channel.jni, jni)
[Thu Jun 09 06:07:05 2005] [error] config.update(): Can't create channel.jni:jni
[Thu Jun 09 06:07:05 2005] [error] env.createBean2(): Factory error creating vm: ( vm, )
```

#### Linux System Log

```log
Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 
Jun 14 15:16:02 combo sshd(pam_unix)[19937]: check pass; user unknown
Jun 14 15:16:02 combo sshd(pam_unix)[19937]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 
Jun 15 02:04:59 combo sshd(pam_unix)[20882]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
Jun 15 02:04:59 combo sshd(pam_unix)[20884]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
Jun 15 02:04:59 combo sshd(pam_unix)[20883]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
Jun 15 02:04:59 combo sshd(pam_unix)[20885]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
Jun 15 02:04:59 combo sshd(pam_unix)[20886]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
Jun 15 02:04:59 combo sshd(pam_unix)[20892]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
Jun 15 02:04:59 combo sshd(pam_unix)[20893]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
```

### More Public Sample Logs

To test more log types and formats, you can leverage this public sample logs repository:

- GitHub: [Sample Log Files Repository](https://github.com/SoftManiaTech/sample_log_files)

How to use with LogSentinelAI:

- Clone and pick appropriate files for your analyzer
- Use `--log-path` to point the analyzer CLI at the chosen file

## Frequently Asked Questions (FAQ)

### Q: How does LogSentinelAI differ from traditional log analysis tools?

**A**: Unlike traditional tools that require complex regex patterns and manual parsing rules, LogSentinelAI uses **declarative extraction** - you simply define a Pydantic model structure, and the LLM automatically extracts and validates security data. No programming required for new log formats.

### Q: Can I use LogSentinelAI for compliance and audit reporting?

**A**: Yes! LogSentinelAI provides structured JSON output with full audit trails, timestamps, and confidence scores - perfect for **SOX compliance**, **PCI DSS audits**, and **security incident reporting**. All analysis results are indexed in Elasticsearch for long-term retention.

### Q: Does it work with custom or proprietary log formats?

**A**: Absolutely! The AI can adapt to any log format. Simply create a new analyzer with your desired output schema, and the LLM will learn to parse your custom logs automatically. No need to write parsing logic.

### Q: Is it suitable for high-volume enterprise environments?

**A**: Yes, LogSentinelAI supports **real-time processing**, **batch analysis**, and **sampling-based monitoring** for high-volume scenarios. It integrates with enterprise SIEM solutions via Elasticsearch and provides **horizontal scaling** capabilities.

### Q: What about data privacy and on-premises deployment?

**A**: LogSentinelAI supports **local LLM deployment** using Ollama or vLLM - your logs never leave your infrastructure. Perfect for organizations with strict **data residency** and **privacy compliance** requirements.

- Some formats may require adapting analyzer prompts/schemas

## Installation & Usage Guide

**Requirements**: Python 3.11 or 3.12 (Python 3.13+ not supported due to dependency compatibility)

For installation, environment setup, CLI usage, Elasticsearch/Kibana integration, and all practical guides for LogSentinelAI, please refer to the installation documentation below.

**[Go to Installation and Usage Guide: INSTALL-and-USAGE.md](./INSTALL-and-USAGE.md)**

> ⚡️ For additional inquiries, please use GitHub Issues/Discussions!

## Acknowledgments

We would like to express our sincere gratitude to the following projects and communities that provided inspiration, guidance, and foundational technologies for LogSentinelAI:

### Core Technologies & Frameworks

- **[Outlines](https://dottxt-ai.github.io/outlines/latest/)** - Structured LLM output generation framework that powers our reliable AI analysis
- **[dottxt-ai Demos](https://github.com/dottxt-ai/demos/tree/main/logs)** - Excellent log analysis examples and implementation patterns
- **[STRESSED - YouTube](https://www.youtube.com/watch?v=csw6TVfzBcw)** - Creating a Structured AI Log Analysis System with Python & LLMs
- **[Docker ELK Stack](https://github.com/deviantony/docker-elk)** - Comprehensive Elasticsearch, Logstash, and Kibana Docker setup

### LLM Infrastructure & Deployment

- **[vLLM](https://github.com/vllm-project/vllm)** - High-performance LLM inference engine for GPU-accelerated local deployment
- **[Ollama](https://ollama.com/)** - Simplified local LLM deployment and management platform

### Open Source Community

We are deeply grateful to the broader open source community and the countless projects that have contributed to making AI-powered log analysis accessible and practical. This project stands on the shoulders of many innovative open source initiatives that continue to push the boundaries of what's possible.

## Contributing

🤝 **Got ideas? Found bugs? Want to add cool features?**

We're always excited to welcome new contributors! Whether you're fixing a typo, adding a new monitoring tool, or improving documentation - every contribution makes this project better.

**Ways to contribute:**
- 🐛 Report issues or bugs
- 💡 Suggest new PostgreSQL monitoring features
- 📝 Improve documentation 
- 🚀 Submit pull requests
- ⭐ Star the repo if you find it useful!

## 📄 License

This project is licensed under the MIT License.