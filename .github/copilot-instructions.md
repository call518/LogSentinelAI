# Copilot Instructions for LogSentinelAI

## Project Overview
**LogSentinelAI** is a declarative, LLM-powered log analysis framework for security, anomaly, and system event detection. The core innovation is **Declarative Extraction**—define a Pydantic model in each analyzer, and the LLM returns structured JSON matching that schema automatically. No manual parsing required.

**Data flow**: Log file input → Parsing → LLM-based analysis → Enrichment (GeoIP, reputation) → Output (JSON, Elasticsearch, stdout) → Visualization (Kibana) → Telegram Alerts.

## Architecture & Key Components
- `src/logsentinelai/analyzers/`: Analyzer modules for each log type. Each follows the pattern: define Pydantic models → get prompts → call `run_generic_*_analysis()`.
- `src/logsentinelai/core/`: Core business logic:
  - `llm.py`: LLM abstraction using **Outlines** library for structured generation
  - `commons.py`: Generic batch/realtime analysis functions, argument parsing, **runtime logging configuration**  
  - `prompts.py`: Centralized prompt templates with detailed security analysis instructions
  - `config.py`: Environment-based configuration loading with **dotenv runtime loading**
  - `elasticsearch.py`: ES integration with **Telegram alert triggers**
  - `monitoring.py`: **Real-time file monitoring** with EOF tracking, rotation detection, and auto-sampling
- `src/logsentinelai/utils/`: Utility functions (general helpers, GeoIP lookup/download, **Telegram alerts**)
- `pyproject.toml`: CLI scripts mapped to analyzer entry points

## Critical Patterns & Conventions

### 1. Declarative Extraction Pattern
**Core concept**: Define result structure as Pydantic models, LLM fills the data automatically.
```python
class SecurityEvent(BaseModel):
    event_type: str
    severity: SeverityLevel
    source_ips: list[str] = Field(description="ALL IPs - NEVER empty")
    related_logs: list[str] = Field(min_length=1, description="Original log lines - at least one required")
    # LLM automatically extracts these fields from raw logs
```

### 2. LLM Integration via Outlines
- Uses **Outlines** library for reliable structured generation
- `core/llm.py` abstracts multiple providers (OpenAI, Ollama, vLLM, Gemini)
- **Gemini special handling**: Raw text → JSON validation due to API limitations with structured output
- All others use `outlines.from_openai()` with structured output
- **Error handling**: Gemini responses cleaned (removes markdown code blocks) before JSON parsing

### 3. Runtime Configuration Loading Pattern
**CRITICAL**: Environment variables must be read at **runtime**, not at module import time.
```python
# ❌ WRONG: Reads at module import (before config loaded)
LOG_FILE = os.getenv("LOG_FILE", "default.log")

# ✅ CORRECT: Reads at function runtime (after config loaded)
def setup_logger():
    log_file = os.getenv("LOG_FILE", "default.log")
```
- `commons.py`: `setup_logger()` reads environment variables at runtime
- `config.py`: Uses `load_dotenv()` to load config files before other modules read env vars
- **Config search order**: `/etc/logsentinelai.config` → `./.env` → error if none found

### 4. Analyzer Structure Pattern
Every analyzer follows this exact pattern:
```python
# 1. Define Pydantic models (SecurityEvent/LogEvent, Statistics, LogAnalysis)
# 2. Import: get_*_prompt, run_generic_*_analysis, create_argument_parser
# 3. main() function with standard argument parsing
# 4. Call run_generic_batch_analysis() or run_generic_realtime_analysis()
```

**Required Pydantic Fields**:
- `related_logs: list[str] = Field(min_length=1)` - Original log entries that triggered event
- `source_ips: list[str]` - **NEVER empty** - extract ALL IPs from logs
- `events: list[Event] = Field(min_length=1)` - **MUST NEVER BE EMPTY** - create at least INFO event if no issues

### 5. Real-time Monitoring Pattern
- **EOF tracking**: `monitoring.py` starts from current file end, processes only new logs
- **File rotation detection**: Uses inode tracking to detect log rotation/truncation  
- **Auto-sampling**: When pending lines > threshold, switches to sampling mode (keeps latest N lines)
- **Chunk timeout**: Forces processing if pending lines don't reach chunk_size within timeout
- **SSH support**: Remote file monitoring via `RemoteSSHLogMonitor`

### 6. Logging Context Pattern
- **Log type injection**: `LOG_TYPE_CTX` context variable adds analyzer type to all log messages
- **Runtime logger setup**: `setup_logger()` reads LOG_LEVEL/LOG_FILE at function call time
- **Consistent format**: `[timestamp] [level] [log_type] (module) message`

### 7. Telegram Integration Pattern
- **Auto-triggers**: CRITICAL severity events OR processing failures
- **Configuration**: `TELEGRAM_ENABLED=true`, `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`
- **Implementation**: `utils/telegram_alert.py` using `python-telegram-bot`
- **Integration point**: `core/elasticsearch.py` checks events and sends alerts

## Developer Workflows

### Adding New Analyzers
1. Create `src/logsentinelai/analyzers/new_analyzer.py`
2. Define Pydantic result models following existing patterns:
   - Include required fields: `related_logs`, `source_ips`, `events` (min_length=1)
   - Use consistent `SeverityLevel` and specific event type enums
3. Add prompt template in `core/prompts.py`
4. Register CLI entry point in `pyproject.toml`: `"logsentinelai-new-analyzer"`
5. Follow the standard analyzer pattern (see `httpd_access.py`, `linux_system.py`, `general_log.py`)

### Analyzer Development Pattern
**Critical imports and structure** (must follow exactly):
```python
# Logger setup first (with log type context)
from ..core.commons import setup_logger
logger = setup_logger("logsentinelai.analyzers.your_analyzer")

# Standard analyzer imports
from ..core.prompts import get_your_analyzer_prompt
from ..core.commons import (
    run_generic_batch_analysis, 
    run_generic_realtime_analysis,
    create_argument_parser,
    handle_ssh_arguments
)

# Define Pydantic models with EXACT required fields
class SecurityEvent(BaseModel):
    related_logs: list[str] = Field(min_length=1, description="Original log lines...")
    source_ips: list[str] = Field(description="ALL IPs - NEVER empty")
    # ... other fields

class LogAnalysis(BaseModel):
    events: list[SecurityEvent] = Field(min_length=1, description="MUST NEVER BE EMPTY")
    # ... other fields

def main():
    parser = create_argument_parser('Your Analyzer Description')
    args = parser.parse_args()
    ssh_config = handle_ssh_arguments(args)
    # Call run_generic_batch_analysis() or run_generic_realtime_analysis()
```

### Configuration System  
- **Environment-based**: Copy `.env.template` → `.env`, set LLM provider/API keys
- **Multi-provider support**: `LLM_PROVIDER={openai|ollama|vllm|gemini}`
- **Logging config**: `LOG_FILE=/var/log/logsentinelai.log`, `LOG_LEVEL=INFO`
- **Chunk-based processing**: `CHUNK_SIZE_*` controls how many log entries per LLM request
- **Real-time config**: Polling intervals, sampling thresholds, buffer times, chunk timeouts
- **Telegram alerts**: `TELEGRAM_ENABLED=true`, bot token, chat ID

### CLI Command Mapping
```bash
logsentinelai-httpd-access   → analyzers/httpd_access.py:main()
logsentinelai-httpd-server   → analyzers/httpd_server.py:main()
logsentinelai-linux-system   → analyzers/linux_system.py:main()
logsentinelai-general-log    → analyzers/general_log.py:main()
logsentinelai-geoip-download → utils/geoip_downloader.py:main()
logsentinelai-geoip-lookup   → utils/geoip_lookup.py:main()
```

### Testing & Debugging
- Use sample logs in `sample-logs/` directory
- Set `LLM_SHOW_PROMPT=true` in config to see full prompts
- CLI supports `--mode {batch|realtime}`, `--output {json|elasticsearch|stdout}`
- Remote analysis: `--ssh-host`, `--ssh-user`, `--ssh-key` options
- Real-time monitoring: `--monitor` flag with sampling control
- **Real-time testing**: Start monitor, tail log file to see live processing

### Build & Development Workflow
- **Package manager**: Uses `uv` for dependency management (not pip/poetry)
- **Build system**: `setuptools` with `pyproject.toml` configuration
- **Version injection**: GitHub Actions injects version from git tags into `pyproject.toml` and `__init__.py`
- **Development dependencies**: `pytest`, `black`, `isort`, `flake8`, `mypy` in `[project.optional-dependencies]`
- **Package data**: `.env.template` included via `MANIFEST.in` and `tool.setuptools.package-data`
- **Development setup**: `uv venv`, `uv sync`, `uv pip install -e .`
- **Local testing**: Copy `.env.template` → `.env`, set API keys, test with sample logs
- **Release workflow**: Git tag → GitHub Actions → TestPyPI → PyPI (automatic)

### Container & Infrastructure Integration  
- **Docker-based LLM deployment**: Ollama and vLLM run in containers with OpenAI-compatible APIs
- **ELK Stack integration**: Uses external Docker-ELK repository for Elasticsearch/Kibana setup  
- **External dependencies**: Requires Docker for local LLM providers and ELK stack
- **Configuration templating**: Uses `.env.template` pattern for environment-specific configuration

## Integration Points
- **LLM Providers**: OpenAI (production), Ollama/vLLM (local), Gemini (with special handling)
- **Elasticsearch**: Auto-index management, ILM policies, GeoIP enrichment via `core/elasticsearch.py`
- **Kibana**: Pre-built dashboards in `Kibana-*.ndjson` files
- **GeoIP**: MaxMind database integration for IP geolocation (coordinates, city, country)
- **Telegram**: Real-time alerts for CRITICAL events via `utils/telegram_alert.py`
- **SSH**: Remote log file access via `paramiko` with connection pooling

## Project-Specific Conventions
- **Mandatory event creation**: Analyzers MUST create at least one event per chunk (even INFO level for normal traffic)
- **IP extraction requirement**: `source_ips` field must NEVER be empty - extract ALL IPs from logs  
- **Related logs requirement**: `related_logs` field must contain exact original log entries (min_length=1)
- **Severity focus**: Use threat-focused severity (CRITICAL for active exploitation, INFO for normal traffic)
- **Confidence scores**: Float 0.0-1.0 (not percentages)
- **Real-time sampling**: Auto-switches to sampling mode when pending lines exceed threshold
- **Logger context**: Use `set_log_type()` for analyzer-specific log tagging
- **Runtime env loading**: Always read environment variables at function runtime, not module import
- **File monitoring**: Real-time mode starts from EOF, handles rotation, supports SSH

## Critical Bug Patterns to Avoid
1. **Environment Variable Loading**: Never read env vars at module import time - use runtime functions
2. **Logger Setup**: Import `setup_logger` without `LOG_LEVEL` parameter (reads runtime)
3. **Config Dependencies**: Ensure `config.py` loads before other modules try to read env vars
4. **Telegram Error Handling**: Wrap telegram imports in try/except for optional dependency
5. **Empty Events List**: Analyzers must always create at least one event (use INFO severity if needed)
6. **Empty source_ips**: Always extract and include ALL IP addresses found in log entries
7. **Missing related_logs**: Always include original log lines that triggered each event

## References
- `README.md`, `INSTALL.md`, `Wiki/Home.md` for setup and usage
- **Outlines docs**: https://dottxt-ai.github.io/outlines/latest/
- Sample public logs: https://github.com/SoftManiaTech/sample_log_files

### 4. Analyzer Structure Pattern
Every analyzer follows this exact pattern:
```python
# 1. Define Pydantic models (SecurityEvent, Statistics, LogAnalysis)
# 2. Import: get_*_prompt, run_generic_*_analysis, create_argument_parser
# 3. main() function with standard argument parsing
# 4. Call run_generic_batch_analysis() or run_generic_realtime_analysis()
```

### 5. Telegram Integration Pattern
- **Auto-triggers**: CRITICAL severity events OR processing failures
- **Configuration**: `TELEGRAM_ENABLED=true`, `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`
- **Implementation**: `utils/telegram_alert.py` using `python-telegram-bot`
- **Integration point**: `core/elasticsearch.py` checks events and sends alerts

## Developer Workflows

### Adding New Analyzers
1. Create `src/logsentinelai/analyzers/new_analyzer.py`
2. Define Pydantic result models (follow existing severity/confidence patterns)
3. Add prompt template in `core/prompts.py`
4. Register CLI entry point in `pyproject.toml`: `"logsentinelai-new-analyzer"`
5. Follow the standard analyzer pattern (see `httpd_access.py`)

### Configuration System
- **Environment-based**: Copy `.env.template` → `.env`, set LLM provider/API keys
- **Multi-provider support**: `LLM_PROVIDER={openai|ollama|vllm|gemini}`
- **Logging config**: `LOG_FILE=/var/log/logsentinelai.log`, `LOG_LEVEL=INFO`
- **Chunk-based processing**: `CHUNK_SIZE_*` controls how many log entries per LLM request
- **Real-time config**: Polling intervals, sampling thresholds, buffer times
- **Telegram alerts**: `TELEGRAM_ENABLED=true`, bot token, chat ID

### CLI Command Mapping
```bash
logsentinelai-httpd-access   → analyzers/httpd_access.py:main()
logsentinelai-httpd-server   → analyzers/httpd_server.py:main()
logsentinelai-linux-system   → analyzers/linux_system.py:main()
logsentinelai-general-log    → analyzers/general_log.py:main()
logsentinelai-geoip-download → utils/geoip_downloader.py:main()
```

### Testing & Debugging
- Use sample logs in `sample-logs/` directory
- Set `LLM_SHOW_PROMPT=true` in config to see full prompts
- CLI supports `--mode {batch|realtime}`, `--output {json|elasticsearch|stdout}`
- Remote analysis: `--ssh-host`, `--ssh-user`, `--ssh-key` options
- Real-time monitoring: `--monitor` flag with sampling control

## Integration Points
- **LLM Providers**: OpenAI (production), Ollama/vLLM (local), Gemini (with special handling)
- **Elasticsearch**: Auto-index management, ILM policies, GeoIP enrichment via `core/elasticsearch.py`
- **Kibana**: Pre-built dashboards in `Kibana-*.ndjson` files
- **GeoIP**: MaxMind database integration for IP geolocation (coordinates, city, country)
- **Telegram**: Real-time alerts for CRITICAL events via `utils/telegram_alert.py`

## Project-Specific Conventions
- **Mandatory event creation**: Analyzers MUST create at least one event per chunk (even INFO level for normal traffic)
- **IP extraction requirement**: `source_ips` field must NEVER be empty - extract ALL IPs from logs
- **Severity focus**: Use threat-focused severity (CRITICAL for active exploitation, INFO for normal traffic)
- **Confidence scores**: Float 0.0-1.0 (not percentages)
- **Real-time sampling**: Auto-switches to sampling mode when pending lines exceed threshold
- **Logger context**: Use `LOG_TYPE_CTX` for analyzer-specific log tagging
- **Runtime env loading**: Always read environment variables at function runtime, not module import

## Critical Bug Patterns to Avoid
1. **Environment Variable Loading**: Never read env vars at module import time - use runtime functions
2. **Logger Setup**: Import `setup_logger` without `LOG_LEVEL` parameter (reads runtime)
3. **Config Dependencies**: Ensure `config.py` loads before other modules try to read env vars
4. **Telegram Error Handling**: Wrap telegram imports in try/except for optional dependency

## References
- `README.md`, `INSTALL.md`, `Wiki/Home.md` for setup and usage
- **Outlines docs**: https://dottxt-ai.github.io/outlines/latest/
- Sample public logs: https://github.com/SoftManiaTech/sample_log_files
