"""LogSentinelAI configuration loader.

This module loads configuration files from the following locations in order:
1) /etc/logsentinelai.config (system-wide config)
2) ./config (local config)

If neither file exists, the application will exit with an error.
"""

from __future__ import annotations

import os
import logging
from dotenv import load_dotenv
import sys

# Attempt to import setup_logger from commons (avoid circular import issues)
try:  # pragma: no cover - 보호적 로드
    from .commons import setup_logger  # type: ignore
except Exception:  # 초기 로드 단계에서 commons 미준비 가능
    def setup_logger(name, level=None):  # minimal placeholder
        log_level = level or os.getenv("LOG_LEVEL", "INFO")
        logging.basicConfig(level=getattr(logging, log_level.upper(), logging.INFO))
        return logging.getLogger(name)

logger = setup_logger(__name__)

# Global state (updated on reload)
CONFIG_FILE_PATH: str | None = None

# Public configuration values (reassigned on reload)
LLM_PROVIDER: str = "openai"
LLM_MODELS: dict[str, str] = {}
LLM_API_HOSTS: dict[str, str] = {}
LLM_TEMPERATURE: float = 0.1
LLM_TOP_P: float = 0.5
LLM_MAX_TOKENS: int = 2048
RESPONSE_LANGUAGE: str = "korean"
ANALYSIS_MODE: str = "batch"
LOG_PATHS: dict[str, str] = {}
REALTIME_CONFIG: dict[str, object] = {}
DEFAULT_REMOTE_SSH_CONFIG: dict[str, object] = {}
LOG_CHUNK_SIZES: dict[str, int] = {}
GEOIP_CONFIG: dict[str, object] = {}
ELASTICSEARCH_HOST: str = "http://localhost:9200"
ELASTICSEARCH_USER: str = "elastic"
ELASTICSEARCH_PASSWORD: str = "changeme"
ELASTICSEARCH_INDEX: str = "logsentinelai-analysis"
TELEGRAM_ENABLED: bool = True
TELEGRAM_TOKEN: str = ""
TELEGRAM_CHAT_ID: str = ""
TELEGRAM_ALERT_LEVEL: str = "CRITICAL"


def _load_values() -> None:
    """Load all global configuration values from environment variables into module globals."""
    global LLM_PROVIDER, LLM_MODELS, LLM_API_HOSTS, LLM_TEMPERATURE, LLM_TOP_P, LLM_MAX_TOKENS
    global RESPONSE_LANGUAGE, ANALYSIS_MODE, LOG_PATHS, REALTIME_CONFIG, DEFAULT_REMOTE_SSH_CONFIG
    global LOG_CHUNK_SIZES, GEOIP_CONFIG, ELASTICSEARCH_HOST, ELASTICSEARCH_USER
    global ELASTICSEARCH_PASSWORD, ELASTICSEARCH_INDEX, TELEGRAM_ENABLED, TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_ALERT_LEVEL
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai")
    LLM_MODELS = {
        "ollama": os.getenv("LLM_MODEL_OLLAMA", "qwen2.5-coder:3b"),
        "vllm": os.getenv("LLM_MODEL_VLLM", "Qwen/Qwen2.5-1.5B-Instruct"),
        "openai": os.getenv("LLM_MODEL_OPENAI", "gpt-4o-mini"),
        "gemini": os.getenv("LLM_MODEL_GEMINI", "gemini-1.5-pro")
    }
    LLM_API_HOSTS = {
        "ollama": os.getenv("LLM_API_HOST_OLLAMA", "http://127.0.0.1:11434/v1"),
        "vllm": os.getenv("LLM_API_HOST_VLLM", "http://127.0.0.1:5000/v1"),
        "openai": os.getenv("LLM_API_HOST_OPENAI", "https://api.openai.com/v1"),
        "gemini": os.getenv("LLM_API_HOST_GEMINI", "https://generativelanguage.googleapis.com/v1beta/openai/")
    }
    try:
        LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))
        LLM_TOP_P = float(os.getenv("LLM_TOP_P", "0.5"))
        LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "2048"))
    except ValueError:
        logger.warning("Invalid numeric LLM parameter detected; using defaults")
        LLM_TEMPERATURE, LLM_TOP_P, LLM_MAX_TOKENS = 0.1, 0.5, 2048

    RESPONSE_LANGUAGE = os.getenv("RESPONSE_LANGUAGE", "korean")
    ANALYSIS_MODE = os.getenv("ANALYSIS_MODE", "batch")
    LOG_PATHS = {
        "httpd_access": os.getenv("LOG_PATH_HTTPD_ACCESS", "sample-logs/access-10k.log"),
        "httpd_server": os.getenv("LOG_PATH_HTTPD_SERVER", "sample-logs/apache-10k.log"),
        "linux_system": os.getenv("LOG_PATH_LINUX_SYSTEM", "sample-logs/linux-2k.log"),
        "general_log": os.getenv("LOG_PATH_GENERAL_LOG", "sample-logs/general.log")
    }
    REALTIME_CONFIG = {
        "polling_interval": int(os.getenv("REALTIME_POLLING_INTERVAL", "5")),
        "max_lines_per_batch": int(os.getenv("REALTIME_MAX_LINES_PER_BATCH", "50")),
        "buffer_time": int(os.getenv("REALTIME_BUFFER_TIME", "2")),
        "only_sampling_mode": os.getenv("REALTIME_ONLY_SAMPLING_MODE", "false").lower() == "true",
        "sampling_threshold": int(os.getenv("REALTIME_SAMPLING_THRESHOLD", "100")),
        "chunk_pending_timeout": int(os.getenv("REALTIME_CHUNK_PENDING_TIMEOUT", "1800"))
    }
    DEFAULT_REMOTE_SSH_CONFIG = {
        "mode": os.getenv("REMOTE_LOG_MODE", "local"),
        "host": os.getenv("REMOTE_SSH_HOST", ""),
        "port": int(os.getenv("REMOTE_SSH_PORT", "22")),
        "user": os.getenv("REMOTE_SSH_USER", ""),
        "key_path": os.getenv("REMOTE_SSH_KEY_PATH", ""),
        "password": os.getenv("REMOTE_SSH_PASSWORD", ""),
        "timeout": int(os.getenv("REMOTE_SSH_TIMEOUT", "10"))
    }
    LOG_CHUNK_SIZES = {
        "httpd_access": int(os.getenv("CHUNK_SIZE_HTTPD_ACCESS", "10")),
        "httpd_server": int(os.getenv("CHUNK_SIZE_HTTPD_SERVER", "10")),
        "linux_system": int(os.getenv("CHUNK_SIZE_LINUX_SYSTEM", "10")),
        "general_log": int(os.getenv("CHUNK_SIZE_GENERAL_LOG", "10"))
    }
    GEOIP_CONFIG = {
        "enabled": os.getenv("GEOIP_ENABLED", "true").lower() == "true",
        "database_path": os.getenv("GEOIP_DATABASE_PATH", "~/.logsentinelai/GeoLite2-City.mmdb"),
        "fallback_country": os.getenv("GEOIP_FALLBACK_COUNTRY", "Unknown"),
        "cache_size": int(os.getenv("GEOIP_CACHE_SIZE", "1000")),
        "include_private_ips": os.getenv("GEOIP_INCLUDE_PRIVATE_IPS", "false").lower() == "true"
    }
    ELASTICSEARCH_HOST = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")
    ELASTICSEARCH_USER = os.getenv("ELASTICSEARCH_USER", "elastic")
    ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "changeme")
    ELASTICSEARCH_INDEX = os.getenv("ELASTICSEARCH_INDEX", "logsentinelai-analysis")
    
    # Telegram Configuration
    TELEGRAM_ENABLED = os.getenv("TELEGRAM_ENABLED", "true").lower() == "true"
    TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
    TELEGRAM_ALERT_LEVEL = os.getenv("TELEGRAM_ALERT_LEVEL", "CRITICAL").upper()

    logger.info(f"Configuration loaded (config_file={CONFIG_FILE_PATH})")


def apply_config() -> None:
    """Apply (load) the configuration file and rebuild global settings.
    
    Searches for configuration files in this order:
    1. /etc/logsentinelai.config
    2. ./config
    """
    global CONFIG_FILE_PATH
    
    # Search for configuration file in priority order
    if os.path.isfile("/etc/logsentinelai.config"):
        CONFIG_FILE_PATH = "/etc/logsentinelai.config"
        logger.info("[config] (1/2) Found config file: /etc/logsentinelai.config")
    else:
        logger.info("[config] (1/2) Not found: /etc/logsentinelai.config")
        if os.path.isfile("./config"):
            CONFIG_FILE_PATH = "./config"
            logger.info("[config] (2/2) Found config file: ./config")
        else:
            logger.info("[config] (2/2) Not found: ./config")
    
    # Check if any config file was found
    if not CONFIG_FILE_PATH:
        
        guidance = """
❌ No configuration file detected
🔎 Searched: /etc/logsentinelai.config, ./config

📄 A config file is REQUIRED.
✅ Quick fix:
  1) Copy the provided template:  cp config.template ./config
  2) Edit the file (add API keys, paths, etc.)
  3) Place it at /etc/logsentinelai.config for global use or ./config for local use.

📘 See INSTALL guide (section: Prepare Config File) for details.
"""
        logger.error(guidance)
        print(guidance, file=sys.stderr)
        sys.exit(1)
    
    logger.info(f"[config] Selected config file: {CONFIG_FILE_PATH}")
    
    try:
        load_dotenv(dotenv_path=CONFIG_FILE_PATH, override=True)
    except Exception as exc:
        logger.error(f"Failed loading config file {CONFIG_FILE_PATH}: {exc}")
        print(f"ERROR: Failed loading config file {CONFIG_FILE_PATH}: {exc}", file=sys.stderr)
        sys.exit(1)
    _load_values()


# Initial load when module is imported
apply_config()

def get_config_file_path() -> str | None:
    """Return the resolved configuration file path currently in use."""
    return CONFIG_FILE_PATH

def get_analysis_config(log_type, chunk_size=None, analysis_mode=None, 
                       remote_mode=None, ssh_config=None, remote_log_path=None):
    """
    Get analysis configuration for specific log type
    
    Args:
        log_type: Log type ("httpd_access", "httpd_server", "linux_system")
        chunk_size: Override chunk size (optional)
        analysis_mode: Override analysis mode (optional) - "batch" or "realtime"
        remote_mode: Override remote mode (optional) - "local" or "ssh" 
        ssh_config: Custom SSH configuration dict (optional)
        remote_log_path: Custom remote log path (optional)
    
    Returns:
        dict: Configuration containing log_path, chunk_size, response_language, analysis_mode, ssh_config
    """
    logger.info(f"Getting analysis configuration for log_type: {log_type}")
    
    mode = analysis_mode if analysis_mode is not None else ANALYSIS_MODE
    access_mode = remote_mode if remote_mode is not None else DEFAULT_REMOTE_SSH_CONFIG["mode"]
    
    logger.debug(f"Configuration parameters - mode: {mode}, access_mode: {access_mode}")
    
    # Get log path - use simple LOG_PATHS for all cases
    if access_mode == "ssh":
        log_path = remote_log_path or LOG_PATHS.get(log_type, "")
        logger.info(f"SSH mode: using log path: {log_path}")
    else:
        log_path = LOG_PATHS.get(log_type, "")
        logger.info(f"Local mode: using log path: {log_path}")
    
    # SSH configuration
    if access_mode == "ssh":
        final_ssh_config = {**DEFAULT_REMOTE_SSH_CONFIG, **(ssh_config or {}), "mode": "ssh"}
        logger.info(f"SSH configuration prepared: {final_ssh_config}")
    else:
        final_ssh_config = {"mode": "local"}
        logger.debug("Local mode configuration prepared")
    
    final_chunk_size = chunk_size if chunk_size is not None else LOG_CHUNK_SIZES.get(log_type, 3)
    logger.info(f"Final configuration - chunk_size: {final_chunk_size}, response_language: {RESPONSE_LANGUAGE}")
    
    config = {
        "log_path": log_path,
        "chunk_size": final_chunk_size,
        "response_language": RESPONSE_LANGUAGE,
        "analysis_mode": mode,
        "access_mode": access_mode,
        "ssh_config": final_ssh_config,
        "realtime_config": REALTIME_CONFIG if mode == "realtime" else None
    }
    
    logger.info("Analysis configuration prepared successfully")
    return config