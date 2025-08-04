"""
Configuration module for Lo# Log paths configuration
LOG_PATHS = {
    "httpd_access": os.getenv("LOG_PATH_HTTPD_ACCESS", "sample-logs/access-10k.log"),
    "httpd_apache_error": os.getenv("LOG_PATH_HTTPD_APACHE_ERROR", "sample-logs/apache-10k.log"),
    "linux_system": os.getenv("LOG_PATH_LINUX_SYSTEM", "sample-logs/linux-2k.log")
}elAI
Centralizes all configuration constants and environment variable handling
"""
import os
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv(dotenv_path="config")

# LLM Configuration
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai")
LLM_MODELS = {
    "ollama": os.getenv("LLM_MODEL_OLLAMA", "qwen2.5-coder:3b"),
    "vllm": os.getenv("LLM_MODEL_VLLM", "Qwen/Qwen2.5-1.5B-Instruct"),
    "openai": os.getenv("LLM_MODEL_OPENAI", "gpt-4o-mini"),
    "gemini": os.getenv("LLM_MODEL_GEMINI", "gemini-1.5-pro")
}
LLM_API_HOSTS = {
    "ollama": os.getenv("LLM_API_HOST_OLLAMA", "http://127.0.0.1:11434"),
    "vllm": os.getenv("LLM_API_HOST_VLLM", "http://127.0.0.1:5000/v1"),
    "openai": os.getenv("LLM_API_HOST_OPENAI", "https://api.openai.com/v1")
}
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))
LLM_TOP_P = float(os.getenv("LLM_TOP_P", "0.5"))
LLM_NO_THINK = os.getenv("LLM_NO_THINK", "false").lower() == "true"

# Common Analysis Configuration
RESPONSE_LANGUAGE = os.getenv("RESPONSE_LANGUAGE", "korean")
ANALYSIS_MODE = os.getenv("ANALYSIS_MODE", "batch")

# Log Paths Configuration
LOG_PATHS = {
    "httpd_access": os.getenv("LOG_PATH_HTTPD_ACCESS", "sample-logs/access-10k.log"),
    "httpd_apache_error": os.getenv("LOG_PATH_HTTPD_APACHE_ERROR", "sample-logs/apache-10k.log"),
    "linux_system": os.getenv("LOG_PATH_LINUX_SYSTEM", "sample-logs/linux-2k.log")
}

# Realtime log paths configuration 
LOG_PATHS_REALTIME = {
    "httpd_access": os.getenv("LOG_PATH_REALTIME_HTTPD_ACCESS", "/var/log/apache2/access.log"),
    "httpd_apache_error": os.getenv("LOG_PATH_REALTIME_HTTPD_APACHE_ERROR", "/var/log/apache2/error.log"),
    "linux_system": os.getenv("LOG_PATH_REALTIME_LINUX_SYSTEM", "/var/log/messages")
}

# Real-time Monitoring Configuration
REALTIME_CONFIG = {
    "polling_interval": int(os.getenv("REALTIME_POLLING_INTERVAL", "5")),
    "max_lines_per_batch": int(os.getenv("REALTIME_MAX_LINES_PER_BATCH", "50")),
    "position_file_dir": os.getenv("REALTIME_POSITION_FILE_DIR", ".positions"),
    "buffer_time": int(os.getenv("REALTIME_BUFFER_TIME", "2")),
    "processing_mode": os.getenv("REALTIME_PROCESSING_MODE", "full"),
    "sampling_threshold": int(os.getenv("REALTIME_SAMPLING_THRESHOLD", "100"))
}

# Default Remote SSH Configuration
DEFAULT_REMOTE_SSH_CONFIG = {
    "mode": os.getenv("REMOTE_LOG_MODE", "local"),
    "host": os.getenv("REMOTE_SSH_HOST", ""),
    "port": int(os.getenv("REMOTE_SSH_PORT", "22")),
    "user": os.getenv("REMOTE_SSH_USER", ""),
    "key_path": os.getenv("REMOTE_SSH_KEY_PATH", ""),
    "password": os.getenv("REMOTE_SSH_PASSWORD", ""),
    "timeout": int(os.getenv("REMOTE_SSH_TIMEOUT", "10"))
}

# Remote SSH configuration for log paths
DEFAULT_REMOTE_LOG_PATHS = {
    "httpd_access": os.getenv("REMOTE_LOG_PATH_HTTPD_ACCESS", "/var/log/apache2/access.log"),
    "httpd_apache_error": os.getenv("REMOTE_LOG_PATH_HTTPD_APACHE_ERROR", "/var/log/apache2/error.log"),
    "linux_system": os.getenv("REMOTE_LOG_PATH_LINUX_SYSTEM", "/var/log/messages")
}

# Default Chunk Sizes
LOG_CHUNK_SIZES = {
    "httpd_access": int(os.getenv("CHUNK_SIZE_HTTPD_ACCESS", "10")),
    "httpd_apache_error": int(os.getenv("CHUNK_SIZE_HTTPD_APACHE_ERROR", "10")),
    "linux_system": int(os.getenv("CHUNK_SIZE_LINUX_SYSTEM", "10"))
}

# GeoIP Configuration
GEOIP_CONFIG = {
    "enabled": os.getenv("GEOIP_ENABLED", "true").lower() == "true",
    "database_path": os.getenv("GEOIP_DATABASE_PATH", "~/.logsentinelai/GeoLite2-City.mmdb"),
    "fallback_country": os.getenv("GEOIP_FALLBACK_COUNTRY", "Unknown"),
    "cache_size": int(os.getenv("GEOIP_CACHE_SIZE", "1000")),
    "include_private_ips": os.getenv("GEOIP_INCLUDE_PRIVATE_IPS", "false").lower() == "true"
}

# Elasticsearch Configuration
ELASTICSEARCH_HOST = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")
ELASTICSEARCH_USER = os.getenv("ELASTICSEARCH_USER", "elastic")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "changeme")
ELASTICSEARCH_INDEX = os.getenv("ELASTICSEARCH_INDEX", "logsentinelai-analysis")

def get_analysis_config(log_type, chunk_size=None, analysis_mode=None, 
                       remote_mode=None, ssh_config=None, remote_log_path=None):
    """
    Get analysis configuration for specific log type
    
    Args:
        log_type: Log type ("httpd_access", "httpd_apache_error", "linux_system")
        chunk_size: Override chunk size (optional)
        analysis_mode: Override analysis mode (optional) - "batch" or "realtime"
        remote_mode: Override remote mode (optional) - "local" or "ssh" 
        ssh_config: Custom SSH configuration dict (optional)
        remote_log_path: Custom remote log path (optional)
    
    Returns:
        dict: Configuration containing log_path, chunk_size, response_language, analysis_mode, ssh_config
    """
    mode = analysis_mode if analysis_mode is not None else ANALYSIS_MODE
    access_mode = remote_mode if remote_mode is not None else DEFAULT_REMOTE_SSH_CONFIG["mode"]
    
    # Get log path based on access mode
    if access_mode == "ssh":
        log_path = remote_log_path or DEFAULT_REMOTE_LOG_PATHS.get(log_type, "")
    else:
        log_path = LOG_PATHS_REALTIME.get(log_type, "") if mode == "realtime" else LOG_PATHS.get(log_type, "")
    
    # SSH configuration
    if access_mode == "ssh":
        final_ssh_config = {**DEFAULT_REMOTE_SSH_CONFIG, **(ssh_config or {}), "mode": "ssh"}
    else:
        final_ssh_config = {"mode": "local"}
    
    return {
        "log_path": log_path,
        "chunk_size": chunk_size if chunk_size is not None else LOG_CHUNK_SIZES.get(log_type, 3),
        "response_language": RESPONSE_LANGUAGE,
        "analysis_mode": mode,
        "access_mode": access_mode,
        "ssh_config": final_ssh_config,
        "realtime_config": REALTIME_CONFIG if mode == "realtime" else None
    }

def get_llm_config(llm_provider=None):
    """
    Get LLM configuration for specific provider
    
    Args:
        llm_provider: LLM provider name (optional, defaults to global LLM_PROVIDER)
    
    Returns:
        dict: Configuration containing provider, model, api_host, temperature, top_p, no_think
    """
    provider = llm_provider if llm_provider is not None else LLM_PROVIDER
    
    return {
        "provider": provider,
        "model": LLM_MODELS.get(provider, "unknown"),
        "api_host": LLM_API_HOSTS.get(provider, ""),
        "temperature": LLM_TEMPERATURE,
        "top_p": LLM_TOP_P,
        "no_think": LLM_NO_THINK
    }
