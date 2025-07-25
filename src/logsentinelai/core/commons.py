import json
import datetime
import os
import time
import hashlib
import re
import ipaddress
from typing import Dict, Any, Optional, List, Generator
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, RequestError
from dotenv import load_dotenv
import outlines
import ollama
import openai

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# .env 파일 로드
load_dotenv(dotenv_path="config")

# LLM Configuration - Read from config file
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai")

# LLM Models Mapping - Read from config file
LLM_MODELS = {
    "ollama": os.getenv("LLM_MODEL_OLLAMA", "qwen2.5-coder:3b"),
    "vllm": os.getenv("LLM_MODEL_VLLM", "Qwen/Qwen2.5-1.5B-Instruct"),
    "openai": os.getenv("LLM_MODEL_OPENAI", "gpt-4o-mini")
}

# LLM Generation Parameters - Read from config file
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))
LLM_TOP_P = float(os.getenv("LLM_TOP_P", "0.5"))

# Common Analysis Configuration - Read from config file
RESPONSE_LANGUAGE = os.getenv("RESPONSE_LANGUAGE", "korean")
ANALYSIS_MODE = os.getenv("ANALYSIS_MODE", "batch")

# Log Paths Configuration - Read from config file
LOG_PATHS = {
    "httpd_access": os.getenv("LOG_PATH_HTTPD_ACCESS", "sample-logs/access-10k.log"),
    "httpd_apache_error": os.getenv("LOG_PATH_HTTPD_APACHE_ERROR", "sample-logs/apache-10k.log"),
    "linux_system": os.getenv("LOG_PATH_LINUX_SYSTEM", "sample-logs/linux-2k.log"),
    "tcpdump_packet": os.getenv("LOG_PATH_TCPDUMP_PACKET", "sample-logs/tcpdump-packet-2k.log")
}

# Real-time Log Paths Configuration
REALTIME_LOG_PATHS = {
    "httpd_access": os.getenv("LOG_PATH_REALTIME_HTTPD_ACCESS", "/var/log/apache2/access.log"),
    "httpd_apache_error": os.getenv("LOG_PATH_REALTIME_HTTPD_APACHE_ERROR", "/var/log/apache2/error.log"),
    "linux_system": os.getenv("LOG_PATH_REALTIME_LINUX_SYSTEM", "/var/log/messages"),
    "tcpdump_packet": os.getenv("LOG_PATH_REALTIME_TCPDUMP_PACKET", "/var/log/tcpdump.log")
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

# Default Remote SSH Configuration (can be overridden per script)
DEFAULT_REMOTE_SSH_CONFIG = {
    "mode": os.getenv("REMOTE_LOG_MODE", "local"),
    "host": os.getenv("REMOTE_SSH_HOST", ""),
    "port": int(os.getenv("REMOTE_SSH_PORT", "22")),
    "user": os.getenv("REMOTE_SSH_USER", ""),
    "key_path": os.getenv("REMOTE_SSH_KEY_PATH", ""),
    "password": os.getenv("REMOTE_SSH_PASSWORD", ""),
    "timeout": int(os.getenv("REMOTE_SSH_TIMEOUT", "10"))
}

# Default Remote Log Paths Configuration (can be overridden per script)
DEFAULT_REMOTE_LOG_PATHS = {
    "httpd_access": os.getenv("REMOTE_LOG_PATH_HTTPD_ACCESS", "/var/log/apache2/access.log"),
    "httpd_apache_error": os.getenv("REMOTE_LOG_PATH_HTTPD_APACHE_ERROR", "/var/log/apache2/error.log"),
    "linux_system": os.getenv("REMOTE_LOG_PATH_LINUX_SYSTEM", "/var/log/messages"),
    "tcpdump_packet": os.getenv("REMOTE_LOG_PATH_TCPDUMP_PACKET", "/var/log/tcpdump.log")
}

# Default Chunk Sizes - Read from config file (can be overridden by individual analysis scripts)
LOG_CHUNK_SIZES = {
    "httpd_access": int(os.getenv("CHUNK_SIZE_HTTPD_ACCESS", "10")),
    "httpd_apache_error": int(os.getenv("CHUNK_SIZE_HTTPD_APACHE_ERROR", "10")),
    "linux_system": int(os.getenv("CHUNK_SIZE_LINUX_SYSTEM", "10")),
    "tcpdump_packet": int(os.getenv("CHUNK_SIZE_TCPDUMP_PACKET", "5"))
}

# GeoIP Configuration - Read from config file
GEOIP_CONFIG = {
    "enabled": os.getenv("GEOIP_ENABLED", "true").lower() == "true",
    "database_path": os.getenv("GEOIP_DATABASE_PATH", "~/.logsentinelai/GeoLite2-Country.mmdb"),
    "fallback_country": os.getenv("GEOIP_FALLBACK_COUNTRY", "Unknown"),
    "cache_size": int(os.getenv("GEOIP_CACHE_SIZE", "1000")),
    "include_private_ips": os.getenv("GEOIP_INCLUDE_PRIVATE_IPS", "false").lower() == "true"
}

def get_analysis_config(log_type, chunk_size=None, analysis_mode=None, 
                       remote_mode=None, ssh_config=None, remote_log_path=None):
    """
    Get analysis configuration for specific log type
    
    Args:
        log_type: Log type ("httpd_access", "httpd_apache_error", "linux_system", "tcpdump_packet")
        chunk_size: Override chunk size (optional)
        analysis_mode: Override analysis mode (optional) - "batch" or "realtime"
        remote_mode: Override remote mode (optional) - "local" or "ssh" 
        ssh_config: Custom SSH configuration dict (optional)
        remote_log_path: Custom remote log path (optional)
    
    Returns:
        dict: Configuration containing log_path, chunk_size, response_language, analysis_mode, ssh_config
    """
    mode = analysis_mode if analysis_mode is not None else ANALYSIS_MODE
    
    # Determine access mode (local or ssh)
    access_mode = remote_mode if remote_mode is not None else DEFAULT_REMOTE_SSH_CONFIG["mode"]
    
    # Get log path based on access mode
    if access_mode == "ssh":
        if remote_log_path:
            log_path = remote_log_path
        else:
            log_path = DEFAULT_REMOTE_LOG_PATHS.get(log_type, "")
    else:
        # Local mode
        if mode == "realtime":
            log_path = REALTIME_LOG_PATHS.get(log_type, "")
        else:
            log_path = LOG_PATHS.get(log_type, "")
    
    # SSH configuration (only relevant for ssh mode)
    if access_mode == "ssh":
        if ssh_config:
            # Use custom SSH config
            final_ssh_config = {**DEFAULT_REMOTE_SSH_CONFIG, **ssh_config, "mode": "ssh"}
        else:
            # Use default SSH config
            final_ssh_config = {**DEFAULT_REMOTE_SSH_CONFIG, "mode": "ssh"}
    else:
        final_ssh_config = {"mode": "local"}
    
    config = {
        "log_path": log_path,
        "chunk_size": chunk_size if chunk_size is not None else LOG_CHUNK_SIZES.get(log_type, 3),
        "response_language": RESPONSE_LANGUAGE,
        "analysis_mode": mode,
        "access_mode": access_mode,
        "ssh_config": final_ssh_config,
        "realtime_config": REALTIME_CONFIG if mode == "realtime" else None
    }
    return config

def initialize_llm_model(llm_provider=None, llm_model_name=None):
    """
    Initialize LLM model
    
    Args:
        llm_provider: Choose from "ollama", "vllm", "openai" (default: use global LLM_PROVIDER)
        llm_model_name: Specific model name (default: use model from LLM_MODELS)
    
    Returns:
        initialized model object
    """
    # Use global configuration if not specified
    if llm_provider is None:
        llm_provider = LLM_PROVIDER
    if llm_model_name is None:
        llm_model_name = LLM_MODELS.get(llm_provider, "unknown")
    
    if llm_provider == "ollama":
        ### Ollama API
        client = ollama.Client()
        model = outlines.from_ollama(
            client,
            llm_model_name,
        )
    elif llm_provider == "vllm":
        ### Local vLLM API
        openai_api_key = "dummy"
        client = openai.OpenAI(
            base_url="http://127.0.0.1:5000/v1",  # Local vLLM API endpoint
            api_key=openai_api_key
        )
        model = outlines.from_openai(
            client,
            llm_model_name,
        )
    elif llm_provider == "openai":
        ### OpenAI API
        openai_api_key = os.getenv("OPENAI_API_KEY")
        client = openai.OpenAI(
            base_url="https://api.openai.com/v1",  # OpenAI API endpoint
            # base_url="http://127.0.0.1:11434/v1",  # Local Ollama API endpoint
            api_key=openai_api_key
        )
        model = outlines.from_openai(
            client,
            llm_model_name,
        )
    else:
        raise ValueError("Unsupported LLM provider. Use 'ollama', 'vllm', or 'openai'.")
    
    return model


def wait_on_failure(delay_seconds=30):
    """
    Wait for specified seconds when analysis fails to prevent rapid failed requests
    
    Args:
        delay_seconds: Number of seconds to wait (default: 30)
    """
    print(f"⏳ Waiting {delay_seconds} seconds before processing next chunk...")
    time.sleep(delay_seconds)
    print("Wait completed, continuing with next chunk.")


def process_log_chunk(model, prompt, model_class, chunk_start_time, chunk_end_time, 
                     elasticsearch_index, chunk_number, chunk_data, llm_provider=None, llm_model=None,
                     processing_mode=None, log_path=None, access_mode=None):
    """
    Common function to process log chunks
    
    Args:
        model: LLM model object
        prompt: Prompt for analysis
        model_class: Pydantic model class
        chunk_start_time: Chunk analysis start time
        chunk_end_time: Chunk analysis completion time (if None, will be calculated after LLM processing)
        elasticsearch_index: Elasticsearch index name
        chunk_number: Chunk number
        chunk_data: Original chunk data
        llm_provider: LLM provider name (e.g., "ollama", "vllm", "openai")
        llm_model: LLM model name (e.g., "Qwen/Qwen2.5-3B-Instruct")
        processing_mode: Processing mode information (default: "batch")
        log_path: Log file path to include in metadata
        access_mode: Access mode (local/ssh) to include in metadata
    
    Returns:
        (success: bool, parsed_data: dict or None)
    """
    try:
        # LLM 제공자에 따라 다른 매개변수 사용
        if LLM_PROVIDER == "ollama":
            # Outlines의 Ollama는 temperature와 top_p를 지원하지 않음
            review = model(prompt, model_class)
        else:
            # Outlines의 OpenAI와 vLLM은 temperature와 top_p 지원
            review = model(
                prompt, 
                model_class,
                temperature=LLM_TEMPERATURE,
                top_p=LLM_TOP_P
            )
        
        # LLM 분석 완료 후 종료 시간 기록 (chunk_end_time이 None인 경우)
        if chunk_end_time is None:
            chunk_end_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        
        # JSON 파싱
        parsed = json.loads(review)
        
        # 원본 로그 데이터를 LOGID -> 원본 내용 매핑으로 생성
        # chunked_iterable()에서 생성된 LOGID를 그대로 사용하여 일관성 유지
        log_raw_data = {}
        log_count = 0
        for line in chunk_data:
            line = line.strip()
            if line.startswith("LOGID-"):
                parts = line.split(" ", 1)
                logid = parts[0]
                # LOGID를 제거한 원본 로그 내용만 저장
                original_content = parts[1] if len(parts) > 1 else ""
                log_raw_data[logid] = original_content
                log_count += 1
        
        # 분석 시간 정보, LLM 정보, 원본 로그 데이터, 로그 건수 추가
        parsed = {
            **parsed,
            "@chunk_analysis_start_utc": chunk_start_time,
            "@chunk_analysis_end_utc": chunk_end_time,
            "@processing_result": "success",
            "@log_count": log_count,
            "@log_raw_data": log_raw_data,
            "@processing_mode": processing_mode if processing_mode else "batch",
            "@access_mode": access_mode if access_mode else "local"
        }
        
        # LLM 정보 추가 (선택사항)
        if llm_provider:
            parsed["@llm_provider"] = llm_provider
        if llm_model:
            parsed["@llm_model"] = llm_model
        
        # 로그 파일 경로 추가 (선택사항)
        if log_path:
            parsed["@log_path"] = log_path
        
        print(json.dumps(parsed, ensure_ascii=False, indent=4))
        
        # Pydantic 모델 검증
        character = model_class.model_validate(parsed)
        
        # Send to Elasticsearch
        print(f"\nSending data to Elasticsearch...")
        success = send_to_elasticsearch(parsed, elasticsearch_index, chunk_number, chunk_data)
        if success:
            print(f"✅ Chunk {chunk_number} data sent to Elasticsearch successfully")
        else:
            print(f"❌ Chunk {chunk_number} data failed to send to Elasticsearch")
        
        return True, parsed
        
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {e}")
        # LLM 분석 완료 후 종료 시간 기록 (chunk_end_time이 None인 경우)
        if chunk_end_time is None:
            chunk_end_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        # 로그 건수 계산
        log_count = sum(1 for line in chunk_data if line.strip().startswith("LOGID-"))
        # Record minimal information on failure
        failure_data = {
            "@chunk_analysis_start_utc": chunk_start_time,
            "@chunk_analysis_end_utc": chunk_end_time,
            "@processing_result": "failed",
            "@error_type": "json_parse_error",
            "@error_message": str(e)[:200],  # Limit error message to 200 characters
            "@chunk_id": chunk_number,
            "@log_count": log_count,
            "@processing_mode": processing_mode if processing_mode else "batch"
        }
        # LLM 정보 추가 (선택사항)
        if llm_provider:
            failure_data["@llm_provider"] = llm_provider
        if llm_model:
            failure_data["@llm_model"] = llm_model
        # 로그 파일 경로 추가 (선택사항)
        if log_path:
            failure_data["@log_path"] = log_path
        print(f"\nSending failure information to Elasticsearch...")
        success = send_to_elasticsearch(failure_data, elasticsearch_index, chunk_number, chunk_data)
        if success:
            print(f"✅ Chunk {chunk_number} failure information sent to Elasticsearch successfully")
        else:
            print(f"❌ Chunk {chunk_number} failure information failed to send to Elasticsearch")
        return False, None
        
    except Exception as e:
        print(f"❌ Analysis processing error: {e}")
        # LLM 분석 완료 후 종료 시간 기록 (chunk_end_time이 None인 경우)
        if chunk_end_time is None:
            chunk_end_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        # 로그 건수 계산
        log_count = sum(1 for line in chunk_data if line.strip().startswith("LOGID-"))
        # Record minimal information on other failures
        failure_data = {
            "@chunk_analysis_start_utc": chunk_start_time,
            "@chunk_analysis_end_utc": chunk_end_time,
            "@processing_result": "failed",
            "@error_type": "processing_error",
            "@error_message": str(e)[:200],  # Limit error message to 200 characters
            "@chunk_id": chunk_number,
            "@log_count": log_count,
            "@processing_mode": processing_mode if processing_mode else "batch"
        }
        # LLM 정보 추가 (선택사항)
        if llm_provider:
            failure_data["@llm_provider"] = llm_provider
        if llm_model:
            failure_data["@llm_model"] = llm_model
        # 로그 파일 경로 추가 (선택사항)
        if log_path:
            failure_data["@log_path"] = log_path
        print(f"\nSending failure information to Elasticsearch...")
        success = send_to_elasticsearch(failure_data, elasticsearch_index, chunk_number, chunk_data)
        if success:
            print(f"✅ Chunk {chunk_number} failure information sent to Elasticsearch successfully")
        else:
            print(f"❌ Chunk {chunk_number} failure information failed to send to Elasticsearch")
        return False, None


def chunked_iterable(iterable, size, debug=False):
    import hashlib
    chunk = []
    for item in iterable:
        # 로그 라인 전체 내용을 해시값으로 변환
        log_content = item.rstrip()
        
        # 이미 LOGID가 있는 경우 그대로 사용 (tcpdump 패킷 분석 등)
        if log_content.startswith("LOGID-"):
            new_item = f"{log_content}\n"
        else:
            # LOGID가 없는 경우에만 새로 생성 (일반 로그 파일)
            # MD5 해시 생성 (빠르고 충돌 확률이 낮음, 16진수 32자리)
            hash_object = hashlib.md5(log_content.encode('utf-8'))
            hash_hex = hash_object.hexdigest()
            
            # LOGID 생성: LOGID- + 해시값 (대문자로 변환)
            logid = f"LOGID-{hash_hex.upper()}"
            
            # 라인 앞에 LOGID 추가
            new_item = f"{logid} {log_content}\n"
        
        chunk.append(new_item)
        
        if len(chunk) == size:
            if debug:
                print("[DEBUG] Yielding chunk:")
                for line in chunk:
                    print(line.rstrip())
            yield chunk
            chunk = []
    if chunk:
        if debug:
            print("[DEBUG] Yielding final chunk:")
            for line in chunk:
                print(line.rstrip())
        yield chunk

def print_chunk_contents(chunk):
    # Chunk 내용 출력 (콘솔용 - LOGID 제거한 원본 로그만 표시)
    print(f"\n[LOG DATA]")
    for idx, line in enumerate(chunk, 1):
        line = line.strip()
        # LOGID-문자열 제거하고 원본 로그 내용만 추출
        if line.startswith("LOGID-"):
            body = line.split(" ", 1)
            original_content = body[1] if len(body) > 1 else ""
        else:
            original_content = line
        
        # tcpdump 데이터인 경우 \\n을 실제 개행 문자로 변환하여 출력
        if "\\n" in original_content:
            # 멀티라인 tcpdump 데이터를 보기 좋게 출력
            multiline_content = original_content.replace('\\n', '\n')
            print(f"{idx:2d}: {multiline_content}")
        else:
            # 일반 싱글라인 데이터 (라인 번호만 표시)
            print(f"{idx:2d}: {original_content}")
    print("")

### Elasticsearch - Read from config file
ELASTICSEARCH_HOST = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")
ELASTICSEARCH_USER = os.getenv("ELASTICSEARCH_USER", "elastic")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "changeme")
ELASTICSEARCH_INDEX = os.getenv("ELASTICSEARCH_INDEX", "logsentinelai-analysis")

def _get_elasticsearch_client() -> Optional[Elasticsearch]:
    """
    Create an Elasticsearch client and test the connection.
    
    Returns:
        Elasticsearch: Connected client object or None (on connection failure)
    """
    try:
        client = Elasticsearch(
            [ELASTICSEARCH_HOST],
            basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD),
            verify_certs=False,  # Ignore SSL certificates in development environment
            ssl_show_warn=False
        )
        
        # Connection test
        if client.ping():
            print(f"✅ Elasticsearch connection successful: {ELASTICSEARCH_HOST}")
            return client
        else:
            print(f"❌ Elasticsearch ping failed: {ELASTICSEARCH_HOST}")
            return None
            
    except ConnectionError as e:
        print(f"❌ Elasticsearch connection error: {e}")
        return None
    except Exception as e:
        print(f"❌ Elasticsearch client creation error: {e}")
        return None

def _send_to_elasticsearch(data: Dict[str, Any], log_type: str, chunk_id: Optional[int] = None) -> bool:
    """
    Send analysis results to Elasticsearch.
    
    Args:
        data: Analysis data to send (JSON format)
        log_type: Log type ("httpd_access", "httpd_apache_error", "linux_system")
        chunk_id: Chunk number (optional)
    
    Returns:
        bool: Whether transmission was successful
    """
    client = _get_elasticsearch_client()
    if not client:
        return False
    
    try:
        # Generate document identification ID (timestamp + log type + chunk ID)
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        doc_id = f"{log_type}_{timestamp}"
        if chunk_id is not None:
            doc_id += f"_chunk_{chunk_id}"
        
        # Add metadata
        enriched_data = {
            **data,
            "@timestamp": datetime.datetime.utcnow().isoformat(),
            "@log_type": log_type,
            "@document_id": doc_id
        }
        
        # Index document in Elasticsearch
        response = client.index(
            index=ELASTICSEARCH_INDEX,
            id=doc_id,
            document=enriched_data
        )
        
        if response.get('result') in ['created', 'updated']:
            print(f"✅ Elasticsearch transmission successful: {doc_id}")
            return True
        else:
            print(f"❌ Elasticsearch transmission failed: {response}")
            return False
    
    except RequestError as e:
        print(f"❌ Elasticsearch request error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error occurred during Elasticsearch transmission: {e}")
        return False

def _create_log_hash_mapping_realtime(chunk: list[str]) -> Dict[str, str]:
    """
    Create LOGID -> original log content mapping for real-time chunks.
    Real-time chunks contain raw log lines without LOGID prefixes.
    
    Args:
        chunk: List of raw log lines
    
    Returns:
        Dict[str, str]: {logid: original_content} mapping
    """
    mapping = {}
    for line in chunk:
        if line.strip():  # Skip empty lines
            # Generate LOGID for raw log line
            logid = f"LOGID-{hashlib.md5(line.strip().encode()).hexdigest().upper()}"
            mapping[logid] = line.strip()
    return mapping


class GeoIPLookup:
    """
    GeoIP lookup utility for enriching IP addresses with country information
    """
    
    def __init__(self):
        """Initialize GeoIP lookup with MaxMind database"""
        self.enabled = GEOIP_CONFIG["enabled"] and GEOIP_AVAILABLE
        self.database_path = os.path.expanduser(GEOIP_CONFIG["database_path"])  # Expand ~ to home directory
        self.fallback_country = GEOIP_CONFIG["fallback_country"]
        self.include_private_ips = GEOIP_CONFIG["include_private_ips"]
        self.cache_size = GEOIP_CONFIG["cache_size"]
        
        # IP lookup cache to avoid repeated database queries
        self._cache = {}
        self._cache_order = []  # For LRU eviction
        
        # GeoIP database reader
        self._reader = None
        
        if self.enabled:
            self._initialize_database()
    
    def _initialize_database(self):
        """Initialize GeoIP database reader"""
        try:
            # Check if database file exists
            if not os.path.exists(self.database_path):
                print(f"⚠️  GeoIP database not found at {self.database_path}")
                print("🔄 Attempting to download GeoIP database automatically...")
                
                # Try to download automatically
                if self._auto_download_database():
                    print("✅ GeoIP database downloaded successfully!")
                else:
                    print("❌ Failed to download GeoIP database automatically")
                    print("💡 You can manually download using: logsentinelai-geoip-download")
                    print("💡 Or download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
                    print("NOTE: GeoIP enrichment will be disabled")
                    self.enabled = False
                    return
            
            self._reader = geoip2.database.Reader(self.database_path)
            print(f"✓ GeoIP database loaded: {self.database_path}")
            
        except Exception as e:
            print(f"WARNING: Failed to initialize GeoIP database: {e}")
            print("NOTE: GeoIP enrichment will be disabled")
            self.enabled = False
    
    def _auto_download_database(self) -> bool:
        """Automatically download GeoIP database to the configured path"""
        try:
            from ..utils.geoip_downloader import download_geoip_database
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.database_path), exist_ok=True)
            
            # Download to the configured directory
            output_dir = os.path.dirname(self.database_path)
            return download_geoip_database(output_dir)
            
        except ImportError:
            print("WARNING: GeoIP downloader module not available")
            return False
        except Exception as e:
            print(f"WARNING: Auto-download failed: {e}")
            return False
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP address is private/internal"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return False
    
    def _manage_cache(self, ip: str):
        """Manage cache size using LRU eviction"""
        if len(self._cache) >= self.cache_size:
            # Remove oldest entry
            oldest_ip = self._cache_order.pop(0)
            del self._cache[oldest_ip]
        
        # Add to end of order list
        if ip in self._cache_order:
            self._cache_order.remove(ip)
        self._cache_order.append(ip)
    
    def lookup_country(self, ip_str: str) -> Dict[str, str]:
        """
        Lookup country information for an IP address
        
        Args:
            ip_str: IP address string
        
        Returns:
            Dict with country information: {"country_code": "US", "country_name": "United States"}
        """
        if not self.enabled:
            return {"country_code": "N/A", "country_name": "GeoIP Disabled"}
        
        # Validate IP format
        try:
            ipaddress.ip_address(ip_str)
        except ValueError:
            return {"country_code": "INVALID", "country_name": "Invalid IP"}
        
        # Check for private IPs
        if self._is_private_ip(ip_str) and not self.include_private_ips:
            return {"country_code": "PRIVATE", "country_name": "Private IP"}
        
        # Check cache first
        if ip_str in self._cache:
            # Move to end of LRU list
            self._cache_order.remove(ip_str)
            self._cache_order.append(ip_str)
            return self._cache[ip_str]
        
        # Lookup in database
        try:
            response = self._reader.country(ip_str)
            country_info = {
                "country_code": response.country.iso_code or "UNKNOWN",
                "country_name": response.country.name or self.fallback_country
            }
            
            # Cache the result
            self._manage_cache(ip_str)
            self._cache[ip_str] = country_info
            
            return country_info
            
        except geoip2.errors.AddressNotFoundError:
            # IP not found in database
            country_info = {"country_code": "UNKNOWN", "country_name": self.fallback_country}
            self._manage_cache(ip_str)
            self._cache[ip_str] = country_info
            return country_info
            
        except Exception as e:
            print(f"WARNING: GeoIP lookup failed for {ip_str}: {e}")
            return {"country_code": "ERROR", "country_name": "Lookup Failed"}
    
    def close(self):
        """Close GeoIP database reader"""
        if self._reader:
            self._reader.close()
            self._reader = None


# Global GeoIP lookup instance
_geoip_lookup = None

def get_geoip_lookup() -> GeoIPLookup:
    """Get or create global GeoIP lookup instance"""
    global _geoip_lookup
    if _geoip_lookup is None:
        _geoip_lookup = GeoIPLookup()
    return _geoip_lookup


def enrich_source_ips_with_geoip(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich source_ips in analysis data with GeoIP country information
    
    This function appends country information as text to IP addresses to maintain
    Elasticsearch compatibility. Instead of converting IPs to objects, it creates
    enriched text strings like "1.1.1.1 (US - United States)".
    
    Handles both:
    1. source_ips arrays (HTTP access, Apache error, Linux system logs)
    2. Individual source_ip/dest_ip fields (TCPDUMP packet logs)
    
    Args:
        analysis_data: Analysis result data containing events with source_ips or source_ip/dest_ip
    
    Returns:
        Dict[str, Any]: Analysis data with enriched source_ips as text strings
    """
    if not GEOIP_CONFIG["enabled"] or not GEOIP_AVAILABLE:
        return analysis_data
    
    geoip = get_geoip_lookup()
    if not geoip.enabled:
        return analysis_data
    
    def enrich_ip_text(ip_str):
        """Convert IP string to enriched format"""
        if not isinstance(ip_str, str):
            return ip_str
        
        try:
            country_info = geoip.lookup_country(ip_str)
            if country_info["country_code"] in ["N/A", "ERROR", "INVALID"]:
                return ip_str
            elif country_info["country_code"] == "PRIVATE":
                return f"{ip_str} (Private)"
            elif country_info["country_code"] == "UNKNOWN":
                return f"{ip_str} (Unknown)"
            else:
                return f"{ip_str} ({country_info['country_code']} - {country_info['country_name']})"
        except Exception:
            return ip_str
    
    # Deep copy to avoid modifying original data
    enriched_data = analysis_data.copy()
    
    # Process events array
    if "events" in enriched_data and isinstance(enriched_data["events"], list):
        for event in enriched_data["events"]:
            if isinstance(event, dict):
                # Handle source_ips arrays (HTTP access, Apache error, Linux system logs)
                if "source_ips" in event and isinstance(event["source_ips"], list):
                    enriched_ips = []
                    
                    for ip_item in event["source_ips"]:
                        if isinstance(ip_item, str):
                            # Simple IP string - enrich with country info as text
                            enriched_ips.append(enrich_ip_text(ip_item))
                            
                        elif isinstance(ip_item, dict) and "ip" in ip_item:
                            # IP dict - extract IP and enrich as text
                            ip_str = ip_item["ip"]
                            enriched_ips.append(enrich_ip_text(ip_str))
                            
                        else:
                            # Unknown format - keep as is
                            enriched_ips.append(ip_item)
                    
                    # Replace source_ips with enriched version
                    event["source_ips"] = enriched_ips
                
                # Handle individual source_ip and dest_ip fields (TCPDUMP)
                if "source_ip" in event:
                    event["source_ip"] = enrich_ip_text(event["source_ip"])
                if "dest_ip" in event:
                    event["dest_ip"] = enrich_ip_text(event["dest_ip"])
    
    # Process statistics if it contains IP information
    if "statistics" in enriched_data and isinstance(enriched_data["statistics"], dict):
        stats = enriched_data["statistics"]
        
        # Enrich top_source_ips if present (HTTP access, Apache error, Linux system logs)
        if "top_source_ips" in stats and isinstance(stats["top_source_ips"], dict):
            enriched_top_ips = {}
            
            for ip, count in stats["top_source_ips"].items():
                enriched_key = enrich_ip_text(ip)
                enriched_top_ips[enriched_key] = count
            
            stats["top_source_ips"] = enriched_top_ips
        
        # Handle TCPDUMP-specific statistics
        if "top_source_addresses" in stats and isinstance(stats["top_source_addresses"], dict):
            enriched_sources = {}
            for ip, count in stats["top_source_addresses"].items():
                enriched_key = enrich_ip_text(ip)
                enriched_sources[enriched_key] = count
            stats["top_source_addresses"] = enriched_sources
        
        if "top_destination_addresses" in stats and isinstance(stats["top_destination_addresses"], dict):
            enriched_destinations = {}
            for ip, count in stats["top_destination_addresses"].items():
                enriched_key = enrich_ip_text(ip)
                enriched_destinations[enriched_key] = count
            stats["top_destination_addresses"] = enriched_destinations
    
    return enriched_data


def send_to_elasticsearch(analysis_data: Dict[str, Any], log_type: str, chunk_id: Optional[int] = None, chunk: Optional[list] = None) -> bool:
    """
    Integrated function to format analysis results and send them to Elasticsearch.
    Includes GeoIP enrichment of source_ips before sending to Elasticsearch.
    
    Args:
        analysis_data: Analysis result data
        log_type: Log type ("httpd_access", "httpd_apache_error", "linux_system")
        chunk_id: Chunk number (optional)
        chunk: Original log chunk (currently not used, maintained for compatibility)
    
    Returns:
        bool: Whether transmission was successful
    """
    # Enrich source_ips with GeoIP information before sending to Elasticsearch
    enriched_data = enrich_source_ips_with_geoip(analysis_data)
    
    return _send_to_elasticsearch(enriched_data, log_type, chunk_id)


class RemoteSSHLogMonitor:
    """
    SSH-based remote log file monitoring
    """
    
    def __init__(self, ssh_config: Dict[str, Any], remote_log_path: str):
        """
        Initialize SSH remote log monitor
        
        Args:
            ssh_config: SSH connection configuration
            remote_log_path: Remote log file path
        """
        self.ssh_host = ssh_config["host"]
        self.ssh_port = ssh_config["port"]
        self.ssh_user = ssh_config["user"]
        self.ssh_key_path = ssh_config["key_path"]
        self.ssh_password = ssh_config["password"]
        self.ssh_timeout = ssh_config["timeout"]
        self.remote_log_path = remote_log_path
        
        # SSH 연결 검증
        self._validate_ssh_config()
        
        print(f"SSH Target:       {self.ssh_user}@{self.ssh_host}:{self.ssh_port}")
        print(f"Remote Log:       {self.remote_log_path}")
        print(f"Auth Method:      {'SSH Key' if self.ssh_key_path else 'Password'}")
        
    def _validate_ssh_config(self):
        """SSH 설정 유효성 검사"""
        if not self.ssh_host:
            raise ValueError("REMOTE_SSH_HOST is required for SSH mode")
        if not self.ssh_user:
            raise ValueError("REMOTE_SSH_USER is required for SSH mode")
        if not self.ssh_key_path and not self.ssh_password:
            raise ValueError("Either REMOTE_SSH_KEY_PATH or REMOTE_SSH_PASSWORD is required")
        
        # SSH 키 파일 존재 확인
        if self.ssh_key_path and not os.path.exists(self.ssh_key_path):
            raise FileNotFoundError(f"SSH key file not found: {self.ssh_key_path}")
    
    def _create_ssh_connection(self):
        """SSH 연결 생성"""
        try:
            import paramiko
        except ImportError:
            raise ImportError("paramiko library is required for SSH functionality. Install with: pip install paramiko")
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            if self.ssh_key_path:
                # SSH 키 인증
                ssh.connect(
                    hostname=self.ssh_host,
                    port=self.ssh_port,
                    username=self.ssh_user,
                    key_filename=self.ssh_key_path,
                    timeout=self.ssh_timeout
                )
            else:
                # 패스워드 인증
                ssh.connect(
                    hostname=self.ssh_host,
                    port=self.ssh_port,
                    username=self.ssh_user,
                    password=self.ssh_password,
                    timeout=self.ssh_timeout
                )
            
            return ssh
            
        except Exception as e:
            ssh.close()
            raise ConnectionError(f"Failed to connect to SSH server: {e}")
    
    def get_file_size(self) -> int:
        """원격 파일 크기 확인"""
        ssh = self._create_ssh_connection()
        try:
            # stat 명령으로 파일 크기 확인
            command = f"stat -c %s '{self.remote_log_path}' 2>/dev/null || echo 0"
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()  # 명령 완료 대기
            
            size_str = stdout.read().decode('utf-8').strip()
            return int(size_str) if size_str.isdigit() else 0
            
        except Exception as e:
            print(f"WARNING: Failed to get remote file size: {e}")
            return 0
        finally:
            ssh.close()
    
    def get_file_inode(self) -> Optional[int]:
        """원격 파일 inode 확인 (로그 로테이션 감지용)"""
        ssh = self._create_ssh_connection()
        try:
            # stat 명령으로 inode 확인
            command = f"stat -c %i '{self.remote_log_path}' 2>/dev/null || echo 0"
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()
            
            inode_str = stdout.read().decode('utf-8').strip()
            return int(inode_str) if inode_str.isdigit() and inode_str != "0" else None
            
        except Exception as e:
            print(f"WARNING: Failed to get remote file inode: {e}")
            return None
        finally:
            ssh.close()
    
    def read_from_position(self, position: int) -> List[str]:
        """특정 위치부터 원격 파일 읽기"""
        ssh = self._create_ssh_connection()
        try:
            # tail 명령으로 특정 바이트부터 읽기
            # +숫자는 바이트 위치를 의미 (1-based이므로 +1)
            command = f"tail -c +{position + 1} '{self.remote_log_path}' 2>/dev/null || echo ''"
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()
            
            content = stdout.read().decode('utf-8', errors='ignore')
            
            if not content.strip():
                return []
            
            # 라인 단위로 분할
            lines = content.split('\n')
            
            # 마지막 빈 라인 제거
            if lines and not lines[-1].strip():
                lines = lines[:-1]
            
            # 빈 라인 필터링
            return [line.strip() for line in lines if line.strip()]
            
        except Exception as e:
            print(f"WARNING: Failed to read remote file: {e}")
            return []
        finally:
            ssh.close()
    
    def test_connection(self) -> bool:
        """SSH 연결 테스트"""
        try:
            ssh = self._create_ssh_connection()
            
            # 간단한 명령 실행으로 연결 테스트
            stdin, stdout, stderr = ssh.exec_command("echo 'SSH connection test'")
            stdout.channel.recv_exit_status()
            
            result = stdout.read().decode('utf-8').strip()
            ssh.close()
            
            return result == "SSH connection test"
            
        except Exception as e:
            print(f"SSH connection test failed: {e}")
            return False


class RealtimeLogMonitor:
    """
    Real-time log file monitoring and analysis
    """
    
    def __init__(self, log_type: str, config: Dict[str, Any]):
        """
        Initialize real-time log monitor
        
        Args:
            log_type: Type of log to monitor
            config: Configuration dictionary from get_analysis_config()
        """
        self.log_type = log_type
        self.log_path = config["log_path"]
        self.chunk_size = config["chunk_size"]
        self.response_language = config["response_language"]
        self.realtime_config = config["realtime_config"]
        
        # Access mode and SSH configuration
        self.access_mode = config["access_mode"]
        self.ssh_config = config["ssh_config"]
        self.ssh_monitor = None
        
        # Sampling configuration
        self.processing_mode = self.realtime_config["processing_mode"]
        self.sampling_threshold = self.realtime_config["sampling_threshold"]
        
        # Position tracking
        self.position_file_dir = self.realtime_config["position_file_dir"]
        self.position_file = os.path.join(
            self.position_file_dir, 
            f"{log_type}_position.txt"
        )
        
        # Create position file directory if it doesn't exist
        os.makedirs(self.position_file_dir, exist_ok=True)
        
        # Buffer for incomplete lines
        self.line_buffer = []
        # Buffer for accumulating lines until chunk_size is reached
        self.pending_lines = []
        
        # File tracking for rotation detection
        self.last_position = 0
        self.last_inode = None
        self.last_size = 0
        
        # Initialize SSH monitor if in SSH mode
        if self.access_mode == "ssh":
            self._initialize_ssh_monitor()
        
        # Load position and file info
        self._load_position_and_file_info()
        
        # Display initialization info in a clean format
        print("=" * 80)
        print(f"REALTIME LOG MONITOR INITIALIZED")
        print("=" * 80)
        print(f"Log Type:         {log_type}")
        print(f"Access Mode:      {self.access_mode.upper()}")
        if self.access_mode == "ssh":
            print(f"Monitoring:       {self.log_path}")
        else:
            print(f"Monitoring:       {self.log_path}")
        print(f"Mode:             {self.processing_mode.upper()}")
        if self.processing_mode == "full":
            print(f"Auto-sampling:    {self.sampling_threshold} {'packets' if log_type == 'tcpdump_packet' else 'lines'} threshold")
        elif self.processing_mode == "sampling":
            print(f"Sampling:         Always keep latest {self.chunk_size} {'packets' if log_type == 'tcpdump_packet' else 'lines'}")
        print(f"Poll Interval:    {self.realtime_config['polling_interval']}s")
        print(f"Chunk Size:       {self.chunk_size} {'packets' if log_type == 'tcpdump_packet' else 'lines'}")
        print("=" * 80)
    
    def _initialize_ssh_monitor(self):
        """SSH 원격 모니터 초기화"""
        try:
            if not self.log_path:
                raise ValueError(f"No remote log path configured for {self.log_type}")
            
            self.ssh_monitor = RemoteSSHLogMonitor(self.ssh_config, self.log_path)
            
            # SSH 연결 테스트
            print("🔗 Testing SSH connection...")
            if self.ssh_monitor.test_connection():
                print("✅ SSH connection successful")
            else:
                raise ConnectionError("SSH connection test failed")
                
        except Exception as e:
            print(f"❌ SSH initialization failed: {e}")
            print("💡 Please check your SSH configuration")
            raise
    
    def _load_position_and_file_info(self):
        """Load last read position and file info from position file"""
        try:
            if os.path.exists(self.position_file):
                with open(self.position_file, 'r') as f:
                    content = f.read().strip()
                    # Support both old format (position only) and new format (position:inode:size)
                    parts = content.split(':')
                    if len(parts) >= 1:
                        self.last_position = int(parts[0])
                    if len(parts) >= 2:
                        self.last_inode = int(parts[1]) if parts[1] != 'None' else None
                    if len(parts) >= 3:
                        self.last_size = int(parts[2])
                    
                    print(f"Loaded state: position={self.last_position}, inode={self.last_inode}, size={self.last_size}")
                    
                    # Verify current file matches saved state
                    if self.access_mode == "ssh":
                        # SSH 모드: 원격 파일 상태 확인
                        if self.ssh_monitor:
                            current_size = self.ssh_monitor.get_file_size()
                            current_inode = self.ssh_monitor.get_file_inode()
                            
                            if self.last_inode and current_inode and current_inode != self.last_inode:
                                print(f"WARNING: Remote file inode changed ({self.last_inode} -> {current_inode})")
                                print(f"         Possible log rotation detected, starting from beginning")
                                self.last_position = 0
                                self.last_size = 0
                            elif current_size < self.last_position:
                                print(f"WARNING: Remote file size decreased ({self.last_size} -> {current_size})")
                                print(f"         File truncated or rotated, starting from beginning")
                                self.last_position = 0
                            
                            # Update current file info
                            if current_inode:
                                self.last_inode = current_inode
                            self.last_size = current_size
                            self._save_position_and_file_info()
                    else:
                        # 로컬 모드: 로컬 파일 상태 확인
                        if os.path.exists(self.log_path):
                            current_stat = os.stat(self.log_path)
                            current_inode = current_stat.st_ino
                            current_size = current_stat.st_size
                            
                            if self.last_inode and current_inode != self.last_inode:
                                print(f"WARNING: File inode changed ({self.last_inode} -> {current_inode})")
                                print(f"         Possible log rotation detected, starting from beginning")
                                self.last_position = 0
                                self.last_size = 0
                            elif current_size < self.last_position:
                                print(f"WARNING: File size decreased ({self.last_size} -> {current_size})")
                                print(f"         File truncated or rotated, starting from beginning")
                                self.last_position = 0
                            
                            # Update current file info
                            self.last_inode = current_inode
                            self.last_size = current_size
                            self._save_position_and_file_info()
                    
                    return
        except (ValueError, IOError) as e:
            print(f"WARNING: Error loading position file: {e}")
        
        # If file doesn't exist or error, start from end of file
        try:
            if self.access_mode == "ssh":
                # SSH 모드: 원격 파일에서 초기화
                if self.ssh_monitor:
                    current_size = self.ssh_monitor.get_file_size()
                    current_inode = self.ssh_monitor.get_file_inode()
                    
                    # 초기 실행 시 최근 chunk_size 라인을 읽기 위해 적절한 위치에서 시작
                    # 파일 크기가 충분히 크면 마지막 몇 KB에서 시작하여 최근 라인들 확보
                    if current_size > 10000:  # 10KB 이상이면 마지막 5KB에서 시작
                        self.last_position = max(0, current_size - 5000)
                        print(f"📍 Starting from recent position in remote file: position={self.last_position} (file_size={current_size})")
                    else:
                        self.last_position = 0  # 작은 파일은 처음부터
                        print(f"📍 Starting from beginning of remote file: position={self.last_position} (file_size={current_size})")
                    
                    self.last_inode = current_inode
                    self.last_size = current_size
                    self._save_position_and_file_info()
                else:
                    print(f"WARNING: SSH monitor not available for initialization")
                    self.last_position = 0
                    self.last_inode = None
                    self.last_size = 0
            else:
                # 로컬 모드: 로컬 파일에서 초기화
                if os.path.exists(self.log_path):
                    file_stat = os.stat(self.log_path)
                    current_size = file_stat.st_size
                    
                    # 초기 실행 시 최근 chunk_size 라인을 읽기 위해 적절한 위치에서 시작
                    if current_size > 10000:  # 10KB 이상이면 마지막 5KB에서 시작
                        self.last_position = max(0, current_size - 5000)
                        print(f"📍 Starting from recent position in file: position={self.last_position} (file_size={current_size})")
                    else:
                        self.last_position = 0  # 작은 파일은 처음부터
                        print(f"📍 Starting from beginning of file: position={self.last_position} (file_size={current_size})")
                    
                    self.last_inode = file_stat.st_ino
                    self.last_size = current_size
                    self._save_position_and_file_info()
                else:
                    print(f"WARNING: Local log file does not exist: {self.log_path}")
                    self.last_position = 0
                    self.last_inode = None
                    self.last_size = 0
        except Exception as e:
            print(f"WARNING: Error accessing log file: {e}")
            self.last_position = 0
            self.last_inode = None
            self.last_size = 0
    
    def _save_position_and_file_info(self):
        """Save current read position and file info to position file"""
        try:
            with open(self.position_file, 'w') as f:
                f.write(f"{self.last_position}:{self.last_inode}:{self.last_size}")
        except IOError as e:
            print(f"WARNING: Error saving position: {e}")
    
    def _read_new_lines(self) -> List[str]:
        """Read new lines from log file since last position (local or remote)"""
        if self.access_mode == "ssh":
            return self._read_remote_new_lines()
        else:
            return self._read_local_new_lines()
    
    def _read_local_new_lines(self) -> List[str]:
        """Read new lines from local log file since last position (기존 방식)"""
        try:
            if not os.path.exists(self.log_path):
                print(f"WARNING: Log file does not exist: {self.log_path}")
                return []
            
            # Get current file stats
            file_stat = os.stat(self.log_path)
            current_size = file_stat.st_size
            current_inode = file_stat.st_ino
            
            # Check for file rotation (inode change)
            if self.last_inode and current_inode != self.last_inode:
                print(f"NOTICE: Log rotation detected (inode {self.last_inode} -> {current_inode})")
                print(f"       New file detected, starting from beginning")
                self.last_position = 0
                self.line_buffer = []
                self.last_inode = current_inode
                self.last_size = current_size
                self._save_position_and_file_info()
            
            # Check for file truncation
            elif current_size < self.last_position:
                if current_size == 0:
                    print(f"NOTICE: File truncated (size=0), resetting position to 0")
                else:
                    print(f"NOTICE: File truncated (size={current_size} < position={self.last_position})")
                    print(f"       Starting from beginning of current file")
                
                # Reset position to start of file and clear buffer
                self.last_position = 0
                self.line_buffer = []
                self.last_size = current_size
                self._save_position_and_file_info()
            
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Seek to last position
                f.seek(self.last_position)
                
                # Read new content
                new_content = f.read()
                new_position = f.tell()
                
                if not new_content:
                    return []
                
                # Split into lines
                lines = new_content.split('\n')
                
                # Handle incomplete last line
                if new_content.endswith('\n'):
                    # Complete lines only
                    complete_lines = lines[:-1]  # Remove empty last element
                else:
                    # Last line is incomplete, save for next read
                    complete_lines = lines[:-1]
                    self.line_buffer.append(lines[-1])
                
                # Prepend any buffered content to first line
                if self.line_buffer and complete_lines:
                    complete_lines[0] = ''.join(self.line_buffer) + complete_lines[0]
                    self.line_buffer = []
                
                # Update position and file info
                if complete_lines:
                    # Only update position if we have complete lines
                    self.last_position = new_position - len(lines[-1]) if not new_content.endswith('\n') else new_position
                    self.last_size = current_size
                    self.last_inode = current_inode
                    self._save_position_and_file_info()
                
                # Filter out empty lines
                complete_lines = [line.strip() for line in complete_lines if line.strip()]
                
                return complete_lines
                
        except IOError as e:
            print(f"WARNING: Error reading local log file: {e}")
            return []
    
    def _read_remote_new_lines(self) -> List[str]:
        """SSH를 통해 원격 파일에서 새로운 라인들을 읽어옴"""
        try:
            if not self.ssh_monitor:
                print(f"WARNING: SSH monitor not initialized")
                return []
            
            # 원격 파일 상태 확인
            current_size = self.ssh_monitor.get_file_size()
            current_inode = self.ssh_monitor.get_file_inode()
            
            # 파일 로테이션 감지
            if self.last_inode and current_inode and current_inode != self.last_inode:
                print(f"NOTICE: Remote log rotation detected (inode {self.last_inode} -> {current_inode})")
                print(f"       New file detected, starting from beginning")
                self.last_position = 0
                self.line_buffer = []
                self.last_inode = current_inode
                self.last_size = current_size
                self._save_position_and_file_info()
            
            # 파일 크기 감소 감지 (truncation)
            elif current_size < self.last_position:
                if current_size == 0:
                    print(f"NOTICE: Remote file truncated (size=0), resetting position to 0")
                else:
                    print(f"NOTICE: Remote file truncated (size={current_size} < position={self.last_position})")
                    print(f"       Starting from beginning of current file")
                
                self.last_position = 0
                self.line_buffer = []
                self.last_size = current_size
                self._save_position_and_file_info()
            
            # 새로운 내용이 없는 경우
            if current_size <= self.last_position:
                return []
            
            # 원격 파일에서 새로운 라인들 읽기
            new_lines = self.ssh_monitor.read_from_position(self.last_position)
            
            if new_lines:
                # 위치 정보 업데이트
                self.last_position = current_size
                self.last_size = current_size
                if current_inode:
                    self.last_inode = current_inode
                self._save_position_and_file_info()
                
                print(f"📡 Read {len(new_lines)} new lines from remote log")
            
            return new_lines
            
        except Exception as e:
            print(f"WARNING: Error reading remote log file: {e}")
            return []
    
    def get_new_log_chunks(self) -> Generator[List[str], None, None]:
        """
        Generator that yields chunks of new log lines
        Only yields when chunk_size lines are accumulated
        Supports both full processing and sampling modes
        TCPDump logs are handled as packet units instead of line units
        
        Yields:
            List[str]: Chunk of new log lines (exactly chunk_size or remaining at end)
        """
        # TCPDump 로그는 패킷 단위로 처리
        if self.log_type == "tcpdump_packet":
            return self._get_new_packet_chunks()
        
        # 기존 라인 단위 처리 (다른 로그 타입들)
        new_lines = self._read_new_lines()
        
        if not new_lines:
            return
        
        # Limit the number of lines per batch
        max_lines = self.realtime_config["max_lines_per_batch"]
        if len(new_lines) > max_lines:
            print(f"WARNING: Too many new lines ({len(new_lines)}), limiting to {max_lines}")
            new_lines = new_lines[:max_lines]
        
        # Add new lines to pending buffer
        self.pending_lines.extend(new_lines)
        
        # Show status update only when significant changes occur
        status_msg = f"[{self.processing_mode.upper()}] Pending: {len(self.pending_lines)} lines"
        if len(new_lines) > 0:
            print(f"STATUS: {status_msg} (+{len(new_lines)} new)")
        
        # Check if we need to apply sampling
        should_sample = (
            self.processing_mode == "sampling" or 
            (self.processing_mode == "full" and len(self.pending_lines) > self.sampling_threshold)
        )
        
        if should_sample and len(self.pending_lines) > self.chunk_size:
            # Sampling mode: only keep the most recent chunk_size lines
            discarded_count = len(self.pending_lines) - self.chunk_size
            self.pending_lines = self.pending_lines[-self.chunk_size:]
            if discarded_count > 0:
                print(f"WARNING: SAMPLING: Discarded {discarded_count} older lines, keeping latest {self.chunk_size}")
        
        # Yield complete chunks only when we have enough lines
        while len(self.pending_lines) >= self.chunk_size:
            chunk = self.pending_lines[:self.chunk_size]
            self.pending_lines = self.pending_lines[self.chunk_size:]
            print(f"CHUNK READY: {len(chunk)} lines | Remaining: {len(self.pending_lines)}")
            yield chunk
    
    def _get_new_packet_chunks(self) -> Generator[List[str], None, None]:
        """
        TCPDump 전용: 패킷 단위로 새로운 로그 청크 생성
        자동으로 단일라인/멀티라인 형태를 감지하여 처리
        """
        # 로그 형태 감지 및 패킷 읽기
        new_packets = self._read_new_packets_auto_detect()
        
        if not new_packets:
            return
        
        # TCPDump는 패킷 수 기준으로 제한
        max_packets = self.realtime_config["max_lines_per_batch"]  # 패킷 단위로 해석
        if len(new_packets) > max_packets:
            print(f"WARNING: Too many new packets ({len(new_packets)}), limiting to {max_packets}")
            new_packets = new_packets[:max_packets]
        
        # 패킷을 pending buffer에 추가
        self.pending_lines.extend(new_packets)
        
        # 상태 표시 (패킷 단위)
        status_msg = f"[{self.processing_mode.upper()}] Pending: {len(self.pending_lines)} packets"
        if len(new_packets) > 0:
            print(f"STATUS: {status_msg} (+{len(new_packets)} new packets)")
        
        # 샘플링 필요 여부 확인 (패킷 단위)
        should_sample = (
            self.processing_mode == "sampling" or 
            (self.processing_mode == "full" and len(self.pending_lines) > self.sampling_threshold)
        )
        
        if should_sample and len(self.pending_lines) > self.chunk_size:
            # 샘플링 모드: 최신 chunk_size 패킷만 유지
            discarded_count = len(self.pending_lines) - self.chunk_size
            self.pending_lines = self.pending_lines[-self.chunk_size:]
            if discarded_count > 0:
                print(f"WARNING: SAMPLING: Discarded {discarded_count} older packets, keeping latest {self.chunk_size}")
        
        # chunk_size만큼 패킷이 쌓이면 청크 생성
        while len(self.pending_lines) >= self.chunk_size:
            chunk = self.pending_lines[:self.chunk_size]
            self.pending_lines = self.pending_lines[self.chunk_size:]
            print(f"PACKET CHUNK READY: {len(chunk)} packets | Remaining: {len(self.pending_lines)}")
            yield chunk
    
    def _read_new_packets_auto_detect(self) -> List[str]:
        """
        TCPDump 로그에서 새로운 패킷들을 읽어옴 (자동 형태 감지)
        단일라인 형태와 멀티라인 형태를 자동으로 감지하여 처리
        """
        try:
            if not os.path.exists(self.log_path):
                print(f"WARNING: Log file does not exist: {self.log_path}")
                return []
            
            # 파일 상태 확인
            file_stat = os.stat(self.log_path)
            current_size = file_stat.st_size
            current_inode = file_stat.st_ino
            
            # 파일 로테이션 감지
            if self.last_inode and current_inode != self.last_inode:
                print(f"NOTICE: Log rotation detected (inode {self.last_inode} -> {current_inode})")
                print(f"       New file detected, starting from beginning")
                self.last_position = 0
                self.line_buffer = []
                self.last_inode = current_inode
                self.last_size = current_size
                self._save_position_and_file_info()
            
            # 파일 truncation 감지
            elif current_size < self.last_position:
                if current_size == 0:
                    print(f"NOTICE: File truncated (size=0), resetting position to 0")
                else:
                    print(f"NOTICE: File truncated (size={current_size} < position={self.last_position})")
                    print(f"       Starting from beginning of current file")
                
                self.last_position = 0
                self.line_buffer = []
                self.last_size = current_size
                self._save_position_and_file_info()
            
            # 로그 형태 감지 (처음 몇 라인 확인)
            log_format = self._detect_tcpdump_format()
            
            if log_format == "multiline":
                print(f"📦 Detected TCPDump format: MULTILINE (with hex dumps)")
                return self._read_multiline_packets()
            else:
                print(f"📦 Detected TCPDump format: SINGLE-LINE (without hex dumps)")
                return self._read_singleline_packets()
            
        except IOError as e:
            print(f"WARNING: Error reading TCPDump log file: {e}")
            return []
    
    def _detect_tcpdump_format(self) -> str:
        """
        TCPDump 로그 형태 감지 (single-line vs multiline)
        
        Returns:
            str: "singleline" 또는 "multiline"
        """
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.last_position)
                
                # 처음 50라인 정도를 읽어서 형태 판단
                lines_checked = 0
                hex_dump_found = False
                
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    lines_checked += 1
                    
                    # hex dump 라인 감지 (0x로 시작하고 콜론 포함)
                    if line.strip().startswith('0x') and ':' in line:
                        hex_dump_found = True
                        break
                    
                    # 충분한 라인을 확인했으면 중단
                    if lines_checked >= 50:
                        break
                
                return "multiline" if hex_dump_found else "singleline"
                
        except IOError:
            # 기본값으로 single-line 반환
            return "singleline"
    
    def _read_singleline_packets(self) -> List[str]:
        """
        단일라인 TCPDump 로그에서 패킷들을 읽어옴
        각 라인이 하나의 패킷
        """
        try:
            packets = []
            
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.last_position)
                
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # 패킷 헤더 라인인지 확인 (타임스탬프로 시작)
                    if self._is_packet_header_line(line):
                        packets.append(line)
                
                # 위치 업데이트
                self.last_position = f.tell()
                self.last_size = os.stat(self.log_path).st_size
                self.last_inode = os.stat(self.log_path).st_ino
                self._save_position_and_file_info()
            
            if packets:
                print(f"📦 Read {len(packets)} single-line packets from TCPDump log")
            
            return packets
            
        except IOError as e:
            print(f"WARNING: Error reading single-line TCPDump log file: {e}")
            return []
    
    def _read_multiline_packets(self) -> List[str]:
        """
        멀티라인 TCPDump 로그에서 패킷들을 읽어옴 (기존 방식)
        패킷 헤더 + hex dump 라인들을 하나의 패킷으로 결합
        """
        try:
            packets = []
            current_packet_lines = []
            
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.last_position)
                
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # 새 패킷 헤더 감지 (타임스탬프로 시작)
                    if self._is_packet_header_line(line):
                        # 이전 패킷이 있으면 완성된 패킷으로 저장
                        if current_packet_lines:
                            packet_content = '\n'.join(current_packet_lines)
                            packets.append(packet_content)
                        
                        # 새 패킷 시작
                        current_packet_lines = [line]
                    else:
                        # 현재 패킷에 데이터 라인 추가 (0x로 시작하는 hex dump)
                        if line.strip().startswith('0x') and current_packet_lines:
                            current_packet_lines.append(line)
                
                # 마지막 패킷 처리 (파일 끝에 도달한 경우)
                if current_packet_lines:
                    packet_content = '\n'.join(current_packet_lines)
                    packets.append(packet_content)
                
                # 위치 업데이트
                self.last_position = f.tell()
                self.last_size = os.stat(self.log_path).st_size
                self.last_inode = os.stat(self.log_path).st_ino
                self._save_position_and_file_info()
            
            if packets:
                print(f"📦 Read {len(packets)} multiline packets from TCPDump log")
            
            return packets
            
        except IOError as e:
            print(f"WARNING: Error reading multiline TCPDump log file: {e}")
            return []
    
    def _is_packet_header_line(self, line: str) -> bool:
        """패킷 헤더 라인인지 확인 (타임스탬프 패턴)"""
        import re
        # 2025-07-17 14:00:00.205658 IP 형태의 타임스탬프 패턴
        timestamp_pattern = r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ IP '
        return bool(re.match(timestamp_pattern, line))
    
    def flush_pending_lines(self) -> Generator[List[str], None, None]:
        """
        Flush any remaining pending lines as a final chunk
        Used when stopping monitoring to process remaining lines
        
        Yields:
            List[str]: Remaining pending lines if any
        """
        if self.pending_lines:
            print(f"FINAL FLUSH: {len(self.pending_lines)} remaining lines")
            yield self.pending_lines.copy()
            self.pending_lines.clear()
    
    def monitor_and_analyze(self, model, analysis_prompt_func, 
                          analysis_schema_class, 
                          process_callback=None):
        """
        Continuously monitor log file and analyze new entries
        
        Args:
            model: LLM model for analysis
            analysis_prompt_func: Function to create analysis prompt (chunk, response_language) -> prompt
            analysis_schema_class: Pydantic schema class for structured output
            process_callback: Optional callback function for processing results
        """
        print("MONITORING STARTED - Press Ctrl+C to stop")
        print("-" * 50)
        
        chunk_counter = 0
        
        try:
            while True:
                # Check for new log entries
                for chunk in self.get_new_log_chunks():
                    chunk_counter += 1
                    
                    print(f"\n� CHUNK #{chunk_counter} ({len(chunk)} lines)")
                    print("─" * 50)
                    for i, line in enumerate(chunk, 1):
                        # Remove LOGID prefix for console display and truncate long lines
                        if line.startswith("LOGID-"):
                            # Extract original content without LOGID
                            parts = line.split(" ", 1)
                            original_line = parts[1] if len(parts) > 1 else ""
                        else:
                            original_line = line
                        
                        display_line = original_line[:100] + "..." if len(original_line) > 100 else original_line
                        print(f"{i:2d}: {display_line}")
                    print("─" * 50)
                    
                    try:
                        # Create prompt
                        prompt = analysis_prompt_func(chunk, self.response_language)
                        
                        # Process the chunk with processing mode info
                        result = process_log_chunk_realtime(
                            model=model,
                            prompt=prompt,
                            model_class=analysis_schema_class,
                            chunk=chunk,
                            chunk_id=chunk_counter,
                            log_type=self.log_type,
                            response_language=self.response_language,
                            processing_mode=self.processing_mode,
                            sampling_threshold=self.sampling_threshold,
                            log_path=self.log_path,
                            access_mode=self.access_mode
                        )
                        
                        # Call custom callback if provided
                        if process_callback:
                            process_callback(result, chunk, chunk_counter)
                        
                        print(f"✅ CHUNK #{chunk_counter} COMPLETED")
                        
                    except Exception as e:
                        print(f"❌ CHUNK #{chunk_counter} FAILED: {e}")
                        continue
                
                # Wait before next poll
                time.sleep(self.realtime_config["polling_interval"])
                
        except KeyboardInterrupt:
            print(f"\n🛑 MONITORING STOPPED")
            print("=" * 50)
            print(f"📊 Total chunks processed: {chunk_counter}")
            
            # Process any remaining buffered lines
            for chunk in self.flush_pending_lines():
                chunk_counter += 1
                print(f"\n� FINAL CHUNK #{chunk_counter} ({len(chunk)} lines)")
                print("─" * 50)
                for i, line in enumerate(chunk, 1):
                    # Remove LOGID prefix for console display and truncate long lines
                    if line.startswith("LOGID-"):
                        # Extract original content without LOGID
                        parts = line.split(" ", 1)
                        original_line = parts[1] if len(parts) > 1 else ""
                    else:
                        original_line = line
                    
                    display_line = original_line[:100] + "..." if len(original_line) > 100 else original_line
                    print(f"{i:2d}: {display_line}")
                print("─" * 50)
                
                try:
                    # Create prompt
                    prompt = analysis_prompt_func(chunk, self.response_language)
                    
                    # Process the chunk with processing mode info
                    result = process_log_chunk_realtime(
                        model=model,
                        prompt=prompt,
                        model_class=analysis_schema_class,
                        chunk=chunk,
                        chunk_id=chunk_counter,
                        log_type=self.log_type,
                        response_language=self.response_language,
                        processing_mode=self.processing_mode,
                        sampling_threshold=self.sampling_threshold,
                        log_path=self.log_path,
                        access_mode=self.access_mode
                    )
                    
                    # Call custom callback if provided
                    if process_callback:
                        process_callback(result, chunk, chunk_counter)
                    
                    print(f"✅ FINAL CHUNK #{chunk_counter} COMPLETED")
                    
                except Exception as e:
                    print(f"❌ FINAL CHUNK #{chunk_counter} FAILED: {e}")
            
            print("=" * 50)
            print(f"🏁 TOTAL CHUNKS PROCESSED: {chunk_counter}")
            print("=" * 50)


def process_log_chunk_realtime(model, prompt, model_class, chunk, chunk_id, log_type, response_language, 
                              processing_mode=None, sampling_threshold=None, log_path=None, access_mode=None):
    """
    Simplified function to process log chunks for real-time monitoring
    
    Args:
        model: LLM model object
        prompt: Prompt for analysis
        model_class: Pydantic model class
        chunk: List of log lines
        chunk_id: Chunk ID
        log_type: Log type
        response_language: Response language
        processing_mode: Processing mode (full/sampling/auto-sampling)
        sampling_threshold: Sampling threshold for auto-sampling mode
        log_path: Log file path to include in metadata
        access_mode: Access mode (local/ssh) to include in metadata
    
    Returns:
        dict: Analysis result
    """
    try:
        # Record start time
        chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        
        # Run LLM analysis - provider-specific parameters
        if LLM_PROVIDER == "ollama":
            # Ollama는 temperature와 top_p를 지원하지 않음
            review = model(prompt, model_class)
        else:
            # OpenAI와 vLLM은 temperature와 top_p 지원
            review = model(
                prompt, 
                model_class,
                temperature=LLM_TEMPERATURE,
                top_p=LLM_TOP_P
            )
        
        # Record end time
        chunk_end_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        
        # Parse result - handle different response types
        if hasattr(review, 'model_dump'):
            # Pydantic v2 style
            parsed_data = review.model_dump()
        elif hasattr(review, 'dict'):
            # Pydantic v1 style
            parsed_data = review.dict()
        elif isinstance(review, dict):
            # Already a dictionary
            parsed_data = review
        else:
            # Try to convert to dict or handle as string
            try:
                if hasattr(review, '__dict__'):
                    parsed_data = review.__dict__
                else:
                    # If it's a string, try to parse as JSON
                    import json
                    if isinstance(review, str):
                        parsed_data = json.loads(review)
                    else:
                        raise ValueError(f"Unexpected response type: {type(review)}")
            except (json.JSONDecodeError, AttributeError, ValueError) as e:
                print(f"⚠️ Failed to parse LLM response: {e}")
                print(f"🔍 Response type: {type(review)}")
                print(f"🔍 Response content: {str(review)[:200]}...")
                # Create a minimal valid response
                parsed_data = {
                    "summary": f"Processing error: {str(e)}",
                    "events": [{
                        "event_type": "UNKNOWN",
                        "severity": "LOW",
                        "description": "Failed to parse LLM response",
                        "confidence_score": 0.1,
                        "recommended_actions": ["Review log processing"],
                        "requires_human_review": True,
                        "related_log_ids": []
                    }],
                    "statistics": {
                        "total_events": 1,
                        "auth_failures": 0,
                        "unique_ips": 0,
                        "unique_users": 0,
                        "event_by_type": {"UNKNOWN": 1},
                        "top_source_ips": {}
                    },
                    "highest_severity": "LOW",
                    "requires_immediate_attention": False
                }
        
        # Add metadata including processing mode information
        parsed_data.update({
            "@chunk_analysis_start_utc": chunk_start_time,
            "@chunk_analysis_end_utc": chunk_end_time,
            "@processing_result": "success",
            "@timestamp": chunk_end_time,
            "@log_type": log_type,
            "@document_id": f"{log_type}_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')}_chunk_{chunk_id}",
            "@log_count": len(chunk),
            "@log_raw_data": _create_log_hash_mapping_realtime(chunk),
            "@processing_mode": processing_mode if processing_mode else "unknown",
            "@sampling_threshold": sampling_threshold if sampling_threshold else None,
            "@access_mode": access_mode if access_mode else "local"
        })
        
        # 로그 파일 경로 추가 (선택사항)
        if log_path:
            parsed_data["@log_path"] = log_path
        
        # Send to Elasticsearch
        send_to_elasticsearch(parsed_data, log_type, chunk_id, chunk)
        
        return parsed_data
        
    except Exception as e:
        print(f"❌ Error in real-time processing: {e}")
        return None


def create_realtime_monitor(log_type: str, 
                          chunk_size: Optional[int] = None,
                          remote_mode: Optional[str] = None,
                          ssh_config: Optional[Dict[str, Any]] = None,
                          remote_log_path: Optional[str] = None) -> RealtimeLogMonitor:
    """
    Create a real-time log monitor for specified log type
    
    Args:
        log_type: Type of log to monitor
        chunk_size: Override default chunk size
        remote_mode: "local" or "ssh" (overrides config default)
        ssh_config: Custom SSH configuration dict (optional)
                   Example: {"host": "server1.example.com", "user": "admin", "key_path": "/path/to/key"}
        remote_log_path: Custom remote log path (optional)
    
    Returns:
        RealtimeLogMonitor: Configured monitor instance
    """
    config = get_analysis_config(
        log_type, 
        chunk_size, 
        analysis_mode="realtime",
        remote_mode=remote_mode,
        ssh_config=ssh_config,
        remote_log_path=remote_log_path
    )
    
    if not config["log_path"]:
        if config["access_mode"] == "ssh":
            raise ValueError(f"No remote log path configured for {log_type}. "
                           f"Provide remote_log_path parameter or set REMOTE_LOG_PATH_{log_type.upper()} in config")
        else:
            raise ValueError(f"No log path configured for {log_type}. "
                           f"Check LOG_PATH_REALTIME_{log_type.upper()} in config")
    
    return RealtimeLogMonitor(log_type, config)


def run_generic_batch_analysis(log_type: str, analysis_schema_class, prompt_template, analysis_title: str,
                             log_path: Optional[str] = None, chunk_size: Optional[int] = None,
                             remote_mode: Optional[str] = None, ssh_config: Optional[Dict[str, Any]] = None,
                             remote_log_path: Optional[str] = None):
    """
    Generic batch analysis function for all log types
    
    Args:
        log_type: Type of log ("httpd_access", "httpd_apache_error", "linux_system", "tcpdump_packet")
        analysis_schema_class: Pydantic schema class for structured output
        prompt_template: Prompt template string
        analysis_title: Title to display in output header
        log_path: Override log file path (for local files)
        chunk_size: Override chunk size
        remote_mode: "local" or "ssh" (overrides config default)
        ssh_config: Custom SSH configuration dict
        remote_log_path: Custom remote log path
    """
    print("=" * 70)
    print(f"LogSentinelAI - {analysis_title} (Batch Mode)")
    print("=" * 70)
    
    # Get LLM configuration
    llm_provider = LLM_PROVIDER
    llm_model_name = LLM_MODELS.get(LLM_PROVIDER, "unknown")
    
    # Get analysis configuration
    config = get_analysis_config(
        log_type,
        chunk_size=chunk_size,
        analysis_mode="batch",
        remote_mode=remote_mode,
        ssh_config=ssh_config,
        remote_log_path=remote_log_path
    )
    
    # Override log path if provided (for local files)
    if log_path and config["access_mode"] == "local":
        config["log_path"] = log_path
    
    print(f"Access mode:       {config['access_mode'].upper()}")
    print(f"Log file:          {config['log_path']}")
    print(f"Chunk size:        {config['chunk_size']}")
    print(f"Response language: {config['response_language']}")
    print(f"LLM Provider:      {llm_provider}")
    print(f"LLM Model:         {llm_model_name}")
    if config["access_mode"] == "ssh":
        ssh_info = config["ssh_config"]
        print(f"SSH Target:        {ssh_info.get('user', 'unknown')}@{ssh_info.get('host', 'unknown')}:{ssh_info.get('port', 22)}")
    print("=" * 70)
    
    log_path = config["log_path"]
    chunk_size = config["chunk_size"]
    response_language = config["response_language"]
    
    model = initialize_llm_model()
    
    with open(log_path, "r", encoding="utf-8") as f:
        for i, chunk in enumerate(chunked_iterable(f, chunk_size, debug=False)):
            # 분석 시작 시간 기록
            chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
            logs = "".join(chunk)
            model_schema = analysis_schema_class.model_json_schema()
            prompt = prompt_template.format(logs=logs, model_schema=model_schema, response_language=response_language)
            print(f"\n--- Chunk {i+1} ---")
            print_chunk_contents(chunk)
            
            # 공통 처리 함수 사용
            success, parsed_data = process_log_chunk(
                model=model,
                prompt=prompt,
                model_class=analysis_schema_class,
                chunk_start_time=chunk_start_time,
                chunk_end_time=None,  # 함수 내부에서 계산
                elasticsearch_index=log_type,
                chunk_number=i+1,
                chunk_data=chunk,
                llm_provider=llm_provider,
                llm_model=llm_model_name,
                processing_mode="batch",
                log_path=log_path,
                access_mode=config["access_mode"]
            )
            
            if success:
                print("✅ Analysis completed successfully")
            else:
                print("❌ Analysis failed")
                wait_on_failure(30)  # 실패 시 30초 대기
            
            print("-" * 50)


def run_generic_realtime_analysis(log_type: str, analysis_schema_class, prompt_template, analysis_title: str,
                                 chunk_size=None, log_path=None, processing_mode=None, sampling_threshold=None,
                                 remote_mode=None, ssh_config=None, remote_log_path=None):
    """
    Generic real-time analysis function for all log types
    
    Args:
        log_type: Type of log ("httpd_access", "httpd_apache_error", "linux_system", "tcpdump_packet")
        analysis_schema_class: Pydantic schema class for structured output
        prompt_template: Prompt template string
        analysis_title: Title to display in output header
        chunk_size: Override default chunk size
        log_path: Override default log file path (local mode only)
        processing_mode: Processing mode (full/sampling)
        sampling_threshold: Sampling threshold
        remote_mode: "local" or "ssh"
        ssh_config: SSH configuration dict
        remote_log_path: Remote log file path
    """
    print("=" * 70)
    print(f"LogSentinelAI - {analysis_title} (Real-time Mode)")
    print("=" * 70)
    
    # Override environment variables if specified
    if processing_mode:
        import os
        os.environ["REALTIME_PROCESSING_MODE"] = processing_mode
    if sampling_threshold:
        import os
        os.environ["REALTIME_SAMPLING_THRESHOLD"] = str(sampling_threshold)
    
    # Get configuration
    config = get_analysis_config(
        log_type, 
        chunk_size, 
        analysis_mode="realtime",
        remote_mode=remote_mode,
        ssh_config=ssh_config,
        remote_log_path=remote_log_path
    )
    
    # Override local log path if specified (for local mode only)
    if log_path and config["access_mode"] == "local":
        config["log_path"] = log_path
    
    print(f"Access mode:       {config['access_mode'].upper()}")
    print(f"Log file:          {config['log_path']}")
    print(f"Chunk size:        {config['chunk_size']}")
    print(f"Response language: {config['response_language']}")
    print(f"Analysis mode:     {config['analysis_mode']}")
    if config["access_mode"] == "ssh":
        ssh_info = config["ssh_config"]
        print(f"SSH Target:        {ssh_info.get('user', 'unknown')}@{ssh_info.get('host', 'unknown')}:{ssh_info.get('port', 22)}")
    
    # Initialize LLM model
    print("\nInitializing LLM model...")
    model = initialize_llm_model()
    
    # Create real-time monitor
    try:
        monitor = RealtimeLogMonitor(log_type, config)
    except ValueError as e:
        print(f"ERROR: Configuration error: {e}")
        print("Please check your configuration settings")
        return
    
    # Function to create analysis prompt
    def create_analysis_prompt(chunk, response_language):
        # Add LOGID prefix to each line for consistency with batch mode
        lines_with_logid = []
        for line in chunk:
            if line.strip():  # Skip empty lines
                # Generate LOGID for the line
                logid = f"LOGID-{hashlib.md5(line.strip().encode()).hexdigest().upper()}"
                # Add LOGID prefix to the line
                lines_with_logid.append(f"{logid} {line.strip()}\n")
        
        logs = "".join(lines_with_logid)
        model_schema = analysis_schema_class.model_json_schema()
        return prompt_template.format(
            logs=logs, 
            model_schema=model_schema, 
            response_language=response_language
        )
    
    # Default callback for processing results
    def process_result_callback(result, chunk, chunk_id):
        """Default callback to handle analysis results"""
        print(f"✅ Analysis complete for chunk {chunk_id}")
        
        if result and 'events' in result:
            event_count = len(result['events'])
            print(f"Found {event_count} security events")
            
            # Show high severity events
            high_severity_events = [
                event for event in result['events'] 
                if event.get('severity') in ['HIGH', 'CRITICAL']
            ]
            
            if high_severity_events:
                print(f"WARNING: HIGH/CRITICAL events: {len(high_severity_events)}")
                for event in high_severity_events:
                    print(f"   {event.get('event_type', 'UNKNOWN')}: {event.get('description', 'No description')}")
        
        print("-" * 40)
    
    # Start real-time monitoring
    try:
        monitor.monitor_and_analyze(
            model=model,
            analysis_prompt_func=create_analysis_prompt,
            analysis_schema_class=analysis_schema_class,
            process_callback=process_result_callback
        )
    except FileNotFoundError:
        print(f"ERROR: Log file not found: {config['log_path']}")
        print("NOTE: Make sure the log file exists and is readable")
        print("NOTE: You may need to run with appropriate permissions")
    except PermissionError:
        print(f"ERROR: Permission denied: {config['log_path']}")
        print("NOTE: You may need to run with sudo or adjust file permissions")
    except Exception as e:
        print(f"ERROR: Unexpected error: {e}")


def create_argument_parser(description: str):
    """
    Create a standard argument parser for all analysis scripts
    
    Args:
        description: Description for the argument parser
    
    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    import argparse
    parser = argparse.ArgumentParser(description=description)
    
    # Analysis mode
    parser.add_argument('--mode', choices=['batch', 'realtime'], default='batch',
                       help='Analysis mode: batch (default) or realtime')
    
    # Chunk configuration
    parser.add_argument('--chunk-size', type=int, default=None,
                       help='Override default chunk size')
    
    # Log file path (unified for local and remote)
    parser.add_argument('--log-path', type=str, default=None,
                       help='Log file path (local: /path/to/log, remote: /var/log/remote.log)')
    
    # Remote access configuration
    parser.add_argument('--remote', action='store_true',
                       help='Enable remote log access via SSH')
    parser.add_argument('--ssh', type=str, default=None,
                       help='SSH connection info: user@host[:port] (required with --remote)')
    parser.add_argument('--ssh-key', type=str, default=None,
                       help='SSH private key file path')
    parser.add_argument('--ssh-password', type=str, default=None,
                       help='SSH password (if no key file provided)')
    
    # Real-time processing configuration
    parser.add_argument('--processing-mode', choices=['full', 'sampling'], default=None,
                       help='Real-time processing mode: full (process all) or sampling (latest only)')
    parser.add_argument('--sampling-threshold', type=int, default=None,
                       help='Auto-switch to sampling if accumulated lines exceed this (only for full mode)')
    
    return parser


def parse_ssh_config_from_args(args) -> Optional[Dict[str, Any]]:
    """
    Parse SSH configuration from command line arguments
    
    Args:
        args: Parsed command line arguments
    
    Returns:
        Dict or None: SSH configuration dictionary or None if not remote mode
    """
    if not getattr(args, 'remote', False):
        return None
    
    ssh_config = {}
    
    # Parse SSH connection string (user@host[:port])
    if hasattr(args, 'ssh') and args.ssh:
        ssh_parts = args.ssh.split('@')
        if len(ssh_parts) != 2:
            raise ValueError("SSH format must be: user@host[:port]")
        
        user, host_port = ssh_parts
        ssh_config['user'] = user
        
        # Parse host and optional port
        if ':' in host_port:
            host, port = host_port.split(':', 1)
            ssh_config['host'] = host
            try:
                ssh_config['port'] = int(port)
            except ValueError:
                raise ValueError(f"Invalid SSH port: {port}")
        else:
            ssh_config['host'] = host_port
            ssh_config['port'] = 22  # Default port
    
    # Authentication method
    if hasattr(args, 'ssh_key') and args.ssh_key:
        ssh_config['key_path'] = args.ssh_key
    
    if hasattr(args, 'ssh_password') and args.ssh_password:
        ssh_config['password'] = args.ssh_password
    
    return ssh_config if ssh_config else None


def validate_args(args):
    """
    Validate command line arguments for consistency and requirements
    
    Args:
        args: Parsed command line arguments
    
    Raises:
        ValueError: If arguments are invalid or inconsistent
    """
    # Remote mode validation
    if getattr(args, 'remote', False):
        # SSH connection info is required
        if not getattr(args, 'ssh', None):
            raise ValueError("--ssh user@host[:port] is required when using --remote")
        
        # At least one authentication method is required
        if not getattr(args, 'ssh_key', None) and not getattr(args, 'ssh_password', None):
            raise ValueError("Either --ssh-key or --ssh-password is required with --remote")
        
        # Validate SSH format
        ssh = getattr(args, 'ssh', '')
        if '@' not in ssh:
            raise ValueError("SSH format must be: user@host[:port]")
    
    # Local mode validation
    else:
        # SSH options should not be used in local mode
        ssh_options = ['ssh', 'ssh_key', 'ssh_password']
        for opt in ssh_options:
            if getattr(args, opt, None):
                print(f"WARNING: --{opt.replace('_', '-')} is ignored in local mode")


def get_remote_mode_from_args(args) -> str:
    """
    Determine access mode from command line arguments
    
    Args:
        args: Parsed command line arguments
    
    Returns:
        str: "ssh" if remote mode, "local" otherwise
    """
    return "ssh" if getattr(args, 'remote', False) else "local"


def get_log_path_from_args(args) -> Optional[str]:
    """
    Get log path from command line arguments
    
    Args:
        args: Parsed command line arguments
    
    Returns:
        str or None: Log file path or None if not specified
    """
    return getattr(args, 'log_path', None)


def handle_ssh_arguments(args):
    """
    Handle SSH configuration setup from command line arguments
    
    Args:
        args: Parsed command line arguments
    
    Returns:
        dict or None: SSH configuration dictionary or None for local mode
    """
    if not getattr(args, 'remote', False):
        return None
    
    # Validate arguments
    validate_args(args)
    
    # Parse SSH configuration
    ssh_config = parse_ssh_config_from_args(args)
    return ssh_config


def create_ssh_client(ssh_config):
    """
    Create SSH client from configuration
    
    Args:
        ssh_config: SSH configuration dictionary
    
    Returns:
        paramiko.SSHClient or None: Connected SSH client or None if failed
    """
    if not ssh_config:
        return None
    
    try:
        import paramiko
        
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Prepare connection parameters
        connect_kwargs = {
            'hostname': ssh_config['host'],
            'port': ssh_config.get('port', 22),
            'username': ssh_config['user'],
            'timeout': 10
        }
        
        # Add authentication
        if 'key_path' in ssh_config:
            connect_kwargs['key_filename'] = ssh_config['key_path']
        elif 'password' in ssh_config:
            connect_kwargs['password'] = ssh_config['password']
        
        ssh_client.connect(**connect_kwargs)
        print(f"✓ SSH connection established to {ssh_config['user']}@{ssh_config['host']}:{ssh_config.get('port', 22)}")
        return ssh_client
        
    except Exception as e:
        print(f"✗ SSH connection failed: {e}")
        return None


def read_file_content(log_path: str, ssh_config=None) -> str:
    """
    Read file content either locally or via SSH
    
    Args:
        log_path: Path to the log file
        ssh_config: SSH configuration dictionary for remote access (optional)
    
    Returns:
        str: File content
    """
    if ssh_config:
        # Read via SSH
        ssh_client = create_ssh_client(ssh_config)
        if not ssh_client:
            raise Exception("Failed to establish SSH connection")
        
        try:
            sftp = ssh_client.open_sftp()
            with sftp.open(log_path, 'r') as f:
                content = f.read()
            sftp.close()
            ssh_client.close()
            return content
        except Exception as e:
            ssh_client.close()
            print(f"✗ Failed to read remote file {log_path}: {e}")
            raise
    else:
        # Read local file
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            print(f"✗ Failed to read local file {log_path}: {e}")
            raise
