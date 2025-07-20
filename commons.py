# CUSTOME_PROMPT_TEMPLATE = """
# You are a computer security intern that's really stressed out.
# Your job is hard and you're not sure you're doing it well.
# Your observations and summaries should reflect your anxiety.
# Convey a sense of urgency and panic, be apologetic, and generally act like you're not sure you can do your job.
# In your summary, address your boss as "boss" and apologize for any mistakes you've made even if you haven't made any. 
# Use "um" and "ah" a lot.
# """

import json
import datetime
import os
import time
import hashlib
from typing import Dict, Any, Optional, List, Generator
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, RequestError
from dotenv import load_dotenv
import outlines
import ollama
import openai

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

# Default Chunk Sizes - Read from config file (can be overridden by individual analysis scripts)
LOG_CHUNK_SIZES = {
    "httpd_access": int(os.getenv("CHUNK_SIZE_HTTPD_ACCESS", "10")),
    "httpd_apache_error": int(os.getenv("CHUNK_SIZE_HTTPD_APACHE_ERROR", "10")),
    "linux_system": int(os.getenv("CHUNK_SIZE_LINUX_SYSTEM", "10")),
    "tcpdump_packet": int(os.getenv("CHUNK_SIZE_TCPDUMP_PACKET", "5"))
}

def get_llm_config():
    """
    Get current LLM configuration
    
    Returns:
        tuple: (llm_provider, llm_model_name)
    """
    llm_model_name = LLM_MODELS.get(LLM_PROVIDER, "unknown")
    return LLM_PROVIDER, llm_model_name

def get_analysis_config(log_type, chunk_size=None, analysis_mode=None):
    """
    Get analysis configuration for specific log type
    
    Args:
        log_type: Log type ("httpd_access", "httpd_apache_error", "linux_system", "tcpdump_packet")
        chunk_size: Override chunk size (optional)
        analysis_mode: Override analysis mode (optional) - "batch" or "realtime"
    
    Returns:
        dict: Configuration containing log_path, chunk_size, response_language, analysis_mode
    """
    mode = analysis_mode if analysis_mode is not None else ANALYSIS_MODE
    
    if mode == "realtime":
        log_path = REALTIME_LOG_PATHS.get(log_type, "")
    else:
        log_path = LOG_PATHS.get(log_type, "")
    
    config = {
        "log_path": log_path,
        "chunk_size": chunk_size if chunk_size is not None else LOG_CHUNK_SIZES.get(log_type, 3),
        "response_language": RESPONSE_LANGUAGE,
        "analysis_mode": mode,
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
        model = outlines.from_ollama(client, llm_model_name)
    elif llm_provider == "vllm":
        ### Local vLLM API
        openai_api_key = "dummy"
        client = openai.OpenAI(
            base_url="http://127.0.0.1:5000/v1",  # Local vLLM API endpoint
            api_key=openai_api_key
        )
        model = outlines.from_openai(client, llm_model_name)
    elif llm_provider == "openai":
        ### OpenAI API
        openai_api_key = os.getenv("OPENAI_API_KEY")
        client = openai.OpenAI(
            base_url="https://api.openai.com/v1",  # OpenAI API endpoint
            # base_url="http://127.0.0.1:11434/v1",  # Local Ollama API endpoint
            api_key=openai_api_key
        )
        model = outlines.from_openai(client, llm_model_name)
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
                     processing_mode=None):
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
    
    Returns:
        (success: bool, parsed_data: dict or None)
    """
    try:
        review = model(prompt, model_class)
        
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
            "@processing_mode": processing_mode if processing_mode else "batch"
        }
        
        # LLM 정보 추가 (선택사항)
        if llm_provider:
            parsed["@llm_provider"] = llm_provider
        if llm_model:
            parsed["@llm_model"] = llm_model
        
        print(json.dumps(parsed, ensure_ascii=False, indent=4))
        
        # Pydantic 모델 검증
        character = model_class.model_validate(parsed)
        
        # Send to Elasticsearch
        print(f"\nSending data to Elasticsearch...")
        success = send_to_elasticsearch(parsed, elasticsearch_index, chunk_number, chunk_data)
        if success:
            print(f"SUCCESS: Chunk {chunk_number} data sent to Elasticsearch successfully")
        else:
            print(f"ERROR: Chunk {chunk_number} data failed to send to Elasticsearch")
        
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
        print(f"\nSending failure information to Elasticsearch...")
        success = send_to_elasticsearch(failure_data, elasticsearch_index, chunk_number, chunk_data)
        if success:
            print(f"SUCCESS: Chunk {chunk_number} failure information sent to Elasticsearch successfully")
        else:
            print(f"ERROR: Chunk {chunk_number} failure information failed to send to Elasticsearch")
        return False, None
        
    except Exception as e:
        print(f"Analysis processing error: {e}")
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
        print(f"\nSending failure information to Elasticsearch...")
        success = send_to_elasticsearch(failure_data, elasticsearch_index, chunk_number, chunk_data)
        if success:
            print(f"SUCCESS: Chunk {chunk_number} failure information sent to Elasticsearch successfully")
        else:
            print(f"ERROR: Chunk {chunk_number} failure information failed to send to Elasticsearch")
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
    # Chunk 내용 출력 (/w LOGID, 순번, 분리)
    print(f"\n[LOG DATA]")
    for idx, line in enumerate(chunk, 1):
        line = line.strip()
        # LOGID-문자열 추출 (시작 부분)
        if line.startswith("LOGID-"):
            body = line.split(" ", 1)
            logid = body[0]
            rest = body[1] if len(body) > 1 else ""
        else:
            logid = "UNKNOWN-LOGID"
            rest = line
        
        # tcpdump 데이터인 경우 \\n을 실제 개행 문자로 변환하여 출력
        if "\\n" in rest:
            # 멀티라인 tcpdump 데이터를 보기 좋게 출력
            multiline_content = rest.replace('\\n', '\n')
            print(f"{logid} {multiline_content}")
        else:
            # 일반 싱글라인 데이터
            print(f"{logid} {rest}")
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

def _extract_log_content_from_logid_line(logid_line: str) -> tuple[str, str]:
    """
    Separate LOGID and original log content from a line containing LOGID.
    
    Args:
        logid_line: String in the format "LOGID-{HASH} {original_log_content}"
    
    Returns:
        tuple: (logid, original_log_content)
    """
    if logid_line.startswith("LOGID-"):
        parts = logid_line.split(" ", 1)
        logid = parts[0]
        original_content = parts[1] if len(parts) > 1 else ""
        return logid, original_content
    else:
        return "UNKNOWN-LOGID", logid_line

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


def _create_log_hash_mapping(chunk: list[str]) -> Dict[str, str]:
    """
    Create LOGID -> original log content mapping for all logs in the chunk.
    
    Args:
        chunk: List of log lines containing LOGID
    
    Returns:
        Dict[str, str]: {logid: original_content} mapping
    """
    mapping = {}
    for line in chunk:
        logid, original_content = _extract_log_content_from_logid_line(line.strip())
        mapping[logid] = original_content
    return mapping

def send_to_elasticsearch(analysis_data: Dict[str, Any], log_type: str, chunk_id: Optional[int] = None, chunk: Optional[list] = None) -> bool:
    """
    Integrated function to format analysis results and send them to Elasticsearch.
    
    Args:
        analysis_data: Analysis result data
        log_type: Log type ("httpd_access", "httpd_apache_error", "linux_system")
        chunk_id: Chunk number (optional)
        chunk: Original log chunk (currently not used, maintained for compatibility)
    
    Returns:
        bool: Whether transmission was successful
    """
    # log_hash_mapping removed to reduce token waste
    # Can be managed separately if needed
    # if chunk:
    #     log_hash_mapping = _create_log_hash_mapping(chunk)
    #     analysis_data["log_hash_mapping"] = log_hash_mapping
    #     print(f"📝 Added {len(log_hash_mapping)} log hash mapping entries")
    
    # Send to Elasticsearch
    return _send_to_elasticsearch(analysis_data, log_type, chunk_id)


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
        self.last_position = self._load_position()
        
        # Display initialization info in a clean format
        print("=" * 80)
        print(f"REALTIME LOG MONITOR INITIALIZED")
        print("=" * 80)
        print(f"Log Type:         {log_type}")
        print(f"Monitoring:       {self.log_path}")
        print(f"Mode:             {self.processing_mode.upper()}")
        if self.processing_mode == "full":
            print(f"Auto-sampling:    {self.sampling_threshold} lines threshold")
        elif self.processing_mode == "sampling":
            print(f"Sampling:         Always keep latest {self.chunk_size} lines")
        print(f"Poll Interval:    {self.realtime_config['polling_interval']}s")
        print(f"Chunk Size:       {self.chunk_size} lines")
        print("=" * 80)
    
    def _load_position(self) -> int:
        """Load last read position from position file"""
        try:
            if os.path.exists(self.position_file):
                with open(self.position_file, 'r') as f:
                    position = int(f.read().strip())
                    print(f"Loaded position: {position}")
                    return position
        except (ValueError, IOError) as e:
            print(f"WARNING: Error loading position file: {e}")
        
        # If file doesn't exist or error, start from end of file
        try:
            if os.path.exists(self.log_path):
                with open(self.log_path, 'rb') as f:
                    f.seek(0, 2)  # Seek to end
                    position = f.tell()
                    print(f"📍 Starting from end of file: {position}")
                    return position
        except IOError as e:
            print(f"WARNING: Error accessing log file: {e}")
        
        return 0
    
    def _save_position(self, position: int):
        """Save current read position to position file"""
        try:
            with open(self.position_file, 'w') as f:
                f.write(str(position))
        except IOError as e:
            print(f"WARNING: Error saving position: {e}")
    
    def _read_new_lines(self) -> List[str]:
        """Read new lines from log file since last position"""
        try:
            if not os.path.exists(self.log_path):
                return []
            
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
                
                # Update position
                if complete_lines:
                    # Only update position if we have complete lines
                    self.last_position = new_position - len(lines[-1]) if not new_content.endswith('\n') else new_position
                    self._save_position(self.last_position)
                
                # Filter out empty lines
                complete_lines = [line.strip() for line in complete_lines if line.strip()]
                
                if complete_lines:
                    # More concise output
                    pass  # Remove verbose output here
                
                return complete_lines
                
        except IOError as e:
            print(f"WARNING: Error reading log file: {e}")
            return []
    
    def get_new_log_chunks(self) -> Generator[List[str], None, None]:
        """
        Generator that yields chunks of new log lines
        Only yields when chunk_size lines are accumulated
        Supports both full processing and sampling modes
        
        Yields:
            List[str]: Chunk of new log lines (exactly chunk_size or remaining at end)
        """
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
                        # Truncate long lines for better readability
                        display_line = line[:100] + "..." if len(line) > 100 else line
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
                            sampling_threshold=self.sampling_threshold
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
                    display_line = line[:100] + "..." if len(line) > 100 else line
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
                        sampling_threshold=self.sampling_threshold
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
                              processing_mode=None, sampling_threshold=None):
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
    
    Returns:
        dict: Analysis result
    """
    try:
        # Record start time
        chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        
        # Run LLM analysis
        review = model(prompt, model_class)
        
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
            "@sampling_threshold": sampling_threshold if sampling_threshold else None
        })
        
        # Send to Elasticsearch
        send_to_elasticsearch(parsed_data, log_type, chunk_id, chunk)
        
        return parsed_data
        
    except Exception as e:
        print(f"❌ Error in real-time processing: {e}")
        return None


def create_realtime_monitor(log_type: str, 
                          chunk_size: Optional[int] = None) -> RealtimeLogMonitor:
    """
    Create a real-time log monitor for specified log type
    
    Args:
        log_type: Type of log to monitor
        chunk_size: Override default chunk size
    
    Returns:
        RealtimeLogMonitor: Configured monitor instance
    """
    config = get_analysis_config(log_type, chunk_size, analysis_mode="realtime")
    
    if not config["log_path"]:
        raise ValueError(f"No real-time log path configured for {log_type}")
    
    return RealtimeLogMonitor(log_type, config)
