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
from typing import Dict, Any, Optional
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, RequestError
from dotenv import load_dotenv
import outlines
import ollama
import openai

# Import prompt templates from prompts.py
from prompts import (
    PROMPT_TEMPLATE_HTTPD_ACCESS_LOG,
    PROMPT_TEMPLATE_HTTPD_APACHE_ERROR_LOG,
    PROMPT_TEMPLATE_LINUX_SYSTEM_LOG,
    PROMPT_TEMPLATE_TCPDUMP_PACKET
)

# .env 파일 로드
load_dotenv()

def initialize_llm_model(llm_provider="vllm"):
    """
    Initialize LLM model
    
    Args:
        llm_provider: Choose from "ollama", "vllm", "openai"
    
    Returns:
        initialized model object
    """
    if llm_provider == "ollama":
        ### Ollama API
        # llm_model = "mistral:7b"
        # llm_model = "qwen2.5-coder:0.5b"
        # llm_model = "qwen2.5-coder:1.5b"
        llm_model = "qwen2.5-coder:3b"
        # llm_model = "qwen2.5-coder:7b"
        # llm_model = "qwen3:0.6b"
        # llm_model = "qwen3:1.7b"
        # llm_model = "qwen3:4b"
        # llm_model = "qwen3:8b"
        # llm_model = "gemma3:1b"
        # llm_model = "gemma3:4b"
        # llm_model = "gemma3:12b"
        # llm_model = "call518/gemma3-tools-8192ctx:4b"
        client = ollama.Client()
        model = outlines.from_ollama(client, llm_model)
    elif llm_provider == "vllm":
        ### Local vLLM API
        openai_api_key = "dummy"
        # llm_model = "Qwen/Qwen2.5-0.5B-Instruct"
        llm_model = "Qwen/Qwen2.5-3B-Instruct"
        # llm_model = "gpt-4o"
        client = openai.OpenAI(
            base_url="http://127.0.0.1:5000/v1",  # Local vLLM API endpoint
            api_key=openai_api_key
        )
        model = outlines.from_openai(client, llm_model)
    elif llm_provider == "openai":
        ### OpenAI API
        openai_api_key = os.getenv("OPENAI_API_KEY")
        # llm_model = "gpt-4o-mini"
        llm_model = "gpt-4o"
        # llm_model = "gpt-4.1"
        client = openai.OpenAI(
            base_url="https://api.openai.com/v1",  # OpenAI API endpoint
            # base_url="http://127.0.0.1:11434/v1",  # Local Ollama API endpoint
            api_key=openai_api_key
        )
        model = outlines.from_openai(client, llm_model)
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
    print("✅ Wait completed, continuing with next chunk.")


def process_log_chunk(model, prompt, model_class, chunk_start_time, chunk_end_time, 
                     elasticsearch_index, chunk_number, chunk_data, llm_provider=None, llm_model=None):
    """
    Common function to process log chunks
    
    Args:
        model: LLM model object
        prompt: Prompt for analysis
        model_class: Pydantic model class
        chunk_start_time: Chunk analysis start time
        chunk_end_time: Chunk analysis completion time
        elasticsearch_index: Elasticsearch index name
        chunk_number: Chunk number
        chunk_data: Original chunk data
        llm_provider: LLM provider name (e.g., "ollama", "vllm", "openai")
        llm_model: LLM model name (e.g., "Qwen/Qwen2.5-3B-Instruct")
    
    Returns:
        (success: bool, parsed_data: dict or None)
    """
    try:
        review = model(prompt, model_class)
        
        # JSON 파싱
        parsed = json.loads(review)
        
        # 원본 로그 데이터를 LOGID -> 원본 내용 매핑으로 생성
        # chunked_iterable()에서 생성된 LOGID를 그대로 사용하여 일관성 유지
        log_raw_data = {}
        for line in chunk_data:
            line = line.strip()
            if line.startswith("LOGID-"):
                parts = line.split(" ", 1)
                logid = parts[0]
                # LOGID를 제거한 원본 로그 내용만 저장
                original_content = parts[1] if len(parts) > 1 else ""
                log_raw_data[logid] = original_content
        
        # 분석 시간 정보, LLM 정보, 원본 로그 데이터 추가
        parsed = {
            "@chunk_analysis_start_utc": chunk_start_time,
            "@chunk_analysis_end_utc": chunk_end_time,
            "@processing_result": "success",
            "@log_raw_data": log_raw_data,
            **parsed
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
        print(f"\n🔄 Sending data to Elasticsearch...")
        success = send_to_elasticsearch(parsed, elasticsearch_index, chunk_number, chunk_data)
        if success:
            print(f"✅ Chunk {chunk_number} data sent to Elasticsearch successfully")
        else:
            print(f"❌ Chunk {chunk_number} data failed to send to Elasticsearch")
        
        return True, parsed
        
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {e}")
        # Record minimal information on failure
        failure_data = {
            "@chunk_analysis_start_utc": chunk_start_time,
            "@chunk_analysis_end_utc": chunk_end_time,
            "@processing_result": "failed",
            "@error_type": "json_parse_error",
            "@error_message": str(e)[:200],  # Limit error message to 200 characters
            "@chunk_id": chunk_number
        }
        # LLM 정보 추가 (선택사항)
        if llm_provider:
            failure_data["@llm_provider"] = llm_provider
        if llm_model:
            failure_data["@llm_model"] = llm_model
        print(f"\n🔄 Sending failure information to Elasticsearch...")
        success = send_to_elasticsearch(failure_data, elasticsearch_index, chunk_number, chunk_data)
        if success:
            print(f"✅ Chunk {chunk_number} failure information sent to Elasticsearch successfully")
        else:
            print(f"❌ Chunk {chunk_number} failure information failed to send to Elasticsearch")
        return False, None
        
    except Exception as e:
        print(f"Analysis processing error: {e}")
        # Record minimal information on other failures
        failure_data = {
            "@chunk_analysis_start_utc": chunk_start_time,
            "@chunk_analysis_end_utc": chunk_end_time,
            "@processing_result": "failed",
            "@error_type": "processing_error",
            "@error_message": str(e)[:200],  # Limit error message to 200 characters
            "@chunk_id": chunk_number
        }
        # LLM 정보 추가 (선택사항)
        if llm_provider:
            failure_data["@llm_provider"] = llm_provider
        if llm_model:
            failure_data["@llm_model"] = llm_model
        print(f"\n🔄 Sending failure information to Elasticsearch...")
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

### Elasticsearch
ELASTICSEARCH_HOST = "http://localhost:9200"  # 일반적인 Elasticsearch 포트
ELASTICSEARCH_USER = os.getenv("ELASTICSEARCH_USER")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD")
ELASTICSEARCH_INDEX = "logsentinelai-analysis"

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
