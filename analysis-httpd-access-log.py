import outlines
import ollama
import openai
from pydantic import BaseModel, Field
from enum import Enum
from typing import Literal, Optional
import json
import os
import sys
import datetime
import subprocess
from dotenv import load_dotenv

from commons import PROMPT_TEMPLATE_HTTPD_ACCESS_LOG
from commons import chunked_iterable
from commons import print_chunk_contents
from commons import send_to_elasticsearch

### Install the required packages
# uv add outlines ollama openai python-dotenv numpy

#---------------------------------- Enums and Models ----------------------------------
class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AttackType(str, Enum):
    BRUTE_FORCE = "BRUTE_FORCE"
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    FILE_INCLUSION = "FILE_INCLUSION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNKNOWN = "UNKNOWN"

class WebTrafficPattern(BaseModel):
    url_path: str
    http_method: str
    hits_count: int
    response_codes: Optional[dict[str, int]]
    unique_ips: int
    request_ips: list[str]

class Statistics(BaseModel):
    request_count_by_ip: Optional[dict[str, int]]
    request_count_by_url_path: Optional[dict[str, int]]

class IPAddress(BaseModel):
    ip_address: str

# Class for an HTTP response code.
class ResponseCode(BaseModel):
    response_code: str

class LogEntry(BaseModel):
    log_id: str
    log_message: str
    
class WebSecurityEvent(BaseModel):
    relevant_log_entry: list[LogEntry] = Field(description="관련된 로그 엔트리 목록")
    reasoning: str
    event_type: str
    severity: SeverityLevel
    requires_human_review: bool
    confidence_score: float = Field(
        ge=0.0, 
        le=1.0,
        description="Confidence score between 0.0 and 1.0 (e.g., 0.8 for 80% confidence, not 80)"
    )
    url_pattern: str = Field(
        min_length=1,
        description="URL pattern that triggered the event"
    )
    http_method: Literal["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
    source_ips: list[IPAddress]
    response_codes: list[ResponseCode]
    user_agents: list[str]
    possible_attack_patterns: list[AttackType]
    recommended_actions: list[str]
    
### Top-level class for log analysis results
class LogAnalysis(BaseModel):
    summary: str
    observations: list[str]
    planning: list[str]
    events: list[WebSecurityEvent]
    traffic_patterns: list[WebTrafficPattern]
    statistics: Optional[Statistics]
    highest_severity: Optional[SeverityLevel]
    requires_immediate_attention: bool
#--------------------------------------------------------------------------------------

# llm_provider = "ollama"
llm_provider = "vllm"
# llm_provider = "openai"

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
    llm_model = "vLLM-Qwen2.5-3B-Instruct"
    # llm_model = "gpt-4o"
    client = openai.OpenAI(
        base_url="http://127.0.0.1:5000/v1",  # Local vLLM API endpoint
        api_key=openai_api_key
    )
    model = outlines.from_openai(client, llm_model)
elif llm_provider == "openai":
    ### OpenAI API
    load_dotenv()
    openai_api_key = os.getenv("OPENAI_API_KEY")
    llm_model = "gpt-4o-mini"
    # llm_model = "gpt-4o"
    client = openai.OpenAI(
        base_url="https://api.openai.com/v1",  # OpenAI API endpoint
        # base_url="http://127.0.0.1:11434/v1",  # Local Ollama API endpoint
        api_key=openai_api_key
    )
    model = outlines.from_openai(client, llm_model)
else:
    raise ValueError("Unsupported LLM provider. Use 'ollama' or 'openai'.")

# log_path = "sample-logs/access-10.log" 
log_path = "sample-logs/access-100.log"
# log_path = "sample-logs/access-10k.log"

chunk_size = 10

with open(log_path, "r", encoding="utf-8") as f:
    for i, chunk in enumerate(chunked_iterable(f, chunk_size, debug=False)):
        # 분석 시작 시간 기록
        chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        logs = "".join(chunk)
        model_schema=LogAnalysis.model_json_schema()
        prompt = PROMPT_TEMPLATE_HTTPD_ACCESS_LOG.format(logs=logs, model_schema=model_schema)
        print(f"\n--- Chunk {i+1} ---")
        print_chunk_contents(chunk)
        review = model(
            prompt,
            LogAnalysis
        )
        # 분석 완료 시간 기록
        chunk_end_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        ### [Validate] Parse the review and print the character
        try:
            # print(review)
            ### Validate JSON
            parsed = json.loads(review)
            # 분석 시간 정보 추가
            parsed = {
                "chunk_analysis_start_utc": chunk_start_time,
                "chunk_analysis_end_utc": chunk_end_time,
                **parsed
            }
            
            print(json.dumps(parsed, ensure_ascii=False, indent=4))
            # json_str = json.dumps(parsed, ensure_ascii=False)
            # subprocess.run(['jq', '--color-output', '.'], input=json_str, text=True, stdout=sys.stdout)
            
            ### Validate Type
            character = LogAnalysis.model_validate(parsed)
            # print(character)
            
            # Send to Elasticsearch
            print(f"\n🔄 Elasticsearch로 데이터 전송 중...")
            success = send_to_elasticsearch(parsed, "httpd_access", i+1, chunk)
            if success:
                print(f"✅ Chunk {i+1} 데이터 Elasticsearch 전송 완료")
            else:
                print(f"❌ Chunk {i+1} 데이터 Elasticsearch 전송 실패")
                
        except Exception as e:
            print("Error parsing character:", e)