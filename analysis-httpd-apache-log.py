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

from commons import PROMPT_TEMPLATE_HTTPD_APACHE_ERROR_LOG
from commons import chunked_iterable
from commons import print_chunk_contents
from commons import send_to_elasticsearch

### Install the required packages
# uv add outlines ollama openai python-dotenv numpy

#---------------------------------- Enums and Models ----------------------------------
class SeverityLevel(str, Enum):
    """
    Severity levels for security events (BALANCED APPROACH):
    - CRITICAL: Confirmed successful attacks with system compromise
    - HIGH: Strong attack indicators with high confidence and potential damage
    - MEDIUM: Suspicious patterns warranting investigation (use for legitimate security concerns)
    - LOW: Minor anomalies or isolated security events
    - INFO: Normal error events and routine activities
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class LogLevel(str, Enum):
    """Apache log levels"""
    ERROR = "error"
    WARN = "warn"
    NOTICE = "notice"
    INFO = "info"
    DEBUG = "debug"

class AttackType(str, Enum):
    DIRECTORY_TRAVERSAL = "DIRECTORY_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    FILE_INCLUSION = "FILE_INCLUSION"
    INVALID_HTTP_METHOD = "INVALID_HTTP_METHOD"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    REPEATED_REQUESTS = "REPEATED_REQUESTS"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    MODULE_ERROR = "MODULE_ERROR"
    UNKNOWN = "UNKNOWN"

class ErrorPattern(BaseModel):
    """Apache error log에서 발견되는 에러 패턴"""
    error_type: str = Field(description="에러 유형 (예: Directory index forbidden, File does not exist)")
    file_path: Optional[str] = Field(description="관련된 파일 경로")
    occurrences: int = Field(description="발생 횟수")
    client_ips: list[str] = Field(description="관련된 클라이언트 IP 목록")

class ApacheModuleInfo(BaseModel):
    """Apache 모듈 관련 정보"""
    module_name: str = Field(description="모듈 이름")
    operation: str = Field(description="모듈 작업 (예: init, configured)")
    status: str = Field(description="상태 (예: ok, error)")

class Statistics(BaseModel):
    error_count_by_ip: Optional[dict[str, int]] = Field(description="IP별 에러 발생 수")
    error_count_by_type: Optional[dict[str, int]] = Field(description="에러 유형별 발생 수")
    log_level_distribution: Optional[dict[str, int]] = Field(description="로그 레벨별 분포")

class IPAddress(BaseModel):
    ip_address: str

class LogEntry(BaseModel):
    log_id: str
    log_message: str

class ApacheSecurityEvent(BaseModel):
    relevant_log_entry: list[LogEntry] = Field(description="관련된 로그 엔트리 목록")
    reasoning: str
    event_type: str
    severity: SeverityLevel = Field(
        description="Severity level - Use balanced judgment based on error patterns and potential security impact"
    )
    requires_human_review: bool
    confidence_score: float = Field(
        ge=0.0, 
        le=1.0,
        description="Confidence score between 0 and 1"
    )
    log_level: str = Field(description="Apache 로그 레벨 (error, notice, warn, info)")
    error_message: str = Field(description="에러 메시지 내용")
    file_path: Optional[str] = Field(description="관련된 파일 경로")
    source_ips: list[str] = Field(description="관련된 클라이언트 IP 목록")
    possible_attack_patterns: list[str] = Field(description="가능한 공격 패턴 목록")
    recommended_actions: list[str]

### Top-level class for log analysis results
class LogAnalysis(BaseModel):
    summary: str
    observations: list[str]
    planning: list[str]
    events: list[ApacheSecurityEvent] = Field(
        min_items=1,
        description="Security events found - MUST contain at least one event per chunk, never empty"
    )
    error_patterns: list[ErrorPattern]
    module_info: list[ApacheModuleInfo]
    statistics: Optional[Statistics]
    highest_severity: Optional[str] = Field(description="가장 높은 심각도 (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
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

# log_path = "sample-logs/apache-10.log"
# log_path = "sample-logs/apache-100.log"
log_path = "sample-logs/apache-10k.log"

chunk_size = 5

with open(log_path, "r", encoding="utf-8") as f:
    for i, chunk in enumerate(chunked_iterable(f, chunk_size, debug=False)):
        # 분석 시작 시간 기록
        chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        logs = "".join(chunk)
        model_schema=LogAnalysis.model_json_schema()
        prompt = PROMPT_TEMPLATE_HTTPD_APACHE_ERROR_LOG.format(logs=logs, model_schema=model_schema)
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
            success = send_to_elasticsearch(parsed, "httpd_apache_error", i+1, chunk)
            if success:
                print(f"✅ Chunk {i+1} 데이터 Elasticsearch 전송 완료")
            else:
                print(f"❌ Chunk {i+1} 데이터 Elasticsearch 전송 실패")
                
        except Exception as e:
            print("Error parsing character:", e)