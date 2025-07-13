import outlines
import ollama
import openai
from pydantic import BaseModel, Field
from enum import Enum
from typing import Literal, Optional
import json
import uuid
import os
import sys
import datetime
import subprocess
from dotenv import load_dotenv

from commons import PROMPT_TEMPLATE_HTTPD_APACHE_ERROR_LOG
from commons import chunked_iterable
from commons import format_log_analysis_httpd_apache_error_log
from commons import print_chunk_contents

### Install the required packages
# pip install outlines ollama openai python-dotenv numpy

#---------------------------------- Enums and Models ----------------------------------
class LogID(BaseModel):
    log_id: str = Field(
        description="""
        The ID of the log entry in the format of LOGID-<LETTERS>, where <LETTERS> indicates the log identifier at the beginning of each log entry and consists of uppercase alphabet letters only (A–Z, no digits).
        i.e. LOGID-KUHYQIPUYT or LOGID-ATCHSKCUWP
        """,
        # This is a regular expression that matches the LOGID-<LETTERS> format.
        # The model will fill in the <LETTERS> part.
    )
    # Find the log entry in a list of logs. Simple
    # conveience function.
    def find_in(self, logs: list[str]) -> Optional[str]:
        for log in logs:
            if self.log_id in log:
                return log
        return None

class SeverityLevel(str, Enum):
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

class ApacheSecurityEvent(BaseModel):
    # The log entry IDs that are relevant to this event.
    relevant_log_entry_ids: list[str] = Field(description="관련된 로그 엔트리 ID 목록")

    # The reasoning for why this event is relevant.
    reasoning: str

    # The type of event.
    event_type: str

    # The severity of the event.
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, INFO 중 하나")

    # Whether this event requires human review.
    requires_human_review: bool

    # The confidence score for this event.
    confidence_score: float = Field(
        ge=0.0, 
        le=1.0,
        description="Confidence score between 0 and 1"
    )

    # Apache error log specific fields
    log_level: str = Field(description="Apache 로그 레벨 (error, notice, warn, info)")
    error_message: str = Field(description="에러 메시지 내용")
    file_path: Optional[str] = Field(description="관련된 파일 경로")
    source_ips: list[str] = Field(description="관련된 클라이언트 IP 목록")

    # Possible attack patterns for this event.
    possible_attack_patterns: list[str] = Field(description="가능한 공격 패턴 목록")

    # Recommended actions for this event.
    recommended_actions: list[str]

### Top-level class for log analysis results
class LogAnalysis(BaseModel):
    # # A summary of the analysis.
    summary: str
    
    # # Observations about the logs.
    observations: list[str]
    
    # # Planning for the analysis.
    planning: list[str]
    
    # # Security events found in the logs.
    events: list[ApacheSecurityEvent]
    
    # # Error patterns found in the logs.
    error_patterns: list[ErrorPattern]
    
    # # Apache module information
    module_info: list[ApacheModuleInfo]
    
    # # Statistics for the logs.
    statistics: Optional[Statistics]
    
    # # The highest severity event found.
    highest_severity: Optional[str] = Field(description="가장 높은 심각도 (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
    
    requires_immediate_attention: bool
#--------------------------------------------------------------------------------------

llm_provider = "ollama"
# llm_provider = "openai"

if llm_provider == "ollama":
    ### Ollama API
    # llm_model = "mistral:7b"
    llm_model = "qwen2.5-coder:3b"
    # llm_model = "qwen2.5-coder:7b"
    # llm_model = "gemma3:1b"
    # llm_model = "gemma3:4b"
    # llm_model = "gemma3:12b"
    # llm_model = "call518/gemma3-tools-8192ctx:4b"
    client = ollama.Client()
    model = outlines.from_ollama(client, llm_model)
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

# log_path = "sample-logs/access-5.log" 
# log_path = "sample-logs/access-10.log" 
# log_path = "sample-logs/access-100.log"
# log_path = "sample-logs/access-10k.log"
log_path = "sample-logs/apache-100.log"
chunk_size = 10

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
            # print(json.dumps(parsed, ensure_ascii=False, indent=4))
            # jq 명령어를 이용해 컬러/포맷 출력 (컬러 강제)
            json_str = json.dumps(parsed, ensure_ascii=False)
            subprocess.run(['jq', '--color-output', '.'], input=json_str, text=True, stdout=sys.stdout)
            ### Validate Type
            character = LogAnalysis.model_validate(parsed)
            # print(character)
            
            # Format and print the log analysis
            format_log_analysis_httpd_apache_error_log(character, chunk)
        except Exception as e:
            print("Error parsing character:", e)