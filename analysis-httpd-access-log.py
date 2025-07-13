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

from commons import PROMPT_TEMPLATE
from commons import chunked_iterable
from commons import format_log_analysis
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

class WebSecurityEvent(BaseModel):
    # The log entry IDs that are relevant to this event.
    relevant_log_entry_ids: list[LogID]

    # The reasoning for why this event is relevant.
    reasoning: str

    # The type of event.
    event_type: str

    # The severity of the event.
    severity: SeverityLevel

    # Whether this event requires human review.
    requires_human_review: bool

    # The confidence score for this event. I'm not sure if this
    # is meaningful for language models, but it's here if we want it.
    confidence_score: float = Field(
        ge=0.0, 
        le=1.0,
        description="Confidence score between 0 and 1"
    )

    # Web-specific fields
    url_pattern: str = Field(
        min_length=1,
        description="URL pattern that triggered the event"
    )

    http_method: Literal["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
    source_ips: list[IPAddress]
    response_codes: list[ResponseCode]
    user_agents: list[str]

    # Possible attack patterns for this event.
    possible_attack_patterns: list[AttackType]

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
    events: list[WebSecurityEvent]
    
    # # Traffic patterns found in the logs.
    traffic_patterns: list[WebTrafficPattern]
    
    # # Statistics for the logs.
    statistics: Optional[Statistics]
    
    # # The highest severity event found.
    highest_severity: Optional[SeverityLevel]
    
    requires_immediate_attention: bool
#--------------------------------------------------------------------------------------

# llm_provider = "ollama"
llm_provider = "openai"

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
log_path = "sample-logs/access-100.log"
# log_path = "sample-logs/access-10k.log"
chunk_size = 10

with open(log_path, "r", encoding="utf-8") as f:
    for i, chunk in enumerate(chunked_iterable(f, chunk_size, debug=False)):
        # 분석 시작 시간 기록
        chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        logs = "".join(chunk)
        model_schema=LogAnalysis.model_json_schema()
        prompt = PROMPT_TEMPLATE.format(logs=logs, model_schema=model_schema)
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
            format_log_analysis(character, chunk)
        except Exception as e:
            print("Error parsing character:", e)