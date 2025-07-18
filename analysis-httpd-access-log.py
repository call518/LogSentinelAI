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
from commons import initialize_llm_model
from commons import process_log_chunk

### Install the required packages
# uv add outlines ollama openai python-dotenv numpy

#---------------------------------- Enums and Models ----------------------------------
class SeverityLevel(str, Enum):
    """
    Severity levels for HTTP Access Log security events (MORE SENSITIVE):
    - CRITICAL: Confirmed successful attacks with system compromise
    - HIGH: Strong attack indicators with high confidence
    - MEDIUM: Suspicious patterns requiring investigation
    - LOW: Minor anomalies worth noting (single errors, unusual patterns)
    - INFO: Any deviation from normal web traffic (4xx/5xx codes, POST requests, parameters)
    
    For HTTP access logs, be generous with INFO/LOW events to provide better visibility.
    """
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
    relevant_log_entry: list[LogEntry] = Field(default=[], description="관련된 로그 엔트리 목록")
    reasoning: str
    event_type: str
    severity: SeverityLevel = Field(
        description="Severity level - Be generous with INFO/LOW events for HTTP access logs. Most unusual patterns should generate events."
    )
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
    events: list[WebSecurityEvent] = Field(
        min_items=1,
        description="Security events found - MUST contain at least one event per chunk, never empty"
    )
    traffic_patterns: list[WebTrafficPattern]
    statistics: Optional[Statistics]
    highest_severity: Optional[SeverityLevel] = Field(
        description="Highest severity found in this analysis - should reflect actual threat assessment"
    )
    requires_immediate_attention: bool
#--------------------------------------------------------------------------------------

# LLM 설정
llm_provider = "vllm"  # "ollama", "vllm", "openai" 중 선택
model = initialize_llm_model(llm_provider)

# log_path = "sample-logs/access-10.log" 
# log_path = "sample-logs/access-100.log"
log_path = "sample-logs/access-10k.log"

chunk_size = 3

with open(log_path, "r", encoding="utf-8") as f:
    for i, chunk in enumerate(chunked_iterable(f, chunk_size, debug=False)):
        # 분석 시작 시간 기록
        chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        logs = "".join(chunk)
        model_schema = LogAnalysis.model_json_schema()
        prompt = PROMPT_TEMPLATE_HTTPD_ACCESS_LOG.format(logs=logs, model_schema=model_schema)
        print(f"\n--- Chunk {i+1} ---")
        print_chunk_contents(chunk)
        
        # 분석 완료 시간 기록
        chunk_end_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        
        # 공통 처리 함수 사용
        success, parsed_data = process_log_chunk(
            model=model,
            prompt=prompt,
            model_class=LogAnalysis,
            chunk_start_time=chunk_start_time,
            chunk_end_time=chunk_end_time,
            elasticsearch_index="httpd_access",
            chunk_number=i+1,
            chunk_data=chunk
        )