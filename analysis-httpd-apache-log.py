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
from commons import initialize_llm_model
from commons import process_log_chunk

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
    client_ips: list[str] = Field(default=[], description="관련된 클라이언트 IP 목록")

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
    relevant_log_entry: list[LogEntry] = Field(default=[], description="관련된 로그 엔트리 목록")
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
    source_ips: list[str] = Field(default=[], description="관련된 클라이언트 IP 목록")
    possible_attack_patterns: list[str] = Field(default=[], description="가능한 공격 패턴 목록")
    recommended_actions: list[str] = Field(default=[], description="권장 조치사항")

### Top-level class for log analysis results
class LogAnalysis(BaseModel):
    summary: str
    observations: list[str] = Field(default=[], description="관찰사항 목록")
    planning: list[str] = Field(default=[], description="계획사항 목록")
    events: list[ApacheSecurityEvent] = Field(
        min_items=1,
        description="Security events found - MUST contain at least one event per chunk, never empty"
    )
    error_patterns: list[ErrorPattern] = Field(default=[], description="에러 패턴 목록")
    module_info: list[ApacheModuleInfo] = Field(default=[], description="모듈 정보 목록")
    statistics: Optional[Statistics]
    highest_severity: Optional[str] = Field(description="가장 높은 심각도 (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
    requires_immediate_attention: bool
#--------------------------------------------------------------------------------------

# LLM 설정
llm_provider = "vllm"  # "ollama", "vllm", "openai" 중 선택
model = initialize_llm_model(llm_provider)

# log_path = "sample-logs/apache-10.log"
# log_path = "sample-logs/apache-100.log"
log_path = "sample-logs/apache-10k.log"

chunk_size = 3

with open(log_path, "r", encoding="utf-8") as f:
    for i, chunk in enumerate(chunked_iterable(f, chunk_size, debug=False)):
        # 분석 시작 시간 기록
        chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        logs = "".join(chunk)
        model_schema = LogAnalysis.model_json_schema()
        prompt = PROMPT_TEMPLATE_HTTPD_APACHE_ERROR_LOG.format(logs=logs, model_schema=model_schema)
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
            elasticsearch_index="httpd_apache_error",
            chunk_number=i+1,
            chunk_data=chunk
        )