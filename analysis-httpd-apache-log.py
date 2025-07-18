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
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AttackType(str, Enum):
    DIRECTORY_TRAVERSAL = "DIRECTORY_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    FILE_INCLUSION = "FILE_INCLUSION"
    INVALID_HTTP_METHOD = "INVALID_HTTP_METHOD"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    MODULE_ERROR = "MODULE_ERROR"
    UNKNOWN = "UNKNOWN"

class ApacheSecurityEvent(BaseModel):
    event_type: str = Field(description="보안 이벤트 유형")
    severity: SeverityLevel
    description: str = Field(description="이벤트 상세 설명")
    confidence_score: float = Field(ge=0.0, le=1.0, description="신뢰도 (0.0-1.0)")
    log_level: str = Field(description="Apache 로그 레벨")
    error_message: str = Field(description="에러 메시지")
    file_path: Optional[str] = Field(default=None, description="관련 파일 경로")
    source_ips: list[str] = Field(default=[], description="소스 IP 목록")
    attack_patterns: list[AttackType] = Field(default=[], description="탐지된 공격 패턴")
    recommended_actions: list[str] = Field(default=[], description="권장 조치사항")
    requires_human_review: bool = Field(description="인간 검토 필요 여부")

class Statistics(BaseModel):
    total_errors: int = Field(default=0, description="총 에러 수")
    error_by_level: dict[str, int] = Field(default={}, description="레벨별 에러 수")
    error_by_type: dict[str, int] = Field(default={}, description="유형별 에러 수")
    top_error_ips: dict[str, int] = Field(default={}, description="상위 에러 IP")

class LogAnalysis(BaseModel):
    summary: str = Field(description="분석 요약")
    events: list[ApacheSecurityEvent] = Field(
        min_items=1,
        description="보안 이벤트 목록 - 반드시 1개 이상 포함"
    )
    statistics: Statistics = Field(description="통계 정보")
    highest_severity: SeverityLevel = Field(description="최고 심각도")
    requires_immediate_attention: bool = Field(description="즉시 주의 필요")
#--------------------------------------------------------------------------------------
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