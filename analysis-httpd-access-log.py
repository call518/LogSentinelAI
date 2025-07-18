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

class SecurityEvent(BaseModel):
    event_type: str = Field(description="보안 이벤트 유형")
    severity: SeverityLevel
    description: str = Field(description="이벤트 상세 설명")
    confidence_score: float = Field(ge=0.0, le=1.0, description="신뢰도 (0.0-1.0)")
    url_pattern: str = Field(description="관련 URL 패턴")
    http_method: str = Field(description="HTTP 메소드")
    source_ips: list[str] = Field(default=[], description="소스 IP 목록")
    response_codes: list[str] = Field(default=[], description="응답 코드 목록")
    attack_patterns: list[AttackType] = Field(default=[], description="탐지된 공격 패턴")
    recommended_actions: list[str] = Field(default=[], description="권장 조치사항")
    requires_human_review: bool = Field(description="인간 검토 필요 여부")
    related_log_ids: list[str] = Field(default=[], description="관련된 LOGID 목록 (예: ['LOGID-ABC123', 'LOGID-DEF456'])")

class Statistics(BaseModel):
    total_requests: int = Field(default=0, description="총 요청 수")
    unique_ips: int = Field(default=0, description="고유 IP 수")
    error_rate: float = Field(default=0.0, description="에러율 (0.0-1.0)")
    top_ips: dict[str, int] = Field(default={}, description="상위 요청 IP")
    response_code_dist: dict[str, int] = Field(default={}, description="응답 코드 분포")

class LogAnalysis(BaseModel):
    summary: str = Field(description="분석 요약")
    events: list[SecurityEvent] = Field(
        min_items=1,
        description="보안 이벤트 목록 - 반드시 1개 이상 포함"
    )
    statistics: Statistics = Field(description="통계 정보")
    highest_severity: SeverityLevel = Field(description="최고 심각도")
    requires_immediate_attention: bool = Field(description="즉시 주의 필요")
#--------------------------------------------------------------------------------------

# LLM 설정
llm_provider = "vllm"  # "ollama", "vllm", "openai" 중 선택
model = initialize_llm_model(llm_provider)

# log_path = "sample-logs/access-10.log" 
# log_path = "sample-logs/access-100.log"
log_path = "sample-logs/access-10k.log"

chunk_size = 5

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