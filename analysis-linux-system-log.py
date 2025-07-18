from pydantic import BaseModel, Field
from enum import Enum
from typing import Literal, Optional
import json
import os
import sys
import datetime
import subprocess
from dotenv import load_dotenv

from commons import PROMPT_TEMPLATE_LINUX_SYSTEM_LOG
from commons import chunked_iterable
from commons import print_chunk_contents
from commons import send_to_elasticsearch
from commons import initialize_llm_model
from commons import process_log_chunk

### Install the required packages
# uv add outlines ollama openai python-dotenv numpy

#---------------------- Linux System Log용 Enums 및 Models ----------------------
class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class EventType(str, Enum):
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    SESSION_EVENT = "SESSION_EVENT"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    SUDO_USAGE = "SUDO_USAGE"
    CRON_JOB = "CRON_JOB"
    SYSTEM_EVENT = "SYSTEM_EVENT"
    USER_MANAGEMENT = "USER_MANAGEMENT"
    ANOMALY = "ANOMALY"
    UNKNOWN = "UNKNOWN"

class LinuxSecurityEvent(BaseModel):
    event_type: EventType = Field(description="이벤트 유형")
    severity: SeverityLevel
    description: str = Field(description="이벤트 상세 설명")
    confidence_score: float = Field(ge=0.0, le=1.0, description="신뢰도 (0.0-1.0)")
    source_ip: Optional[str] = Field(default=None, description="소스 IP")
    username: Optional[str] = Field(default=None, description="사용자명")
    process: Optional[str] = Field(default=None, description="관련 프로세스")
    service: Optional[str] = Field(default=None, description="관련 서비스")
    recommended_actions: list[str] = Field(default=[], description="권장 조치사항")
    requires_human_review: bool = Field(description="인간 검토 필요 여부")

class Statistics(BaseModel):
    total_events: int = Field(default=0, description="총 이벤트 수")
    auth_failures: int = Field(default=0, description="인증 실패 수")
    unique_ips: int = Field(default=0, description="고유 IP 수")
    unique_users: int = Field(default=0, description="고유 사용자 수")
    event_by_type: dict[str, int] = Field(default={}, description="유형별 이벤트 수")
    top_source_ips: dict[str, int] = Field(default={}, description="상위 소스 IP")

class LinuxLogAnalysis(BaseModel):
    summary: str = Field(description="분석 요약")
    events: list[LinuxSecurityEvent] = Field(
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

# log_path = "sample-logs/linux-10.log"
# log_path = "sample-logs/linux-100.log"
log_path = "sample-logs/linux-2k.log"

chunk_size = 3

with open(log_path, "r", encoding="utf-8") as f:
    for i, chunk in enumerate(chunked_iterable(f, chunk_size, debug=False)):
        chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        logs = "".join(chunk)
        model_schema = LinuxLogAnalysis.model_json_schema()
        prompt = PROMPT_TEMPLATE_LINUX_SYSTEM_LOG.format(logs=logs, model_schema=model_schema)
        print(f"\n--- Linux Chunk {i+1} ---")
        print_chunk_contents(chunk)
        
        chunk_end_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        
        # 공통 처리 함수 사용
        success, parsed_data = process_log_chunk(
            model=model,
            prompt=prompt,
            model_class=LinuxLogAnalysis,
            chunk_start_time=chunk_start_time,
            chunk_end_time=chunk_end_time,
            elasticsearch_index="linux_system",
            chunk_number=i+1,
            chunk_data=chunk
        )
