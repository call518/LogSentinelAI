from pydantic import BaseModel, Field
from enum import Enum
from typing import Literal, Optional
import json
import os
import sys
import datetime
import subprocess
from dotenv import load_dotenv

from prompts import PROMPT_TEMPLATE_HTTPD_ACCESS_LOG
from commons import chunked_iterable
from commons import print_chunk_contents
from commons import send_to_elasticsearch
from commons import initialize_llm_model
from commons import process_log_chunk
from commons import wait_on_failure

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
    event_type: str = Field(description="Security event type")
    severity: SeverityLevel
    description: str = Field(description="Detailed event description")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Confidence level (0.0-1.0)")
    url_pattern: str = Field(description="Related URL pattern")
    http_method: str = Field(description="HTTP method")
    source_ips: list[str] = Field(description="Source IP list")
    response_codes: list[str] = Field(description="Response code list")
    attack_patterns: list[AttackType] = Field(description="Detected attack patterns")
    recommended_actions: list[str] = Field(description="Recommended actions")
    requires_human_review: bool = Field(description="Whether human review is required")
    related_log_ids: list[str] = Field(description="Related LOGID list (e.g., ['LOGID-7DD17B008706AC22C60AD6DF9AC5E2E9', 'LOGID-F3B6E3F03EC9E5BC1F65624EB65C6C51'])")

class Statistics(BaseModel):
    total_requests: int = Field(description="Total number of requests")
    unique_ips: int = Field(description="Number of unique IPs")
    error_rate: float = Field(description="Error rate (0.0-1.0)")
    top_ips: dict[str, int] = Field(default_factory=dict, description="Top requesting IPs")
    response_code_dist: dict[str, int] = Field(default_factory=dict, description="Response code distribution")

class LogAnalysis(BaseModel):
    summary: str = Field(description="Analysis summary")
    events: list[SecurityEvent] = Field(
        min_items=1,
        description="List of security events - must include at least one"
    )
    statistics: Statistics
    highest_severity: SeverityLevel
    requires_immediate_attention: bool = Field(description="Requires immediate attention")
#--------------------------------------------------------------------------------------

# LLM Configuration - Choose from "ollama", "vllm", "openai"
# llm_provider = "ollama"
llm_provider = "vllm"
# llm_provider = "openai"

# LLM 모델 이름 정의 (각 provider별로)
if llm_provider == "ollama":
    llm_model_name = "qwen2.5-coder:3b"
elif llm_provider == "vllm":
    llm_model_name = "Qwen/Qwen2.5-3B-Instruct"
elif llm_provider == "openai":
    llm_model_name = "gpt-4o"
else:
    llm_model_name = "unknown"

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
            chunk_data=chunk,
            llm_provider=llm_provider,
            llm_model=llm_model_name
        )
        
        if success:
            print("✅ Analysis completed successfully")
        else:
            print("❌ Analysis failed")
            wait_on_failure(30)  # 실패 시 30초 대기
        
        print("-" * 50)