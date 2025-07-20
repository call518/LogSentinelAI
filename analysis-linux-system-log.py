from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional
import datetime

from prompts import PROMPT_TEMPLATE_LINUX_SYSTEM_LOG
from commons import chunked_iterable
from commons import print_chunk_contents
from commons import initialize_llm_model
from commons import process_log_chunk
from commons import wait_on_failure
from commons import get_llm_config
from commons import get_analysis_config

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

class SecurityEvent(BaseModel):
    event_type: EventType
    severity: SeverityLevel
    description: str = Field(description="Detailed event description")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Confidence level (0.0-1.0)")
    source_ip: Optional[str] = Field(description="Source IP")
    username: Optional[str] = Field(description="Username")
    process: Optional[str] = Field(description="Related process")
    service: Optional[str] = Field(description="Related service")
    recommended_actions: list[str] = Field(description="Recommended actions")
    requires_human_review: bool = Field(description="Whether human review is required")
    related_log_ids: list[str] = Field(description="Related LOGID list (e.g., ['LOGID-7DD17B008706AC22C60AD6DF9AC5E2E9', 'LOGID-F3B6E3F03EC9E5BC1F65624EB65C6C51'])")

class Statistics(BaseModel):
    total_events: int = Field(description="Total number of events")
    auth_failures: int = Field(description="Number of authentication failures")
    unique_ips: int = Field(description="Number of unique IPs")
    unique_users: int = Field(description="Number of unique users")
    event_by_type: dict[str, int] = Field(default_factory=dict, description="Events by type")
    top_source_ips: dict[str, int] = Field(default_factory=dict, description="Top source IPs")

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

# Get LLM configuration from commons
llm_provider, llm_model_name = get_llm_config()

# Get analysis configuration (can override chunk_size if needed)
# config = get_analysis_config("linux_system", chunk_size=5)  # Override chunk_size
config = get_analysis_config("linux_system")  # Use default chunk_size

log_path = config["log_path"]
chunk_size = config["chunk_size"]
response_language = config["response_language"]

model = initialize_llm_model()

with open(log_path, "r", encoding="utf-8") as f:
    for i, chunk in enumerate(chunked_iterable(f, chunk_size, debug=False)):
        # 분석 시작 시간 기록
        chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        logs = "".join(chunk)
        model_schema = LogAnalysis.model_json_schema()
        prompt = PROMPT_TEMPLATE_LINUX_SYSTEM_LOG.format(logs=logs, model_schema=model_schema, response_language=response_language)
        print(f"\n--- Chunk {i+1} ---")
        print_chunk_contents(chunk)
        
        # 공통 처리 함수 사용 (분석 완료 시간은 함수 내부에서 기록)
        success, parsed_data = process_log_chunk(
            model=model,
            prompt=prompt,
            model_class=LogAnalysis,
            chunk_start_time=chunk_start_time,
            chunk_end_time=None,  # 함수 내부에서 계산
            elasticsearch_index="linux_system",
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
