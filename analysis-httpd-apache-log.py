from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional
import datetime

from prompts import PROMPT_TEMPLATE_HTTPD_APACHE_ERROR_LOG
from commons import chunked_iterable
from commons import print_chunk_contents
from commons import initialize_llm_model
from commons import process_log_chunk
from commons import wait_on_failure
from commons import get_llm_config
from commons import get_analysis_config

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

class SecurityEvent(BaseModel):
    event_type: str = Field(description="Security event type")
    severity: SeverityLevel
    description: str = Field(description="Detailed event description")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Confidence level (0.0-1.0)")
    log_level: str = Field(description="Apache log level")
    error_message: str = Field(description="Error message")
    file_path: Optional[str] = Field(description="Related file path")
    source_ips: list[str] = Field(description="Source IP list")
    attack_patterns: list[AttackType] = Field(description="Detected attack patterns")
    recommended_actions: list[str] = Field(description="Recommended actions")
    requires_human_review: bool = Field(description="Whether human review is required")
    related_log_ids: list[str] = Field(description="Related LOGID list (e.g., ['LOGID-7DD17B008706AC22C60AD6DF9AC5E2E9', 'LOGID-F3B6E3F03EC9E5BC1F65624EB65C6C51'])")

class Statistics(BaseModel):
    total_errors: int = Field(description="Total number of errors")
    error_by_level: dict[str, int] = Field(default_factory=dict, description="Errors by level")
    error_by_type: dict[str, int] = Field(default_factory=dict, description="Errors by type")
    top_error_ips: dict[str, int] = Field(default_factory=dict, description="Top error IPs")

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
#--------------------------------------------------------------------------------------

# Get LLM configuration from commons
llm_provider, llm_model_name = get_llm_config()

# Get analysis configuration (can override chunk_size if needed)
# config = get_analysis_config("httpd_apache_error", chunk_size=5)  # Override chunk_size
config = get_analysis_config("httpd_apache_error")  # Use default chunk_size

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
        prompt = PROMPT_TEMPLATE_HTTPD_APACHE_ERROR_LOG.format(logs=logs, model_schema=model_schema, response_language=response_language)
        print(f"\n--- Chunk {i+1} ---")
        print_chunk_contents(chunk)
        
        # 공통 처리 함수 사용 (분석 완료 시간은 함수 내부에서 기록)
        success, parsed_data = process_log_chunk(
            model=model,
            prompt=prompt,
            model_class=LogAnalysis,
            chunk_start_time=chunk_start_time,
            chunk_end_time=None,  # 함수 내부에서 계산
            elasticsearch_index="httpd_apache_error",
            chunk_number=i+1,
            chunk_data=chunk,
            llm_provider=llm_provider,
            llm_model=llm_model_name,
            processing_mode="batch"
        )
        
        if success:
            print("Analysis completed successfully")
        else:
            print("Analysis failed")
            wait_on_failure(30)  # 실패 시 30초 대기
        
        print("-" * 50)