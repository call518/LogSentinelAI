from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional

from ..core.prompts import get_httpd_access_prompt
from ..core.commons import (
    run_generic_batch_analysis, 
    run_generic_realtime_analysis,
    create_argument_parser,
    handle_ssh_arguments
)

### Install the required packages
# uv add outlines ollama openai python-dotenv numpy elasticsearch

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
    description: str = Field(description="Detailed event description, including a brief summary of region statistics for related logs")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Confidence level (0.0-1.0)")
    event_message: str = Field(description="Event message")
    url_pattern: str = Field(description="Related URL pattern")
    http_method: str = Field(description="HTTP method")
    source_ips: list[str] = Field(description="Complete list of ALL source IP addresses found in this chunk - NEVER leave empty")
    response_codes: list[str] = Field(description="Response code list")
    attack_patterns: list[AttackType] = Field(description="Detected attack patterns")
    recommended_actions: list[str] = Field(description="Recommended actions")
    requires_human_review: bool = Field(description="Whether human review is required")
    related_logs: list[str] = Field(min_items=1, description="Original log lines that triggered this event - include exact unmodified log entries from the source data (at least one required)")

class Statistics(BaseModel):
    total_requests: int = Field(description="Total number of requests")
    unique_ips: int = Field(description="Number of unique IPs")
    error_rate: float = Field(description="Error rate (0.0-1.0)")
    response_code_dist: dict[str, int] = Field(default_factory=dict, description="Response code distribution")

class LogAnalysis(BaseModel):
    summary: str = Field(description="Analysis summary including IP patterns and geographic distribution")
    events: list[SecurityEvent] = Field(
        min_length=1,
        description="List of events - MUST NEVER BE EMPTY. Always create at least one INFO event with 'No significant issues detected' if no problems found"
    )
    statistics: Statistics
    highest_severity: Optional[SeverityLevel] = Field(description="Highest severity level of detected events (null if no events)")
    requires_immediate_attention: bool = Field(description="Requires immediate attention")
#--------------------------------------------------------------------------------------

def main():
    """Main function with argument parsing"""
    parser = create_argument_parser('HTTPD Access Log Analysis')
    args = parser.parse_args()
    
    # SSH 설정 파싱
    ssh_config = handle_ssh_arguments(args)
    remote_mode = "ssh" if ssh_config else "local"
    
    log_type = "httpd_access"
    analysis_title = "HTTPD Access Log Analysis"
    
    if args.mode == 'realtime':
        run_generic_realtime_analysis(
            log_type=log_type,
            analysis_schema_class=LogAnalysis,
            prompt_template=get_httpd_access_prompt(),
            analysis_title=analysis_title,
            chunk_size=args.chunk_size,
            log_path=args.log_path,
            processing_mode=args.processing_mode,
            sampling_threshold=args.sampling_threshold,
            remote_mode=remote_mode,
            ssh_config=ssh_config
        )
    else:
        run_generic_batch_analysis(
            log_type=log_type,
            analysis_schema_class=LogAnalysis,
            prompt_template=get_httpd_access_prompt(),
            analysis_title=analysis_title,
            log_path=args.log_path,
            remote_mode=remote_mode,
            ssh_config=ssh_config
        )


if __name__ == "__main__":
    main()
