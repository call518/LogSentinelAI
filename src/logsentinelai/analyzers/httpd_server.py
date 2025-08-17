from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional

from ..core.prompts import get_httpd_server_error_prompt
from ..core.commons import (
    run_generic_batch_analysis, 
    run_generic_realtime_analysis,
    create_argument_parser,
    handle_ssh_arguments
)

### Install the required packages
# uv add outlines ollama openai python-dotenv elasticsearch

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
    event_type: str = Field(description="Security or error event type")
    severity: SeverityLevel
    related_logs: list[str] = Field(min_length=1, description="Original log lines that triggered this event - include exact unmodified log entries from the source data (at least one required)")
    description: str = Field(description="Detailed event description")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Confidence level (0.0-1.0)")
    file_path: Optional[str] = Field(description="Related file path")
    source_ips: list[str] = Field(description="Source IP list")
    attack_patterns: list[AttackType] = Field(description="Detected attack patterns")
    recommended_actions: list[str] = Field(description="Recommended actions")
    requires_human_review: bool = Field(description="Whether human review is required")

class Statistics(BaseModel):
    total_event: int = Field(description="Total number of errors")
    event_by_level: dict[str, int] = Field(default_factory=dict, description="Errors by level")
    event_by_type: dict[str, int] = Field(default_factory=dict, description="Errors by type")

class LogAnalysis(BaseModel):
    summary: str = Field(description="Analysis summary")
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
    parser = create_argument_parser('HTTPD Server Log Analysis')
    args = parser.parse_args()

    # 파일 로깅 설정 (콘솔 출력은 기존대로 print 사용)
    from ..core.commons import setup_logger
    logger = setup_logger(__name__)

    try:
        # SSH 설정 파싱
        ssh_config = handle_ssh_arguments(args)
        remote_mode = "ssh" if ssh_config else "local"

        log_type = "httpd_server"
        analysis_title = "HTTPD Server Log Analysis"

        logger.info(f"Starting {analysis_title} (mode: {args.mode}, log_path: {args.log_path}, remote_mode: {remote_mode})")

        if args.mode == 'realtime':
            logger.debug("Running in realtime mode.")
            run_generic_realtime_analysis(
                log_type=log_type,
                analysis_schema_class=LogAnalysis,
                prompt_template=get_httpd_server_error_prompt(),
                analysis_title=analysis_title,
                chunk_size=args.chunk_size,
                log_path=args.log_path,
                only_sampling_mode=args.only_sampling_mode,
                sampling_threshold=args.sampling_threshold,
                remote_mode=remote_mode,
                ssh_config=ssh_config
            )
            logger.info("Realtime analysis completed.")
        else:
            logger.debug("Running in batch mode.")
            run_generic_batch_analysis(
                log_type=log_type,
                analysis_schema_class=LogAnalysis,
                prompt_template=get_httpd_server_error_prompt(),
                analysis_title=analysis_title,
                log_path=args.log_path,
                remote_mode=remote_mode,
                ssh_config=ssh_config
            )
            logger.info("Batch analysis completed.")
    except KeyboardInterrupt:
        logger.info("HTTPD server log analysis interrupted by user")
        print("\nAnalysis interrupted by user")
        return 0
    except Exception as e:
        logger.exception(f"Unexpected error in HTTPD server log analysis: {e}")
        print(f"ERROR: Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    main()
