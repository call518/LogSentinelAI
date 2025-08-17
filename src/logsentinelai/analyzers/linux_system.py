from ..core.commons import setup_logger
import logging

# 파일 로깅만 추가 (콘솔 출력은 기존 print 코드 그대로 유지)
logger = setup_logger("logsentinelai.analyzers.linux_system")
from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional

from ..core.prompts import get_linux_system_prompt
from ..core.commons import (
    run_generic_batch_analysis, 
    run_generic_realtime_analysis,
    create_argument_parser,
    handle_ssh_arguments
)

### Install the required packages
# uv add outlines ollama openai python-dotenv elasticsearch

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
    related_logs: list[str] = Field(min_length=1, description="Original log lines that triggered this event - include exact unmodified log entries from the source data (at least one required)")
    description: str = Field(description="Detailed event description")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Confidence level (0.0-1.0)")
    source_ips: Optional[list[str]] = Field(description="Source IP address list")
    username: Optional[str] = Field(description="Username")
    process: Optional[str] = Field(description="Related process")
    service: Optional[str] = Field(description="Related service")
    recommended_actions: list[str] = Field(description="Recommended actions")
    requires_human_review: bool = Field(description="Whether human review is required")

class Statistics(BaseModel):
    total_events: int = Field(description="Total number of events")
    auth_failures: int = Field(description="Number of authentication failures")
    unique_ips: int = Field(description="Number of unique IPs")
    unique_users: int = Field(description="Number of unique users")
    event_by_type: dict[str, int] = Field(default_factory=dict, description="Events by type")

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
    parser = create_argument_parser('Linux System Log Analysis')
    args = parser.parse_args()

    try:
        logger.info("Linux System Log Analysis started.")
        logger.debug(f"Parsed arguments: {args}")

        # SSH 설정 파싱
        ssh_config = handle_ssh_arguments(args)
        remote_mode = "ssh" if ssh_config else "local"
        logger.info(f"Remote mode: {remote_mode}")

        log_type = "linux_system"
        analysis_title = "Linux System Log Analysis"

        if args.mode == 'realtime':
            logger.info("Running in real-time analysis mode.")
            run_generic_realtime_analysis(
                log_type=log_type,
                analysis_schema_class=LogAnalysis,
                prompt_template=get_linux_system_prompt(),
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
            logger.info("Running in batch analysis mode.")
            run_generic_batch_analysis(
                log_type=log_type,
                analysis_schema_class=LogAnalysis,
                prompt_template=get_linux_system_prompt(),
                analysis_title=analysis_title,
                log_path=args.log_path,
                remote_mode=remote_mode,
                ssh_config=ssh_config
            )
            logger.info("Batch analysis completed.")
    except KeyboardInterrupt:
        logger.info("Linux system log analysis interrupted by user")
        print("\nAnalysis interrupted by user")
        return 0
    except Exception as e:
        logger.exception(f"Unexpected error in Linux system log analysis: {e}")
        print(f"ERROR: Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    main()
