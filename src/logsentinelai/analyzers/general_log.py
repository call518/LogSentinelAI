from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional, Any, Dict, List

from ..core.prompts import get_general_log_prompt
from ..core.commons import (
    run_generic_batch_analysis, 
    run_generic_realtime_analysis,
    create_argument_parser,
    handle_ssh_arguments
)

### Install the required packages
# uv add outlines ollama openai python-dotenv elasticsearch

#---------------------- General Log용 Enums 및 Models ----------------------
class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class EventCategory(str, Enum):
    SECURITY = "SECURITY"
    ERROR = "ERROR"
    WARNING = "WARNING"
    PERFORMANCE = "PERFORMANCE"
    ACCESS = "ACCESS"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    NETWORK = "NETWORK"
    DATABASE = "DATABASE"
    APPLICATION = "APPLICATION"
    SYSTEM = "SYSTEM"
    USER_ACTION = "USER_ACTION"
    BUSINESS_LOGIC = "BUSINESS_LOGIC"
    UNKNOWN = "UNKNOWN"

class LogEvent(BaseModel):
    category: EventCategory
    severity: SeverityLevel
    related_logs: list[str] = Field(min_length=1, description="Original log lines that triggered this event - include exact unmodified log entries from the source data (at least one required)")
    description: str = Field(description="Detailed event description")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Confidence level (0.0-1.0)")
    source_ips: list[str] = Field(description="Complete list of ALL source IP addresses found in this chunk - NEVER leave empty")
    pattern_type: Optional[str] = Field(description="Detected log pattern type (e.g., 'Apache Access', 'JSON API', 'Syslog', 'Database', etc.)")
    recommended_actions: list[str] = Field(description="Recommended actions based on this event")
    requires_human_review: bool = Field(description="Whether human review is required")

class EventStatistics(BaseModel):
    total_events: int = Field(description="Total number of events detected")
    security_events: int = Field(description="Number of SECURITY events")
    error_events: int = Field(description="Number of ERROR events")
    warning_events: int = Field(description="Number of WARNING events")
    performance_events: int = Field(description="Number of PERFORMANCE events")
    access_events: int = Field(description="Number of ACCESS events")
    authentication_events: int = Field(description="Number of AUTHENTICATION events")
    authorization_events: int = Field(description="Number of AUTHORIZATION events")
    network_events: int = Field(description="Number of NETWORK events")
    database_events: int = Field(description="Number of DATABASE events")
    application_events: int = Field(description="Number of APPLICATION events")
    system_events: int = Field(description="Number of SYSTEM events")
    user_action_events: int = Field(description="Number of USER_ACTION events")
    business_logic_events: int = Field(description="Number of BUSINESS_LOGIC events")
    unknown_events: int = Field(description="Number of UNKNOWN events")

class SeverityBreakdown(BaseModel):
    critical_events: int = Field(description="Number of CRITICAL severity events")
    high_events: int = Field(description="Number of HIGH severity events")
    medium_events: int = Field(description="Number of MEDIUM severity events")
    low_events: int = Field(description="Number of LOW severity events")
    info_events: int = Field(description="Number of INFO severity events")

class LogAnalysis(BaseModel):
    events: list[LogEvent] = Field(description="List of detected log events")
    # Log pattern information (flattened from LogPatternInfo)
    detected_formats: List[str] = Field(description="Detected log formats in the chunk (e.g., 'Apache Combined', 'JSON', 'Syslog', 'Custom')")
    timestamp_patterns: List[str] = Field(description="Identified timestamp formats")
    common_fields: List[str] = Field(description="Common fields found across logs")
    log_sources: List[str] = Field(description="Identified log sources/applications")
    # Statistics (nested models)
    statistics_event: EventStatistics
    statistics_severity: SeverityBreakdown
    # Analysis metadata
    unique_sources: int = Field(description="Number of unique log sources detected")
    requires_human_review_count: int = Field(description="Number of events requiring human review")
    # Summary fields
    analysis_summary: str = Field(description="Overall analysis summary")
    recommendations: list[str] = Field(description="General recommendations for log monitoring")

def main():
    # Create argument parser
    parser = create_argument_parser("General Log Analysis")
    args = parser.parse_args()

    # 파일 로깅 설정 (콘솔 출력은 기존대로 print 사용)
    from ..core.commons import setup_logger
    logger = setup_logger(__name__)

    try:
        # Handle SSH configuration
        ssh_config = handle_ssh_arguments(args)
        remote_mode = "ssh" if ssh_config else "local"

        # Run analysis based on mode
        log_type = "general_log"
        analysis_title = "General Log Analysis"

        logger.info(f"Starting {analysis_title} (mode: {args.mode}, log_path: {args.log_path}, remote_mode: {remote_mode})")

        if args.mode == "batch":
            logger.debug("Running in batch mode.")
            run_generic_batch_analysis(
                log_type=log_type,
                analysis_schema_class=LogAnalysis,
                prompt_template=get_general_log_prompt(),
                analysis_title=analysis_title,
                log_path=args.log_path,
                chunk_size=args.chunk_size,
                remote_mode=remote_mode,
                ssh_config=ssh_config
            )
            logger.info("Batch analysis completed.")
        elif args.mode == "realtime":
            logger.debug("Running in realtime mode.")
            run_generic_realtime_analysis(
                log_type=log_type,
                analysis_schema_class=LogAnalysis,
                prompt_template=get_general_log_prompt(),
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
            logger.error(f"Invalid analysis mode: {args.mode}")
            print(f"ERROR: Invalid analysis mode: {args.mode}")
            return 1
    except KeyboardInterrupt:
        logger.info("General log analysis interrupted by user")
        print("\nAnalysis interrupted by user")
        return 0
    except Exception as e:
        logger.exception(f"Unexpected error in general log analysis: {e}")
        print(f"ERROR: Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    main()
