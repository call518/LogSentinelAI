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
# uv add outlines ollama openai python-dotenv numpy elasticsearch

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
    extracted_entities: Dict[str, Any] = Field(description="Key entities extracted from logs (IPs, usernames, timestamps, error codes, etc.)")
    pattern_type: Optional[str] = Field(description="Detected log pattern type (e.g., 'Apache Access', 'JSON API', 'Syslog', 'Database', etc.)")
    recommended_actions: list[str] = Field(description="Recommended actions based on this event")
    requires_human_review: bool = Field(description="Whether human review is required")

class LogPatternInfo(BaseModel):
    detected_formats: List[str] = Field(description="Detected log formats in the chunk (e.g., 'Apache Combined', 'JSON', 'Syslog', 'Custom')")
    timestamp_patterns: List[str] = Field(description="Identified timestamp formats")
    common_fields: List[str] = Field(description="Common fields found across logs")
    log_sources: List[str] = Field(description="Identified log sources/applications")

class Statistics(BaseModel):
    total_events: int = Field(description="Total number of events")
    events_by_category: Dict[str, int] = Field(description="Event count by category")
    events_by_severity: Dict[str, int] = Field(description="Event count by severity")
    unique_sources: int = Field(description="Number of unique log sources detected")
    requires_human_review_count: int = Field(description="Number of events requiring human review")

class LogAnalysis(BaseModel):
    events: list[LogEvent] = Field(description="List of detected log events")
    log_patterns: LogPatternInfo = Field(description="Information about detected log patterns")
    statistics: Statistics = Field(description="Analysis statistics")
    analysis_summary: str = Field(description="Overall analysis summary")
    recommendations: list[str] = Field(description="General recommendations for log monitoring")

def main():
    # Create argument parser
    parser = create_argument_parser("General Log Analysis")
    args = parser.parse_args()
    
    # Handle SSH configuration
    ssh_config = handle_ssh_arguments(args)
    remote_mode = "ssh" if ssh_config else "local"
    
    # Run analysis based on mode
    log_type = "general_log"
    analysis_title = "General Log Analysis"
    
    if args.mode == "batch":
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
    elif args.mode == "realtime":
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

if __name__ == "__main__":
    main()
