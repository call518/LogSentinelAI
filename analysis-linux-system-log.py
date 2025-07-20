from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional
import datetime
import argparse

from prompts import PROMPT_TEMPLATE_LINUX_SYSTEM_LOG
from commons import chunked_iterable
from commons import print_chunk_contents
from commons import initialize_llm_model
from commons import process_log_chunk
from commons import wait_on_failure
from commons import get_llm_config
from commons import get_analysis_config
from commons import create_realtime_monitor

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

def run_batch_analysis():
    """Run batch analysis on complete log file"""
    print("=" * 70)
    print("LogSentinelAI - Linux System Log Analysis (Batch Mode)")
    print("=" * 70)
    
    # Get LLM configuration from commons
    llm_provider, llm_model_name = get_llm_config()
    
    # Get analysis configuration (can override chunk_size if needed)
    # config = get_analysis_config("linux_system", chunk_size=5)  # Override chunk_size
    config = get_analysis_config("linux_system")  # Use default chunk_size
    
    print(f"Log file:          {config['log_path']}")
    print(f"Chunk size:        {config['chunk_size']}")
    print(f"Response language: {config['response_language']}")
    print(f"LLM Provider:      {llm_provider}")
    print(f"LLM Model:         {llm_model_name}")
    print("=" * 70)
    
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
                llm_model=llm_model_name,
                processing_mode="batch"
            )
            
            if success:
                print("Analysis completed successfully")
            else:
                print("Analysis failed")
                wait_on_failure(30)  # 실패 시 30초 대기
            
            print("-" * 50)


def run_realtime_analysis(chunk_size=None, log_path=None, processing_mode=None, sampling_threshold=None):
    """Run real-time analysis on live log file with sampling support"""
    print("=" * 70)
    print("LogSentinelAI - Linux System Log Analysis (Real-time Mode)")
    print("=" * 70)
    
    # Log type for this analysis
    log_type = "linux_system"
    
    # Override environment variables if specified
    if processing_mode:
        import os
        os.environ["REALTIME_PROCESSING_MODE"] = processing_mode
    if sampling_threshold:
        import os
        os.environ["REALTIME_SAMPLING_THRESHOLD"] = str(sampling_threshold)
    
    # Get configuration
    config = get_analysis_config(log_type, chunk_size, analysis_mode="realtime")
    
    # Override log path if specified
    if log_path:
        config["log_path"] = log_path
    
    print(f"Log file:          {config['log_path']}")
    print(f"Chunk size:        {config['chunk_size']}")
    print(f"Response language: {config['response_language']}")
    print(f"Analysis mode:     {config['analysis_mode']}")
    
    # Initialize LLM model
    print("\nInitializing LLM model...")
    model = initialize_llm_model()
    
    # Create real-time monitor
    try:
        monitor = create_realtime_monitor(log_type, chunk_size)
    except ValueError as e:
        print(f"ERROR: Configuration error: {e}")
        print("Please check your config file for real-time log paths")
        return
    
    # Custom callback for processing results
    def process_result_callback(result, chunk, chunk_id):
        """Custom callback to handle analysis results"""
        print(f"📈 Analysis complete for chunk {chunk_id}")
        
        if result and 'events' in result:
            event_count = len(result['events'])
            print(f"🚨 Found {event_count} security events")
            
            # Show high severity events
            high_severity_events = [
                event for event in result['events'] 
                if event.get('severity') in ['HIGH', 'CRITICAL']
            ]
            
            if high_severity_events:
                print(f"WARNING: HIGH/CRITICAL events: {len(high_severity_events)}")
                for event in high_severity_events:
                    print(f"   🔥 {event.get('event_type', 'UNKNOWN')}: {event.get('description', 'No description')}")
        
        print("-" * 40)
    
    # Function to create analysis prompt
    def create_analysis_prompt(chunk, response_language):
        logs = "".join(chunk)
        model_schema = LogAnalysis.model_json_schema()
        return PROMPT_TEMPLATE_LINUX_SYSTEM_LOG.format(
            logs=logs, 
            model_schema=model_schema, 
            response_language=response_language
        )
    
    # Start real-time monitoring
    try:
        monitor.monitor_and_analyze(
            model=model,
            analysis_prompt_func=create_analysis_prompt,
            analysis_schema_class=LogAnalysis,
            process_callback=process_result_callback
        )
    except FileNotFoundError:
        print(f"ERROR: Log file not found: {config['log_path']}")
        print("NOTE: Make sure the log file exists and is readable")
        print("NOTE: You may need to run with appropriate permissions")
    except PermissionError:
        print(f"ERROR: Permission denied: {config['log_path']}")
        print("NOTE: You may need to run with sudo or adjust file permissions")
    except Exception as e:
        print(f"ERROR: Unexpected error: {e}")


def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(description='Linux System Log Analysis')
    parser.add_argument('--mode', choices=['batch', 'realtime'], default='batch',
                       help='Analysis mode: batch (default) or realtime')
    parser.add_argument('--chunk-size', type=int, default=None,
                       help='Override default chunk size')
    parser.add_argument('--log-path', type=str, default=None,
                       help='Override default log file path')
    parser.add_argument('--processing-mode', choices=['full', 'sampling'], default=None,
                       help='Real-time processing mode: full (process all) or sampling (latest only)')
    parser.add_argument('--sampling-threshold', type=int, default=None,
                       help='Auto-switch to sampling if accumulated lines exceed this (only for full mode)')
    args = parser.parse_args()
    
    if args.mode == 'realtime':
        run_realtime_analysis(args.chunk_size, args.log_path, args.processing_mode, args.sampling_threshold)
    else:
        run_batch_analysis()


if __name__ == "__main__":
    main()
