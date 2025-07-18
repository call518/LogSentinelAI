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
class LinuxSeverityLevel(str, Enum):
    """
    Severity levels for security events (BALANCED APPROACH):
    - CRITICAL: Confirmed successful attacks or system compromise
    - HIGH: Strong attack indicators with high confidence and potential system damage
    - MEDIUM: Suspicious patterns warranting investigation (use for legitimate security concerns)
    - LOW: Minor security events or isolated anomalies
    - INFO: Normal system events and routine activities
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class LinuxEventType(str, Enum):
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    SESSION_OPENED = "SESSION_OPENED"
    SESSION_CLOSED = "SESSION_CLOSED"
    FTP_CONNECTION = "FTP_CONNECTION"
    SFTP_CONNECTION = "SFTP_CONNECTION"
    SSH_CONNECTION = "SSH_CONNECTION"
    SUDO_USAGE = "SUDO_USAGE"
    CRON_JOB = "CRON_JOB"
    SYSTEMD_EVENT = "SYSTEMD_EVENT"
    KERNEL_EVENT = "KERNEL_EVENT"
    USER_MANAGEMENT = "USER_MANAGEMENT"
    LOGROTATE_ALERT = "LOGROTATE_ALERT"
    ANOMALY = "ANOMALY"
    UNKNOWN = "UNKNOWN"

class LogEntry(BaseModel):
    log_id: str
    log_message: str

class LinuxSecurityEvent(BaseModel):
    event_type: LinuxEventType
    severity: LinuxSeverityLevel = Field(
        description="Severity level - Use balanced judgment based on error patterns and potential security impact"
    )
    description: str
    source_ip: Optional[str]
    username: Optional[str]
    process: Optional[str] = None
    service: Optional[str] = None
    escalation_reason: Optional[str] = None
    relevant_log_entry: list[LogEntry] = Field(default=[], description="관련된 로그 엔트리 목록")
    requires_human_review: bool
    recommended_actions: list[str] = Field(default=[], description="권장 조치사항")
    confidence_score: float = Field(ge=0.0, le=1.0)

class LinuxStatistics(BaseModel):
    auth_failures_by_ip: Optional[dict[str, int]]
    ftp_connections_by_ip: Optional[dict[str, int]]
    sftp_connections_by_ip: Optional[dict[str, int]]
    ssh_connections_by_ip: Optional[dict[str, int]]
    session_opened_count: Optional[int]
    session_closed_count: Optional[int]
    sudo_usage_by_user: Optional[dict[str, int]]
    cron_jobs_by_user: Optional[dict[str, int]]
    service_events: Optional[dict[str, int]]
    user_management_events: Optional[dict[str, int]]
    kernel_events: Optional[dict[str, int]]
    anomaly_counts: Optional[dict[str, int]]

class LinuxLogAnalysis(BaseModel):
    summary: str
    observations: list[str]
    planning: list[str]
    events: list[LinuxSecurityEvent] = Field(
        min_items=1,
        description="Security events found - MUST contain at least one event per chunk, never empty"
    )
    statistics: Optional[LinuxStatistics]
    highest_severity: Optional[LinuxSeverityLevel]
    requires_immediate_attention: bool
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
