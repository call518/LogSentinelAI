import outlines
import ollama
import openai
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

### Install the required packages
# uv add outlines ollama openai python-dotenv numpy

#---------------------- Linux System Log용 Enums 및 Models ----------------------
class LinuxSeverityLevel(str, Enum):
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
    severity: LinuxSeverityLevel
    description: str
    source_ip: Optional[str]
    username: Optional[str]
    process: Optional[str] = None
    service: Optional[str] = None
    escalation_reason: Optional[str] = None
    relevant_log_entry: list[LogEntry] = Field(description="관련된 로그 엔트리 목록")
    requires_human_review: bool
    recommended_actions: list[str]
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
    events: list[LinuxSecurityEvent]
    statistics: Optional[LinuxStatistics]
    highest_severity: Optional[LinuxSeverityLevel]
    requires_immediate_attention: bool
#--------------------------------------------------------------------------------------

llm_provider = "ollama"
# llm_provider = "vllm"
# llm_provider = "openai"

if llm_provider == "ollama":
    ### Ollama API
    # llm_model = "mistral:7b"
    llm_model = "qwen2.5-coder:3b"
    # llm_model = "qwen2.5-coder:7b"
    # llm_model = "gemma3:1b"
    # llm_model = "gemma3:4b"
    # llm_model = "gemma3:12b"
    # llm_model = "call518/gemma3-tools-8192ctx:4b"
    client = ollama.Client()
    model = outlines.from_ollama(client, llm_model)
elif llm_provider == "vllm":
    ### Local vLLM API
    openai_api_key = "dummy"
    llm_model = "vLLM-Qwen2.5-3B-Instruct"
    # llm_model = "gpt-4o"
    client = openai.OpenAI(
        base_url="http://127.0.0.1:5000/v1",  # Local vLLM API endpoint
        api_key=openai_api_key
    )
    model = outlines.from_openai(client, llm_model)
elif llm_provider == "openai":
    ### OpenAI API
    load_dotenv()
    openai_api_key = os.getenv("OPENAI_API_KEY")
    llm_model = "gpt-4o-mini"
    # llm_model = "gpt-4o"
    client = openai.OpenAI(
        base_url="https://api.openai.com/v1",  # OpenAI API endpoint
        # base_url="http://127.0.0.1:11434/v1",  # Local Ollama API endpoint
        api_key=openai_api_key
    )
    model = outlines.from_openai(client, llm_model)
else:
    raise ValueError("Unsupported LLM provider. Use 'ollama' or 'openai'.")

# log_path = "sample-logs/linux-10.log"
log_path = "sample-logs/linux-100.log"
# log_path = "sample-logs/linux-10k.log"

chunk_size = 10

with open(log_path, "r", encoding="utf-8") as f:
    for i, chunk in enumerate(chunked_iterable(f, chunk_size, debug=False)):
        chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        logs = "".join(chunk)
        model_schema = LinuxLogAnalysis.model_json_schema()
        prompt = PROMPT_TEMPLATE_LINUX_SYSTEM_LOG.format(logs=logs, model_schema=model_schema)
        print(f"\n--- Linux Chunk {i+1} ---")
        print_chunk_contents(chunk)
        review = model(
            prompt,
            LinuxLogAnalysis
        )
        chunk_end_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        try:
            parsed = json.loads(review)
            parsed = {
                "chunk_analysis_start_utc": chunk_start_time,
                "chunk_analysis_end_utc": chunk_end_time,
                **parsed
            }
            
            print(json.dumps(parsed, ensure_ascii=False, indent=4))
            #json_str = json.dumps(parsed, ensure_ascii=False)
            #subprocess.run(['jq', '--color-output', '.'], input=json_str, text=True, stdout=sys.stdout)
            
            character = LinuxLogAnalysis.model_validate(parsed)
            # print(character)
            
            # Send to Elasticsearch
            print(f"\n🔄 Elasticsearch로 데이터 전송 중...")
            success = send_to_elasticsearch(parsed, "linux_system", i+1, chunk)
            if success:
                print(f"✅ Chunk {i+1} 데이터 Elasticsearch 전송 완료")
            else:
                print(f"❌ Chunk {i+1} 데이터 Elasticsearch 전송 실패")
                
        except Exception as e:
            print("Error parsing Linux log analysis:", e)
