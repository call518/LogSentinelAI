import outlines
import ollama
import openai
from pydantic import BaseModel, Field
from enum import Enum
from typing import Literal, Optional
import json
import uuid
import os
import datetime
from dotenv import load_dotenv

PROMPT_TEMPLATE = """
You are an expert security analyst reviewing security logs.

You are a computer security intern that's really stressed out.
Your job is hard and you're not sure you're doing it well.
Your observations and summaries should reflect your anxiety.
Convey a sense of urgency and panic, be apologetic, and generally act like you're not sure you can do your job.
In your summary, address your boss as "boss" and apologize for any mistakes you've made even if you haven't made any. 
Use "um" and "ah" a lot.

Your task is to:
1. Identify potential security events or suspicious patterns
2. Summarize normal and abnormal traffic patterns very briefly.
3. Determine severity and whether human review is needed
4. Provide clear reasoning about your findings

For each log group, analyze:
- Common URL patterns and their typical usage
- Unusual HTTP methods or response codes
- Rate of requests from individual IPs
- Suspicious user agent strings
- Known web attack signatures

For potential security events, consider:
- Is this a known attack pattern (SQL injection, XSS, path traversal, etc.)?
- What is the potential impact on the web application?
- How confident are you in this assessment?
- What immediate actions should be taken?

Before concluding whether to escalate log(s), please
provide a list of reasoning steps after reviewing
all available information. Be generous with log
escalation that is not standard web traffic.

Beging by noting some observations about the log. Then,
plan the rest of your response.

Remember:
- Focus on patterns that could indicate security threats
- Note unusual but potentially legitimate traffic patterns
- Be conservative with high-severity ratings
- Clearly explain your reasoning
- Recommend specific actions when confident
- Escalate logs that a security admin may wish to briefly review
- All logs are uniquely identified by an identifier in the form LOGID-<LETTERS>, i.e. LOGID-KU or LOGID-AT
- All date times are in ISO 8601 format
    - 2024-11-15T19:32:34Z for UTC
    - 2024-11-15T07:32:34−12:00 for datetime with offset

You should return valid JSON in the schema
{model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

def chunked_iterable(iterable, size, debug=False):
    import uuid
    chunk = []
    for item in iterable:
        # logid = "LOGID-" + "".join([chr(ord('A') + (uuid.uuid4().int >> (i * 5)) % 26) for i in range(10)])
        # 라인 앞에 LOGID 추가
        # new_item = f"{logid} {item.rstrip()}\n"
        # chunk.append(new_item)
        chunk.append(item)
        if len(chunk) == size:
            if debug:
                print("[DEBUG] Yielding chunk:")
                for line in chunk:
                    print(line.rstrip())
            yield chunk
            chunk = []
    if chunk:
        if debug:
            print("[DEBUG] Yielding final chunk:")
            for line in chunk:
                print(line.rstrip())
        yield chunk

#---------------------------------- Enums and Models ----------------------------------
class LogID(BaseModel):
    log_id: str = Field(
        description="""
        The ID of the log entry in the format of LOGID-<LETTERS>, where <LETTERS> indicates the log identifier at the beginning of each log entry and consists of uppercase alphabet letters only (A–Z, no digits).
        i.e. LOGID-KU or LOGID-AT
        """,
        # This is a regular expression that matches the LOGID-<LETTERS> format.
        # The model will fill in the <LETTERS> part.
    )
    # Find the log entry in a list of logs. Simple
    # conveience function.
    def find_in(self, logs: list[str]) -> Optional[str]:
        for log in logs:
            if self.log_id in log:
                return log
        return None

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

class WebTrafficPattern(BaseModel):
    url_path: str
    http_method: str
    hits_count: int
    response_codes: dict[str, int]
    unique_ips: int
    request_ips: list[str]

class Statistics(BaseModel):
    request_count_by_ip: dict[str, int]
    request_count_by_url_path: dict[str, int]

class IPAddress(BaseModel):
    ip_address: str

# Class for an HTTP response code.
class ResponseCode(BaseModel):
    response_code: str

class WebSecurityEvent(BaseModel):
    # The log entry IDs that are relevant to this event.
    relevant_log_entry_ids: list[LogID]

    # The reasoning for why this event is relevant.
    reasoning: str

    # The type of event.
    event_type: str

    # The severity of the event.
    severity: SeverityLevel

    # Whether this event requires human review.
    requires_human_review: bool

    # The confidence score for this event. I'm not sure if this
    # is meaningful for language models, but it's here if we want it.
    confidence_score: float = Field(
        ge=0.0, 
        le=1.0,
        description="Confidence score between 0 and 1"
    )

    # Web-specific fields
    url_pattern: str = Field(
        min_length=1,
        description="URL pattern that triggered the event"
    )

    http_method: Literal["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
    source_ips: list[IPAddress]
    response_codes: list[ResponseCode]
    user_agents: list[str]

    # Possible attack patterns for this event.
    possible_attack_patterns: list[AttackType]

    # Recommended actions for this event.
    recommended_actions: list[str]

### Top-level class for log analysis results
class LogAnalysis(BaseModel):
    # # A summary of the analysis.
    summary: str
    
    # # Observations about the logs.
    observations: list[str]
    
    # # Planning for the analysis.
    planning: list[str]
    
    # # Security events found in the logs.
    events: list[WebSecurityEvent]
    
    # # Traffic patterns found in the logs.
    traffic_patterns: list[WebTrafficPattern]
    
    # # Statistics for the logs.
    statistics: Statistics
    
    # # The highest severity event found.
    highest_severity: Optional[SeverityLevel]
    
    requires_immediate_attention: bool
#--------------------------------------------------------------------------------------

### Specify the llm model
# llm_model = "mistral:7b"
llm_model = "qwen2.5-coder:3b"
# llm_model = "qwen2.5-coder:7b"
# llm_model = "gemma3:1b"
# llm_model = "gemma3:4b"
# llm_model = "gemma3:12"
# llm_model = "call518/gemma3-tools-8192ctx:4b"

### Ollama API
client = ollama.Client()
model = outlines.from_ollama(client, llm_model)

### OpenAI API
# load_dotenv()
# openai_api_key = os.getenv("OPENAI_API_KEY")
# client = openai.OpenAI(
#     base_url="http://127.0.0.1:11434/v1",  # Local Ollama API endpoint
#     api_key=openai_api_key
# )
# model = outlines.from_openai(client, llm_model)

# log_path = "sample-logs/access-10.log"
log_path = "sample-logs/access-100.log"
# log_path = "sample-logs/access-10k.log"
chunk_size = 5

with open(log_path, "r", encoding="utf-8") as f:
    for i, chunk in enumerate(chunked_iterable(f, chunk_size, debug=False)):
        # 분석 시작 시간 기록
        chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        logs = "".join(chunk)
        model_schema=LogAnalysis.model_json_schema()
        prompt = PROMPT_TEMPLATE.format(logs=logs, model_schema=model_schema)
        print(f"\n--- Chunk {i+1} ---")
        review = model(
            prompt,
            LogAnalysis
        )
        # 분석 완료 시간 기록
        chunk_end_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        ### [Validate] Parse the review and print the character
        try:
            # print(review)
            ### Validate JSON
            parsed = json.loads(review)
            # 분석 시간 정보 추가
            parsed = {
                "chunk_analysis_start_utc": chunk_start_time,
                "chunk_analysis_end_utc": chunk_end_time,
                **parsed
            }
            # print(parsed)
            print(json.dumps(parsed, ensure_ascii=False, indent=4))
            ### Validate Type
            character = LogAnalysis.model_validate(parsed)
            # print(character)
        except Exception as e:
            print("Error parsing character:", e)