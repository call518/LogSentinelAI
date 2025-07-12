import outlines
import ollama
import openai
from pydantic import BaseModel
from enum import Enum
from typing import Literal, Optional
import json
import os
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
- All logs are uniquely identified by an identifier in the form LOGID-<LETTERS>, i.e. LOGID-KU
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
    chunk = []
    for item in iterable:
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

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class WebTrafficPattern(BaseModel):
    url_path: str
    http_method: str
    hits_count: int
    response_codes: dict[str, int]  # Maps status code to count
    unique_ips: int
    count_per_ip: dict[str, int]  # Maps IP to count

### Top-level class for log analysis results
class LogAnalysis(BaseModel):
    # Traffic patterns found in the logs.
    traffic_patterns: list[WebTrafficPattern]
    
    # The highest severity event found.
    highest_severity: Optional[SeverityLevel]

### Specify the llm model
llm_model = "qwen2.5-coder:3b"
# llm_model = "qwen2.5-coder:7b"
# llm_model = "gemma3:4b"
# llm_model = "call518/gemma3-tools-8192ctx:4b"

### Ollama API
# client = ollama.Client()
# model = outlines.from_ollama(client, llm_model)

### OpenAI API
load_dotenv()
openai_api_key = os.getenv("OPENAI_API_KEY")
client = openai.OpenAI(
    base_url="http://127.0.0.1:11434/v1",  # Local Ollama API endpoint
    api_key=openai_api_key
)
model = outlines.from_openai(client, llm_model)

# log_path = "sample-logs/access-10.log"
log_path = "sample-logs/access-100.log"
# log_path = "sample-logs/access-10k.log"
chunk_size = 5

with open(log_path, "r", encoding="utf-8") as f:
    for i, chunk in enumerate(chunked_iterable(f, chunk_size, debug=False)):
        logs = "".join(chunk)
        model_schema=LogAnalysis.model_json_schema()
        prompt = PROMPT_TEMPLATE.format(logs=logs, model_schema=model_schema)
        print(f"\n--- Chunk {i+1} ---")
        review = model(
            prompt,
            LogAnalysis
        )
        
        ### [Validate] Parse the review and print the character
        try:
            # Validate JSON
            parsed = json.loads(review)
            print(review)
            # Validate Type
            character = LogAnalysis.model_validate(parsed)
            # print(character)
        except Exception as e:
            print("Error parsing character:", e)