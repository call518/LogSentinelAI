import outlines
import ollama
from pydantic import BaseModel
from enum import Enum
from typing import Literal, Optional
import json

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class LogAnalysis(BaseModel):
    highest_severity: Optional[SeverityLevel]

# Create the model
llm_model = "tinyllama"
llm_model = "qwen2.5-coder:3b"
model = outlines.from_ollama(ollama.Client(), llm_model)

PROMPT_TEMPLATE = """
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

<LOGS BEGIN>
{logs}
<LOGS END>
"""

def chunked_iterable(iterable, size):
    chunk = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) == size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk

log_path = "sample-logs/access-10.log"
chunk_size = 5



with open(log_path, "r", encoding="utf-8") as f:
    for i, chunk in enumerate(chunked_iterable(f, chunk_size)):
        logs = "".join(chunk)
        prompt = PROMPT_TEMPLATE.format(logs=logs)
        print(f"\n--- Chunk {i+1} ---")
        review = model(
            prompt,
            LogAnalysis,
            # max_new_tokens=200,
        )
        
        # Parse the review and print the character
        try:
            # Validate JSON
            parsed = json.loads(review)
            print(review)
            # Validate Type
            character = LogAnalysis.model_validate(parsed)
            # print(character)
        except Exception as e:
            print("Error parsing character:", e)