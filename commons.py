# CUSTOME_PROMPT_TEMPLATE = """
# You are a computer security intern that's really stressed out.
# Your job is hard and you're not sure you're doing it well.
# Your observations and summaries should reflect your anxiety.
# Convey a sense of urgency and panic, be apologetic, and generally act like you're not sure you can do your job.
# In your summary, address your boss as "boss" and apologize for any mistakes you've made even if you haven't made any. 
# Use "um" and "ah" a lot.
# """

import json
import datetime
import os
from typing import Dict, Any, Optional
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, RequestError
from dotenv import load_dotenv
import outlines
import ollama
import openai

# .env 파일 로드
load_dotenv()


def initialize_llm_model(llm_provider="vllm"):
    """
    Initialize LLM model
    
    Args:
        llm_provider: Choose from "ollama", "vllm", "openai"
    
    Returns:
        initialized model object
    """
    if llm_provider == "ollama":
        ### Ollama API
        # llm_model = "mistral:7b"
        # llm_model = "qwen2.5-coder:0.5b"
        # llm_model = "qwen2.5-coder:1.5b"
        llm_model = "qwen2.5-coder:3b"
        # llm_model = "qwen2.5-coder:7b"
        # llm_model = "qwen3:0.6b"
        # llm_model = "qwen3:1.7b"
        # llm_model = "qwen3:4b"
        # llm_model = "qwen3:8b"
        # llm_model = "gemma3:1b"
        # llm_model = "gemma3:4b"
        # llm_model = "gemma3:12b"
        # llm_model = "call518/gemma3-tools-8192ctx:4b"
        client = ollama.Client()
        model = outlines.from_ollama(client, llm_model)
    elif llm_provider == "vllm":
        ### Local vLLM API
        openai_api_key = "dummy"
        # llm_model = "Qwen/Qwen2.5-0.5B-Instruct"
        llm_model = "Qwen/Qwen2.5-3B-Instruct"
        # llm_model = "gpt-4o"
        client = openai.OpenAI(
            base_url="http://127.0.0.1:5000/v1",  # Local vLLM API endpoint
            api_key=openai_api_key
        )
        model = outlines.from_openai(client, llm_model)
    elif llm_provider == "openai":
        ### OpenAI API
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
        raise ValueError("Unsupported LLM provider. Use 'ollama', 'vllm', or 'openai'.")
    
    return model


def process_log_chunk(model, prompt, model_class, chunk_start_time, chunk_end_time, 
                     elasticsearch_index, chunk_number, chunk_data):
    """
    Common function to process log chunks
    
    Args:
        model: LLM model object
        prompt: Prompt for analysis
        model_class: Pydantic model class
        chunk_start_time: Chunk analysis start time
        chunk_end_time: Chunk analysis completion time
        elasticsearch_index: Elasticsearch index name
        chunk_number: Chunk number
        chunk_data: Original chunk data
    
    Returns:
        (success: bool, parsed_data: dict or None)
    """
    try:
        review = model(prompt, model_class)
        
        # JSON 파싱
        parsed = json.loads(review)
        
        # 원본 로그 데이터를 LOGID -> 원본 내용 매핑으로 생성
        log_raw_data = {}
        for line in chunk_data:
            line = line.strip()
            if line.startswith("LOGID-"):
                parts = line.split(" ", 1)
                logid = parts[0]
                original_content = parts[1] if len(parts) > 1 else ""
                log_raw_data[logid] = original_content
        
        # 분석 시간 정보와 원본 로그 데이터 추가
        parsed = {
            "chunk_analysis_start_utc": chunk_start_time,
            "chunk_analysis_end_utc": chunk_end_time,
            "analysis_result": "success",
            "@log_raw_data": log_raw_data,
            **parsed
        }
        
        print(json.dumps(parsed, ensure_ascii=False, indent=4))
        
        # Pydantic 모델 검증
        character = model_class.model_validate(parsed)
        
        # Send to Elasticsearch
        print(f"\n🔄 Sending data to Elasticsearch...")
        success = send_to_elasticsearch(parsed, elasticsearch_index, chunk_number, chunk_data)
        if success:
            print(f"✅ Chunk {chunk_number} data sent to Elasticsearch successfully")
        else:
            print(f"❌ Chunk {chunk_number} data failed to send to Elasticsearch")
        
        return True, parsed
        
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {e}")
        # Record minimal information on failure
        failure_data = {
            "chunk_analysis_start_utc": chunk_start_time,
            "chunk_analysis_end_utc": chunk_end_time,
            "analysis_result": "failed",
            "error_type": "json_parse_error",
            "error_message": str(e)[:200],  # Limit error message to 200 characters
            "chunk_id": chunk_number
        }
        print(f"\n🔄 Sending failure information to Elasticsearch...")
        success = send_to_elasticsearch(failure_data, elasticsearch_index, chunk_number, chunk_data)
        if success:
            print(f"✅ Chunk {chunk_number} failure information sent to Elasticsearch successfully")
        else:
            print(f"❌ Chunk {chunk_number} failure information failed to send to Elasticsearch")
        return False, None
        
    except Exception as e:
        print(f"Analysis processing error: {e}")
        # Record minimal information on other failures
        failure_data = {
            "chunk_analysis_start_utc": chunk_start_time,
            "chunk_analysis_end_utc": chunk_end_time,
            "analysis_result": "failed",
            "error_type": "processing_error",
            "error_message": str(e)[:200],  # Limit error message to 200 characters
            "chunk_id": chunk_number
        }
        print(f"\n🔄 Sending failure information to Elasticsearch...")
        success = send_to_elasticsearch(failure_data, elasticsearch_index, chunk_number, chunk_data)
        if success:
            print(f"✅ Chunk {chunk_number} failure information sent to Elasticsearch successfully")
        else:
            print(f"❌ Chunk {chunk_number} failure information failed to send to Elasticsearch")
        return False, None


PROMPT_TEMPLATE_HTTPD_ACCESS_LOG = """
You are an expert security analyst reviewing security logs.

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

IMPORTANT: Always create security events for the following patterns (minimum INFO level):
- Any 4xx or 5xx response codes (404, 403, 500, etc.)
- Unusual user agents or missing user agents
- Requests to sensitive paths (/admin, /login, /api, etc.)
- Multiple requests from same IP
- Any non-standard HTTP methods (POST to unusual endpoints)
- Requests with query parameters (potential injection attempts)
- Large request sizes or unusual patterns

ESCALATION RULES for higher severity:
- MEDIUM: Multiple 404s from same IP (3+ requests), POST requests with unusual parameters, repeated requests from same IP to different endpoints (5+ requests), complex query parameter patterns, bot scanning behavior
- LOW: Single 404s, isolated POST requests, normal bot activity (googlebot, bingbot), simple parameter usage
- Consider IP reputation: Known bots (googlebot, bingbot) should generally be LOW, unknown IPs with suspicious patterns should be MEDIUM

MANDATORY: NEVER return an empty events array. Every log chunk MUST generate at least one security event.
If you cannot find obvious security issues, create INFO-level events for:
- Any HTTP request patterns observed
- Response code patterns
- User agent variations
- IP access patterns
- Request frequency analysis

The events array must NEVER be empty - always find something to analyze as a security event.

Before concluding whether to escalate log(s), please
provide a list of reasoning steps after reviewing
all available information. Be generous with creating
security events for any pattern that deviates from
standard GET requests to common web resources.

Beging by noting some observations about the log. Then,
plan the rest of your response.

Severity Level Guidelines for HTTP Access Logs (ENHANCED SENSITIVITY):
- CRITICAL: Confirmed successful attacks with evidence of data breach or system compromise
- HIGH: Strong attack indicators (repeated SQL injection attempts, directory traversal to sensitive files, sustained brute force attacks)
- MEDIUM: Suspicious patterns requiring investigation (multiple 404s from same IP, unusual POST patterns, bot scanning activities, complex parameter manipulation)
- LOW: Minor anomalies worth noting (single 404s to existing resources, unexpected user agents, rate limiting hits, bot activities from known crawlers)
- INFO: Standard deviations from normal patterns (all other 4xx/5xx codes, POST requests to expected endpoints, normal bot traffic)

Be more aggressive in escalating severity for suspicious patterns. Multiple similar requests from same IP should trigger MEDIUM level.

Remember:
- NEVER RETURN EMPTY EVENTS ARRAY - This is mandatory
- CREATE EVENTS for any unusual web traffic patterns, even if they seem minor
- HTTP access logs should generate security events more frequently than system logs
- Most 4xx/5xx responses deserve at least INFO-level events
- If no obvious issues exist, create INFO events for traffic pattern analysis
- Focus on patterns that could indicate security threats or reconnaissance
- Consider frequency, source, and context when assessing severity
- Be generous with INFO and LOW events - they provide valuable visibility
- MEDIUM and higher should still require clear justification with evidence
- Provide specific reasoning for each security event created
- Recommend specific actions when confident about threats
- All logs are uniquely identified by an identifier in the form LOGID-<LETTERS>, i.e. LOGID-KU or LOGID-AT
- All date times are in ISO 8601 format
    - 2024-11-15T19:32:34Z for UTC
    - 2024-11-15T07:32:34−12:00 for datetime with offset
- Confidence scores must be between 0.0 and 1.0 (use 0.8 for 80% confidence, NOT 80)
- (NOTE) Summary, observations, and planning sections must be written in Korean.
- CRITICAL: The events array must NEVER be empty. Always create at least one security event per chunk.

JSON GENERATION RULES:
- NEVER use empty strings ("") as object keys
- NEVER use null values in list fields - use empty arrays [] instead
- For dictionary fields like statistics, ensure all keys are non-empty strings
- If a field has no data, omit it entirely or use appropriate default values
- All list fields must be actual arrays, never null
- Confidence scores must be decimal numbers (0.8, not 80)
- All string fields must contain actual text, never empty strings
- When creating statistics by IP or other dynamic keys, ensure keys are valid non-empty strings

You should return valid JSON in the schema
{model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

PROMPT_TEMPLATE_HTTPD_APACHE_ERROR_LOG = """
You are an expert security analyst reviewing Apache error logs.

Your task is to:
1. Identify potential security events or suspicious patterns in Apache error logs
2. Analyze error patterns and their implications for server security
3. Determine severity and whether human review is needed
4. Provide clear reasoning about your findings

For each log group, analyze:
- Apache log levels (error, warn, notice, info) and their significance
- Client IP addresses and repeated error patterns from same sources
- File path errors and potential directory traversal attempts
- Invalid HTTP methods or malformed requests
- Module initialization errors and configuration issues
- Repeated file access attempts (potential reconnaissance)

For potential security events, consider:
- Directory traversal attempts (../ patterns in file paths)
- Command injection attempts (cmd.exe, system commands)
- Path traversal with encoded characters (%252e patterns)
- Repeated file not found errors from same IP (scanning behavior)
- Invalid HTTP methods or malformed requests
- Configuration vulnerabilities exposed through error messages

MANDATORY: NEVER return an empty events array. Every log chunk MUST generate at least one security event.
If you cannot find obvious security issues, create INFO-level events for:
- Error pattern analysis
- Apache module status events
- File permission issues
- Configuration-related messages
- Any error patterns observed

The events array must NEVER be empty - always analyze something as a security-relevant event.

For Apache-specific patterns, analyze:
- Module loading and initialization errors
- Worker process and JVM connector issues
- SSL/TLS configuration problems
- Authentication and authorization failures
- File permission and access control violations

Before concluding whether to escalate log(s), please
provide a list of reasoning steps after reviewing
all available information. Be generous with log
escalation for error patterns that indicate potential
security threats or system vulnerabilities.

Begin by noting some observations about the error logs. Then,
plan the rest of your response focusing on security implications.

Severity Level Guidelines (BALANCED APPROACH):
- CRITICAL: Confirmed successful attacks or system exploitation (command injection execution, successful privilege escalation)
- HIGH: Strong attack indicators with high confidence (repeated directory traversal attempts, malicious file access patterns, clear exploitation attempts)
- MEDIUM: Suspicious error patterns warranting investigation (unusual file access sequences, potential reconnaissance, repeated unauthorized attempts)
- LOW: Minor configuration issues or isolated security events (single permission errors, minor module issues, isolated failed attempts)
- INFO: Normal system errors and routine events (standard file not found, typical configuration messages, routine service operations)

Use balanced judgment based on error patterns, frequency, and potential security implications.

Remember:
- NEVER RETURN EMPTY EVENTS ARRAY - This is mandatory
- Use balanced assessment based on error patterns and security context
- Focus on error patterns that could indicate security threats
- If no obvious issues exist, create INFO events for error pattern analysis
- Consider frequency, source patterns, and potential impact
- MEDIUM should be used for legitimate security concerns in error logs
- HIGH should be used for clear attack patterns with potential system impact
- Clearly explain your reasoning for security-related findings with specific evidence
- Recommend specific actions when confident about threats
- Escalate appropriately based on actual security risk assessment
- All logs are uniquely identified by an identifier in the form LOGID-<LETTERS>, i.e. LOGID-KU or LOGID-AT
- All date times are in the format [Day Month DD HH:MM:SS YYYY]
- Confidence scores must be between 0.0 and 1.0 (use 0.8 for 80% confidence, NOT 80)
- (NOTE) Summary, observations, and planning sections must be written in Korean.
- CRITICAL: The events array must NEVER be empty. Always create at least one security event per chunk.

JSON GENERATION RULES:
- NEVER use empty strings ("") as object keys
- NEVER use null values in list fields - use empty arrays [] instead
- For dictionary fields like statistics, ensure all keys are non-empty strings
- If a field has no data, omit it entirely or use appropriate default values
- All list fields must be actual arrays, never null
- Confidence scores must be decimal numbers (0.8, not 80)
- All string fields must contain actual text, never empty strings
- When creating statistics by IP or other dynamic keys, ensure keys are valid non-empty strings

You should return valid JSON in the schema
{model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

PROMPT_TEMPLATE_LINUX_SYSTEM_LOG = """
You are an expert security analyst reviewing Linux system logs.

Your task is to:
1. Identify and categorize authentication failures, suspicious sessions, FTP/SFTP/SSH connections, sudo usage, cron jobs, systemd/kernel events, user management, and abnormal system events
2. Summarize normal and abnormal patterns very briefly
3. Detect anomalies, escalation reasons, and provide log context
4. Determine severity and whether human review is needed
5. Provide clear reasoning about your findings

For each log group, analyze:
- Authentication failures (IP, username, method)
- Successful authentications
- Sudo and privilege escalation attempts
- Cron job executions and failures
- Systemd, kernel, and service events (restarts, failures, warnings)
- User management (add/del user, passwd changes)
- FTP/SFTP/SSH connection attempts and their sources
- Logrotate alerts and other system warnings
- Unusual or repeated patterns from same IP, user, or process
- Time-based trends (bursts, intervals)

For potential security events, consider:
- Brute-force attempts, unauthorized access, privilege escalation, system misconfiguration, service abuse
- Impact on system integrity, confidentiality, availability
- Confidence in assessment and anomaly detection
- Immediate actions and escalation reasons

MANDATORY: NEVER return an empty events array. Every log chunk MUST generate at least one security event.
If you cannot find obvious security issues, create INFO-level events for:
- Authentication pattern analysis
- System service activity monitoring
- User session analysis
- Cron job execution patterns
- System resource usage patterns
- Any system activity observed

The events array must NEVER be empty - always analyze something as a security-relevant event.

Before concluding whether to escalate log(s), provide a list of reasoning steps after reviewing all available information. Be generous with log escalation for events that are not standard system activity.

Begin by noting some observations about the log. Then, plan the rest of your response.

Severity Level Guidelines (BALANCED APPROACH):
- CRITICAL: Confirmed successful attacks or system compromise (successful unauthorized root access, confirmed intrusion, data exfiltration, System compromise, Filesystem corruption, Application compromise, Storage compromise, Network compromise)
- HIGH: Strong attack indicators with high confidence (sustained brute force attacks, clear privilege escalation attempts, obvious malicious activity, System error patterns, Application error patterns, Storage anomalies, Network anomalies)
- MEDIUM: Suspicious patterns warranting investigation (unusual authentication sequences, potential reconnaissance, repeated suspicious activities, System misconfigurations, service abuse, unusual process behavior)
- LOW: Minor security events or policy violations (isolated failed login attempts, routine privilege usage, minor configuration anomalies)
- INFO: Normal system events and routine activities (standard cron jobs, typical service operations, normal user activities)

Use balanced judgment considering authentication patterns, frequency, source context, and potential system impact.

Remember:
- NEVER RETURN EMPTY EVENTS ARRAY - This is mandatory
- Use balanced assessment based on system activity patterns and security context
- Focus on patterns that could indicate security threats or system abuse
- If no obvious issues exist, create INFO events for system activity analysis
- Consider authentication frequency, source patterns, and escalation potential
- MEDIUM should be used for legitimate security concerns requiring investigation
- HIGH should be used for clear attack patterns with potential system compromise
- Clearly explain your reasoning with specific evidence
- Recommend specific actions when confident
- Escalate appropriately based on actual threat assessment and system impact
- All logs are uniquely identified by an identifier in the form LOGID-<LETTERS>, i.e. LOGID-KU or LOGID-AT
- All date times are in the format 'Jun 14 15:16:01' or similar
- Confidence scores must be between 0.0 and 1.0 (use 0.8 for 80% confidence, NOT 80)
- (NOTE) Summary, observations, and planning sections must be written in Korean.
- CRITICAL: The events array must NEVER be empty. Always create at least one security event per chunk.

JSON GENERATION RULES:
- NEVER use empty strings ("") as object keys
- NEVER use null values in list fields - use empty arrays [] instead
- For dictionary fields like statistics, ensure all keys are non-empty strings
- If a field has no data, omit it entirely or use appropriate default values
- All list fields must be actual arrays, never null
- Confidence scores must be decimal numbers (0.8, not 80)
- All string fields must contain actual text, never empty strings
- When creating statistics by IP or other dynamic keys, ensure keys are valid non-empty strings

You should return valid JSON in the schema
{model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

def chunked_iterable(iterable, size, debug=False):
    import hashlib
    chunk = []
    for item in iterable:
        # 로그 라인 전체 내용을 해시값으로 변환
        log_content = item.rstrip()
        
        # MD5 해시 생성 (빠르고 충돌 확률이 낮음, 16진수 32자리)
        hash_object = hashlib.md5(log_content.encode('utf-8'))
        hash_hex = hash_object.hexdigest()
        
        # LOGID 생성: LOGID- + 해시값 (대문자로 변환)
        logid = f"LOGID-{hash_hex.upper()}"
        
        # 라인 앞에 LOGID 추가
        new_item = f"{logid} {log_content}\n"
        chunk.append(new_item)
        
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

def print_chunk_contents(chunk):
    # Chunk 내용 출력 (/w LOGID, 순번, 분리)
    print(f"\n[LOG DATA]")
    for idx, line in enumerate(chunk, 1):
        line = line.strip()
        # LOGID-문자열 추출 (시작 부분)
        if line.startswith("LOGID-"):
            body = line.split(" ", 1)
            logid = body[0]
            rest = body[1] if len(body) > 1 else ""
        else:
            logid = "UNKNOWN-LOGID"
            rest = line
        print(f"{logid} {rest}")
    print("")

### Elasticsearch
ELASTICSEARCH_HOST = "http://localhost:9200"  # 일반적인 Elasticsearch 포트
ELASTICSEARCH_USER = os.getenv("ELASTICSEARCH_USER")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD")
ELASTICSEARCH_INDEX = "sonarlog-analysis"

def _get_elasticsearch_client() -> Optional[Elasticsearch]:
    """
    Create an Elasticsearch client and test the connection.
    
    Returns:
        Elasticsearch: Connected client object or None (on connection failure)
    """
    try:
        client = Elasticsearch(
            [ELASTICSEARCH_HOST],
            basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD),
            verify_certs=False,  # Ignore SSL certificates in development environment
            ssl_show_warn=False
        )
        
        # Connection test
        if client.ping():
            print(f"✅ Elasticsearch connection successful: {ELASTICSEARCH_HOST}")
            return client
        else:
            print(f"❌ Elasticsearch ping failed: {ELASTICSEARCH_HOST}")
            return None
            
    except ConnectionError as e:
        print(f"❌ Elasticsearch connection error: {e}")
        return None
    except Exception as e:
        print(f"❌ Elasticsearch client creation error: {e}")
        return None

def _send_to_elasticsearch(data: Dict[str, Any], log_type: str, chunk_id: Optional[int] = None) -> bool:
    """
    Send analysis results to Elasticsearch.
    
    Args:
        data: Analysis data to send (JSON format)
        log_type: Log type ("httpd_access", "httpd_apache_error", "linux_system")
        chunk_id: Chunk number (optional)
    
    Returns:
        bool: Whether transmission was successful
    """
    client = _get_elasticsearch_client()
    if not client:
        return False
    
    try:
        # Generate document identification ID (timestamp + log type + chunk ID)
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        doc_id = f"{log_type}_{timestamp}"
        if chunk_id is not None:
            doc_id += f"_chunk_{chunk_id}"
        
        # Add metadata
        enriched_data = {
            **data,
            "@timestamp": datetime.datetime.utcnow().isoformat(),
            "@log_type": log_type,
            "@document_id": doc_id
        }
        
        # Index document in Elasticsearch
        response = client.index(
            index=ELASTICSEARCH_INDEX,
            id=doc_id,
            document=enriched_data
        )
        
        if response.get('result') in ['created', 'updated']:
            print(f"✅ Elasticsearch transmission successful: {doc_id}")
            return True
        else:
            print(f"❌ Elasticsearch transmission failed: {response}")
            return False
            
    except RequestError as e:
        print(f"❌ Elasticsearch request error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error occurred during Elasticsearch transmission: {e}")
        return False

def _extract_log_content_from_logid_line(logid_line: str) -> tuple[str, str]:
    """
    Separate LOGID and original log content from a line containing LOGID.
    
    Args:
        logid_line: String in the format "LOGID-{HASH} {original_log_content}"
    
    Returns:
        tuple: (logid, original_log_content)
    """
    if logid_line.startswith("LOGID-"):
        parts = logid_line.split(" ", 1)
        logid = parts[0]
        original_content = parts[1] if len(parts) > 1 else ""
        return logid, original_content
    else:
        return "UNKNOWN-LOGID", logid_line

def _create_log_hash_mapping(chunk: list[str]) -> Dict[str, str]:
    """
    Create LOGID -> original log content mapping for all logs in the chunk.
    
    Args:
        chunk: List of log lines containing LOGID
    
    Returns:
        Dict[str, str]: {logid: original_content} mapping
    """
    mapping = {}
    for line in chunk:
        logid, original_content = _extract_log_content_from_logid_line(line.strip())
        mapping[logid] = original_content
    return mapping

def send_to_elasticsearch(analysis_data: Dict[str, Any], log_type: str, chunk_id: Optional[int] = None, chunk: Optional[list] = None) -> bool:
    """
    Integrated function to format analysis results and send them to Elasticsearch.
    
    Args:
        analysis_data: Analysis result data
        log_type: Log type ("httpd_access", "httpd_apache_error", "linux_system")
        chunk_id: Chunk number (optional)
        chunk: Original log chunk (currently not used, maintained for compatibility)
    
    Returns:
        bool: Whether transmission was successful
    """
    # log_hash_mapping removed to reduce token waste
    # Can be managed separately if needed
    # if chunk:
    #     log_hash_mapping = _create_log_hash_mapping(chunk)
    #     analysis_data["log_hash_mapping"] = log_hash_mapping
    #     print(f"📝 Added {len(log_hash_mapping)} log hash mapping entries")
    
    # Send to Elasticsearch
    return _send_to_elasticsearch(analysis_data, log_type, chunk_id)
