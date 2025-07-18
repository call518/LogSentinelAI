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

# .env 파일 로드
load_dotenv()


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
    Elasticsearch 클라이언트를 생성하고 연결을 테스트합니다.
    
    Returns:
        Elasticsearch: 연결된 클라이언트 객체 또는 None (연결 실패시)
    """
    try:
        client = Elasticsearch(
            [ELASTICSEARCH_HOST],
            basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD),
            verify_certs=False,  # 개발 환경에서 SSL 인증서 무시
            ssl_show_warn=False
        )
        
        # 연결 테스트
        if client.ping():
            print(f"✅ Elasticsearch 연결 성공: {ELASTICSEARCH_HOST}")
            return client
        else:
            print(f"❌ Elasticsearch ping 실패: {ELASTICSEARCH_HOST}")
            return None
            
    except ConnectionError as e:
        print(f"❌ Elasticsearch 연결 오류: {e}")
        return None
    except Exception as e:
        print(f"❌ Elasticsearch 클라이언트 생성 오류: {e}")
        return None

def _send_to_elasticsearch(data: Dict[str, Any], log_type: str, chunk_id: Optional[int] = None) -> bool:
    """
    분석 결과를 Elasticsearch에 전송합니다.
    
    Args:
        data: 전송할 분석 데이터 (JSON 형태)
        log_type: 로그 타입 ("httpd_access", "httpd_apache_error", "linux_system")
        chunk_id: 청크 번호 (선택적)
    
    Returns:
        bool: 전송 성공 여부
    """
    client = _get_elasticsearch_client()
    if not client:
        return False
    
    try:
        # 문서 식별 ID 생성 (타임스탬프 + 로그타입 + 청크ID)
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        doc_id = f"{log_type}_{timestamp}"
        if chunk_id is not None:
            doc_id += f"_chunk_{chunk_id}"
        
        # 메타데이터 추가
        enriched_data = {
            **data,
            "@timestamp": datetime.datetime.utcnow().isoformat(),
            "@log_type": log_type,
            "@document_id": doc_id
        }
        
        # Elasticsearch에 문서 인덱싱
        response = client.index(
            index=ELASTICSEARCH_INDEX,
            id=doc_id,
            document=enriched_data
        )
        
        if response.get('result') in ['created', 'updated']:
            print(f"✅ Elasticsearch 전송 성공: {doc_id}")
            return True
        else:
            print(f"❌ Elasticsearch 전송 실패: {response}")
            return False
            
    except RequestError as e:
        print(f"❌ Elasticsearch 요청 오류: {e}")
        return False
    except Exception as e:
        print(f"❌ Elasticsearch 전송 중 오류 발생: {e}")
        return False

def _extract_log_content_from_logid_line(logid_line: str) -> tuple[str, str]:
    """
    LOGID가 포함된 라인에서 LOGID와 원본 로그 내용을 분리합니다.
    
    Args:
        logid_line: "LOGID-{HASH} {original_log_content}" 형태의 문자열
    
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
    청크의 모든 로그에 대해 LOGID -> 원본 로그 내용 매핑을 생성합니다.
    
    Args:
        chunk: LOGID가 포함된 로그 라인들의 리스트
    
    Returns:
        Dict[str, str]: {logid: original_content} 매핑
    """
    mapping = {}
    for line in chunk:
        logid, original_content = _extract_log_content_from_logid_line(line.strip())
        mapping[logid] = original_content
    return mapping

def send_to_elasticsearch(analysis_data: Dict[str, Any], log_type: str, chunk_id: Optional[int] = None, chunk: Optional[list] = None) -> bool:
    """
    분석 결과를 포맷팅하고 Elasticsearch에 전송하는 통합 함수입니다.
    
    Args:
        analysis_data: 분석 결과 데이터
        log_type: 로그 타입 ("httpd_access", "httpd_apache_error", "linux_system")
        chunk_id: 청크 번호 (선택적)
        chunk: 원본 로그 청크 (현재는 사용하지 않음, 호환성을 위해 유지)
    
    Returns:
        bool: 전송 성공 여부
    """
    # log_hash_mapping은 토큰 낭비를 줄이기 위해 제거됨
    # 필요시 별도로 관리할 수 있음
    # if chunk:
    #     log_hash_mapping = _create_log_hash_mapping(chunk)
    #     analysis_data["log_hash_mapping"] = log_hash_mapping
    #     print(f"📝 로그 해시 매핑 {len(log_hash_mapping)}개 항목 추가됨")
    
    # Elasticsearch에 전송
    return _send_to_elasticsearch(analysis_data, log_type, chunk_id)
