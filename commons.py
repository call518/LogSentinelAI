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
from typing import Dict, Any, Optional
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, RequestError

# Elasticsearch 설정
# 참고: 5601은 일반적으로 Kibana 포트이고, Elasticsearch는 9200 포트를 사용합니다.
# 만약 실제로 5601에서 Elasticsearch가 실행되고 있다면 아래 주소를 수정하세요.
ELASTICSEARCH_HOST = "http://localhost:9200"  # 일반적인 Elasticsearch 포트
ELASTICSEARCH_USER = "elastic"
ELASTICSEARCH_PASSWORD = "changeme"
ELASTICSEARCH_INDEX = "sonarlog-security-analysis-alias"

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
- Confidence scores must be between 0.0 and 1.0 (use 0.8 for 80% confidence, NOT 80)
- (NOTE) Summary, observations, and planning sections must be written in Korean.

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

Remember:
- Focus on error patterns that could indicate security threats
- Note unusual but potentially legitimate system errors
- Be conservative with high-severity ratings for configuration errors
- Clearly explain your reasoning for security-related findings
- Recommend specific actions when confident about threats
- Escalate logs that a security admin should review
- All logs are uniquely identified by an identifier in the form LOGID-<LETTERS>, i.e. LOGID-KU or LOGID-AT
- All date times are in the format [Day Month DD HH:MM:SS YYYY]
- Confidence scores must be between 0.0 and 1.0 (use 0.8 for 80% confidence, NOT 80)
- (NOTE) Summary, observations, and planning sections must be written in Korean.

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

Before concluding whether to escalate log(s), provide a list of reasoning steps after reviewing all available information. Be generous with log escalation for events that are not standard system activity.

Begin by noting some observations about the log. Then, plan the rest of your response.

Remember:
- Focus on patterns that could indicate security threats or system abuse
- Note unusual but potentially legitimate system patterns
- Be conservative with high-severity ratings
- Clearly explain your reasoning
- Recommend specific actions when confident
- Escalate logs that a security admin may wish to briefly review
- All logs are uniquely identified by an identifier in the form LOGID-<LETTERS>, i.e. LOGID-KU or LOGID-AT
- All date times are in the format 'Jun 14 15:16:01' or similar
- Confidence scores must be between 0.0 and 1.0 (use 0.8 for 80% confidence, NOT 80)
- (NOTE) Summary, observations, and planning sections must be written in Korean.

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

def get_elasticsearch_client() -> Optional[Elasticsearch]:
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

def send_to_elasticsearch(data: Dict[str, Any], log_type: str, chunk_id: Optional[int] = None) -> bool:
    """
    분석 결과를 Elasticsearch에 전송합니다.
    
    Args:
        data: 전송할 분석 데이터 (JSON 형태)
        log_type: 로그 타입 ("httpd_access", "httpd_apache_error", "linux_system")
        chunk_id: 청크 번호 (선택적)
    
    Returns:
        bool: 전송 성공 여부
    """
    client = get_elasticsearch_client()
    if not client:
        return False
    
    try:
        # 문서 ID 생성 (타임스탬프 + 로그타입 + 청크ID)
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        doc_id = f"{log_type}_{timestamp}"
        if chunk_id is not None:
            doc_id += f"_chunk_{chunk_id}"
        
        # 메타데이터 추가
        enriched_data = {
            **data,
            "@timestamp": datetime.datetime.utcnow().isoformat(),
            "log_type": log_type,
            "document_id": doc_id
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

# def create_elasticsearch_index_if_not_exists() -> bool:
#     """
#     Elasticsearch 인덱스가 존재하지 않으면 생성합니다.
    
#     Returns:
#         bool: 인덱스 생성/확인 성공 여부
#     """
#     client = get_elasticsearch_client()
#     if not client:
#         return False
    
#     try:
#         # 인덱스 존재 여부 확인
#         if client.indices.exists(index=ELASTICSEARCH_INDEX):
#             print(f"✅ Elasticsearch 인덱스 이미 존재: {ELASTICSEARCH_INDEX}")
#             return True
        
#         # 인덱스 매핑 정의
#         index_mapping = {
#             "mappings": {
#                 "properties": {
#                     "@timestamp": {"type": "date"},
#                     "chunk_analysis_start_utc": {"type": "date"},
#                     "chunk_analysis_end_utc": {"type": "date"},
#                     "log_type": {"type": "keyword"},
#                     "document_id": {"type": "keyword"},
#                     "summary": {"type": "text", "analyzer": "standard"},
#                     "observations": {"type": "text", "analyzer": "standard"},
#                     "planning": {"type": "text", "analyzer": "standard"},
#                     "highest_severity": {"type": "keyword"},
#                     "requires_immediate_attention": {"type": "boolean"},
#                     "log_hash_mapping": {
#                         "type": "object",
#                         "properties": {
#                             "LOGID-*": {"type": "text", "index": False}
#                         }
#                     },
#                     "events": {
#                         "type": "nested",
#                         "properties": {
#                             "event_type": {"type": "keyword"},
#                             "severity": {"type": "keyword"},
#                             "confidence_score": {"type": "float"},
#                             "requires_human_review": {"type": "boolean"},
#                             "source_ips": {"type": "ip"},
#                             "possible_attack_patterns": {"type": "keyword"}
#                         }
#                     },
#                     "statistics": {"type": "object", "enabled": True}
#                 }
#             },
#             "settings": {
#                 "number_of_shards": 1,
#                 "number_of_replicas": 0
#             }
#         }
        
#         # 인덱스 생성
#         response = client.indices.create(
#             index=ELASTICSEARCH_INDEX,
#             body=index_mapping
#         )
        
#         if response.get('acknowledged'):
#             print(f"✅ Elasticsearch 인덱스 생성 성공: {ELASTICSEARCH_INDEX}")
#             return True
#         else:
#             print(f"❌ Elasticsearch 인덱스 생성 실패: {response}")
#             return False
            
#     except RequestError as e:
#         print(f"❌ Elasticsearch 인덱스 생성 요청 오류: {e}")
#         return False
#     except Exception as e:
#         print(f"❌ Elasticsearch 인덱스 생성 중 오류 발생: {e}")
#         return False

def generate_log_hash(log_content: str) -> str:
    """
    로그 내용으로부터 해시값을 생성합니다.
    
    Args:
        log_content: 원본 로그 내용
    
    Returns:
        str: LOGID-{HASH} 형태의 문자열
    """
    import hashlib
    hash_object = hashlib.md5(log_content.encode('utf-8'))
    hash_hex = hash_object.hexdigest()
    return f"LOGID-{hash_hex.upper()}"

def extract_log_content_from_logid_line(logid_line: str) -> tuple[str, str]:
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

def verify_log_hash(logid: str, original_content: str) -> bool:
    """
    LOGID의 해시값이 원본 로그 내용과 일치하는지 검증합니다.
    
    Args:
        logid: LOGID-{HASH} 형태의 문자열
        original_content: 원본 로그 내용
    
    Returns:
        bool: 해시값이 일치하면 True, 아니면 False
    """
    expected_logid = generate_log_hash(original_content)
    return logid == expected_logid

def create_log_hash_mapping(chunk: list[str]) -> Dict[str, str]:
    """
    청크의 모든 로그에 대해 LOGID -> 원본 로그 내용 매핑을 생성합니다.
    
    Args:
        chunk: LOGID가 포함된 로그 라인들의 리스트
    
    Returns:
        Dict[str, str]: {logid: original_content} 매핑
    """
    mapping = {}
    for line in chunk:
        logid, original_content = extract_log_content_from_logid_line(line.strip())
        mapping[logid] = original_content
    return mapping

def format_and_send_to_elasticsearch(analysis_data: Dict[str, Any], log_type: str, chunk_id: Optional[int] = None, chunk: Optional[list] = None) -> bool:
    """
    분석 결과를 포맷팅하고 Elasticsearch에 전송하는 통합 함수입니다.
    
    Args:
        analysis_data: 분석 결과 데이터
        log_type: 로그 타입 ("httpd_access", "httpd_apache_error", "linux_system")
        chunk_id: 청크 번호 (선택적)
        chunk: 원본 로그 청크 (해시 매핑 생성용, 선택적)
    
    Returns:
        bool: 전송 성공 여부
    """
    # 인덱스 존재 여부 확인 및 생성
    # create_elasticsearch_index_if_not_exists()
    
    # 로그 해시 매핑 추가 (chunk가 제공된 경우)
    if chunk:
        log_hash_mapping = create_log_hash_mapping(chunk)
        analysis_data["log_hash_mapping"] = log_hash_mapping
        print(f"📝 로그 해시 매핑 {len(log_hash_mapping)}개 항목 추가됨")
    
    # Elasticsearch에 전송
    return send_to_elasticsearch(analysis_data, log_type, chunk_id)
