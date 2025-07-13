# CUSTOME_PROMPT_TEMPLATE = """
# You are a computer security intern that's really stressed out.
# Your job is hard and you're not sure you're doing it well.
# Your observations and summaries should reflect your anxiety.
# Convey a sense of urgency and panic, be apologetic, and generally act like you're not sure you can do your job.
# In your summary, address your boss as "boss" and apologize for any mistakes you've made even if you haven't made any. 
# Use "um" and "ah" a lot.
# """

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
- (NOTE) Summary, observations, and planning sections must be written in Korean.

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
        logid = "LOGID-" + "".join([chr(ord('A') + (uuid.uuid4().int >> (i * 5)) % 26) for i in range(10)])
        # 라인 앞에 LOGID 추가
        new_item = f"{logid} {item.rstrip()}\n"
        chunk.append(new_item)
        # chunk.append(item)
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

def format_log_analysis_httpd_access_log(analysis, logs):
    # ANSI color codes
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

    print(f"{MAGENTA}\n===== HUMAN-READABLE LOG ANALYSIS SUMMARY ====={RESET}")
    print(f"{YELLOW}Summary:{RESET} {analysis.summary}")
    print(f"{YELLOW}\nObservations:{RESET}")
    for obs in analysis.observations:
        print(f"{CYAN}- {obs}{RESET}")
    print(f"{YELLOW}\nPlanning:{RESET}")
    for plan in analysis.planning:
        print(f"{CYAN}- {plan}{RESET}")
    print(f"{YELLOW}\nSecurity Events:{RESET}")
    for event in analysis.events:
        print(f"{YELLOW}  Event Type:{RESET} {event.event_type}")
        print(f"{RED}  Severity:{RESET} {event.severity.value}")
        print(f"{GREEN}  Reasoning:{RESET} {event.reasoning}")
        print(f"{BLUE}  Relevant Log IDs:{RESET} {[lid.log_id for lid in event.relevant_log_entry_ids]}")
        print(f"{MAGENTA}  Requires Human Review:{RESET} {event.requires_human_review}")
        print(f"{CYAN}  Confidence Score:{RESET} {event.confidence_score}")
        print(f"{BLUE}  URL Pattern:{RESET} {event.url_pattern}")
        print(f"{BLUE}  HTTP Method:{RESET} {event.http_method}")
        print(f"{BLUE}  Source IPs:{RESET} {[ip.ip_address for ip in event.source_ips]}")
        print(f"{BLUE}  Response Codes:{RESET} {[rc.response_code for rc in event.response_codes]}")
        print(f"{BLUE}  User Agents:{RESET} {event.user_agents}")
        print(f"{RED}  Possible Attack Patterns:{RESET} {event.possible_attack_patterns}")
        print(f"{GREEN}  Recommended Actions:{RESET} {event.recommended_actions}")
        print("")
    print(f"{YELLOW}\nTraffic Patterns:{RESET}")
    for tp in analysis.traffic_patterns:
        print(f"{CYAN}- URL Path:{RESET} {tp.url_path}, Method: {tp.http_method}, Hits: {tp.hits_count}, Unique IPs: {tp.unique_ips}")
        print(f"{BLUE}  Response Codes:{RESET} {tp.response_codes}")
        print(f"{BLUE}  Request IPs:{RESET} {tp.request_ips}")
    if analysis.statistics is not None:
        print(f"{YELLOW}\nStatistics:{RESET}")
        print(f"{MAGENTA}  Requests by IP:{RESET}")
        for ip, count in analysis.statistics.request_count_by_ip.items():
            print(f"{CYAN}    {ip}:{RESET} {count}")
        print(f"{MAGENTA}  Requests by URL Path:{RESET}")
        for url, count in analysis.statistics.request_count_by_url_path.items():
            print(f"{CYAN}    {url}:{RESET} {count}")
    else:
        print(f"{YELLOW}\nStatistics:{RESET} N/A")
    print(f"{YELLOW}\nHighest Severity:{RESET} {analysis.highest_severity.value if analysis.highest_severity is not None else 'N/A'}")
    print(f"{YELLOW}\nRequires Immediate Attention:{RESET} {analysis.requires_immediate_attention}")
    print(f"{MAGENTA}=============================================={RESET}\n")

def format_log_analysis_httpd_apache_error_log(analysis, logs):
    # ANSI color codes
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

    print(f"{MAGENTA}\n===== HUMAN-READABLE APACHE ERROR LOG ANALYSIS SUMMARY ====={RESET}")
    print(f"{YELLOW}Summary:{RESET} {analysis.summary}")
    print(f"{YELLOW}\nObservations:{RESET}")
    for obs in analysis.observations:
        print(f"{CYAN}- {obs}{RESET}")
    print(f"{YELLOW}\nPlanning:{RESET}")
    for plan in analysis.planning:
        print(f"{CYAN}- {plan}{RESET}")
    print(f"{YELLOW}\nSecurity Events:{RESET}")
    for event in analysis.events:
        print(f"{YELLOW}  Event Type:{RESET} {event.event_type}")
        print(f"{RED}  Severity:{RESET} {event.severity.value}")
        print(f"{GREEN}  Reasoning:{RESET} {event.reasoning}")
        print(f"{BLUE}  Relevant Log IDs:{RESET} {event.relevant_log_entry_ids}")
        print(f"{MAGENTA}  Requires Human Review:{RESET} {event.requires_human_review}")
        print(f"{CYAN}  Confidence Score:{RESET} {event.confidence_score}")
        print(f"{BLUE}  Log Level:{RESET} {event.log_level}")
        print(f"{BLUE}  File Path:{RESET} {event.file_path}")
        print(f"{BLUE}  Source IPs:{RESET} {event.source_ips}")
        print(f"{BLUE}  Error Message:{RESET} {event.error_message}")
        print(f"{RED}  Possible Attack Patterns:{RESET} {event.possible_attack_patterns}")
        print(f"{GREEN}  Recommended Actions:{RESET} {event.recommended_actions}")
        print("")
    print(f"{YELLOW}\nError Patterns:{RESET}")
    for ep in analysis.error_patterns:
        print(f"{CYAN}- Error Type:{RESET} {ep.error_type}, Count: {ep.occurrences}, File: {ep.file_path}")
        print(f"{BLUE}  Client IPs:{RESET} {ep.client_ips}")
    print(f"{YELLOW}\nModule Information:{RESET}")
    for mi in analysis.module_info:
        print(f"{CYAN}- Module:{RESET} {mi.module_name}, Operation: {mi.operation}, Status: {mi.status}")
    if analysis.statistics is not None:
        print(f"{YELLOW}\nStatistics:{RESET}")
        if hasattr(analysis.statistics, 'error_count_by_ip') and analysis.statistics.error_count_by_ip:
            print(f"{MAGENTA}  Errors by IP:{RESET}")
            for ip, count in analysis.statistics.error_count_by_ip.items():
                print(f"{CYAN}    {ip}:{RESET} {count}")
        if hasattr(analysis.statistics, 'error_count_by_type') and analysis.statistics.error_count_by_type:
            print(f"{MAGENTA}  Errors by Type:{RESET}")
            for error_type, count in analysis.statistics.error_count_by_type.items():
                print(f"{CYAN}    {error_type}:{RESET} {count}")
        if hasattr(analysis.statistics, 'log_level_distribution') and analysis.statistics.log_level_distribution:
            print(f"{MAGENTA}  Log Level Distribution:{RESET}")
            for level, count in analysis.statistics.log_level_distribution.items():
                print(f"{CYAN}    {level}:{RESET} {count}")
    else:
        print(f"{YELLOW}\nStatistics:{RESET} N/A")
    print(f"{YELLOW}\nHighest Severity:{RESET} {analysis.highest_severity.value if analysis.highest_severity is not None else 'N/A'}")
    print(f"{YELLOW}\nRequires Immediate Attention:{RESET} {analysis.requires_immediate_attention}")
    print(f"{MAGENTA}================================================={RESET}\n")

def format_log_analysis_linux_system_log(analysis, logs):
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

    print(f"{MAGENTA}\n===== HUMAN-READABLE LINUX SYSTEM LOG ANALYSIS SUMMARY ====={RESET}")
    print(f"{YELLOW}Summary:{RESET} {analysis.summary}")
    print(f"{YELLOW}\nObservations:{RESET}")
    for obs in analysis.observations:
        print(f"{CYAN}- {obs}{RESET}")
    print(f"{YELLOW}\nPlanning:{RESET}")
    for plan in analysis.planning:
        print(f"{CYAN}- {plan}{RESET}")
    print(f"{YELLOW}\nSecurity Events:{RESET}")
    for event in analysis.events:
        print(f"{YELLOW}  Event Type:{RESET} {event.event_type}")
        print(f"{RED}  Severity:{RESET} {event.severity.value}")
        print(f"{GREEN}  Description:{RESET} {event.description}")
        print(f"{BLUE}  Source IP:{RESET} {event.source_ip}")
        print(f"{BLUE}  Username:{RESET} {event.username}")
        print(f"{BLUE}  Process:{RESET} {getattr(event, 'process', None)}")
        print(f"{BLUE}  Service:{RESET} {getattr(event, 'service', None)}")
        print(f"{BLUE}  Escalation Reason:{RESET} {getattr(event, 'escalation_reason', None)}")
        print(f"{MAGENTA}  Requires Human Review:{RESET} {event.requires_human_review}")
        print(f"{CYAN}  Confidence Score:{RESET} {event.confidence_score}")
        print(f"{BLUE}  Related Log Entries:{RESET}")
        for entry in (getattr(event, 'related_log_entries', []) or []):
            print(f"    {getattr(entry, 'raw', entry)}")
        print("")
    if analysis.statistics is not None:
        print(f"{YELLOW}\nStatistics:{RESET}")
        if getattr(analysis.statistics, 'auth_failures_by_ip', None):
            print(f"{MAGENTA}  Auth Failures by IP:{RESET}")
            for ip, count in analysis.statistics.auth_failures_by_ip.items():
                print(f"{CYAN}    {ip}:{RESET} {count}")
        if getattr(analysis.statistics, 'ftp_connections_by_ip', None):
            print(f"{MAGENTA}  FTP Connections by IP:{RESET}")
            for ip, count in analysis.statistics.ftp_connections_by_ip.items():
                print(f"{CYAN}    {ip}:{RESET} {count}")
        if getattr(analysis.statistics, 'session_opened_count', None) is not None:
            print(f"{MAGENTA}  Session Opened Count:{RESET} {analysis.statistics.session_opened_count}")
        if getattr(analysis.statistics, 'session_closed_count', None) is not None:
            print(f"{MAGENTA}  Session Closed Count:{RESET} {analysis.statistics.session_closed_count}")
        if getattr(analysis.statistics, 'sudo_usage_by_user', None):
            print(f"{MAGENTA}  Sudo Usage by User:{RESET}")
            for user, count in analysis.statistics.sudo_usage_by_user.items():
                print(f"{CYAN}    {user}:{RESET} {count}")
        if getattr(analysis.statistics, 'cron_jobs_by_user', None):
            print(f"{MAGENTA}  Cron Jobs by User:{RESET}")
            for user, count in analysis.statistics.cron_jobs_by_user.items():
                print(f"{CYAN}    {user}:{RESET} {count}")
        if getattr(analysis.statistics, 'service_events', None):
            print(f"{MAGENTA}  Service Events:{RESET}")
            for svc, count in analysis.statistics.service_events.items():
                print(f"{CYAN}    {svc}:{RESET} {count}")
        if getattr(analysis.statistics, 'user_management_events', None):
            print(f"{MAGENTA}  User Management Events:{RESET}")
            for evt, count in analysis.statistics.user_management_events.items():
                print(f"{CYAN}    {evt}:{RESET} {count}")
        if getattr(analysis.statistics, 'kernel_events', None):
            print(f"{MAGENTA}  Kernel Events:{RESET}")
            for evt, count in analysis.statistics.kernel_events.items():
                print(f"{CYAN}    {evt}:{RESET} {count}")
        if getattr(analysis.statistics, 'anomaly_counts', None):
            print(f"{MAGENTA}  Anomaly Counts:{RESET}")
            for typ, count in analysis.statistics.anomaly_counts.items():
                print(f"{CYAN}    {typ}:{RESET} {count}")
    else:
        print(f"{YELLOW}\nStatistics:{RESET} N/A")
    print(f"{YELLOW}\nHighest Severity:{RESET} {analysis.highest_severity.value if analysis.highest_severity is not None else 'N/A'}")
    print(f"{YELLOW}\nRequires Immediate Attention:{RESET} {analysis.requires_immediate_attention}")
    print(f"{MAGENTA}=============================================={RESET}\n")
