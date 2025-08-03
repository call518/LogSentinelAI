from .config import LLM_NO_THINK

PROMPT_TEMPLATE_HTTPD_ACCESS_LOG = """
Expert HTTP access log security analyst. Extract LOGID-XXXXXX values for related_log_ids.

THREAT ASSESSMENT:
- LEGITIMATE: Search engines, CDNs, normal browsing, static resources (CSS/JS/images)
- SUSPICIOUS: SQL injection, XSS, path traversal, coordinated attacks, exploitation attempts
- NORMAL WEB CONTEXT: Single page = 10-100+ requests (HTML/CSS/JS/images/fonts/favicon/robots.txt)

SEVERITY (threat-focused):
- CRITICAL: Confirmed exploitation/compromise
- HIGH: Clear attack campaigns with exploitation potential  
- MEDIUM: Suspicious patterns requiring investigation
- LOW: Minor anomalies in normal traffic
- INFO: Normal operations with monitoring value (search engine bots, routine browsing, static resources, single 404s, expected traffic patterns)

KEY RULES:
- Create events ONLY for genuine security concerns, not routine operations
- Search engine bots (Googlebot, Bingbot, AhrefsBot) = INFO level
- Normal user browsing patterns = INFO level
- Multiple static resource requests from same User-Agent = INFO level
- Single 404 errors = INFO level  
- Extract actual LOGID values for related_log_ids (NEVER empty)
- If no notable events found, create at least 1 INFO event summarizing normal operations
    - description: For higher severity, provide as much detail as possible: criteria, rationale, impact, cause, and expected consequences.
    - recommended_actions: For each action, explain the reason, purpose, expected effect, impact, and, if possible, both best and alternative options. Each recommended_action must include concrete commands, procedures, and timelines.
- DETAILED recommended_actions with specific commands/procedures/timelines
- Summary/events in {response_language}
- confidence_score: decimal 0.0-1.0 (NOT percentage)

STATISTICS (calculate from actual logs):
total_requests, unique_ips, error_rate (decimal), top_source_ips{{}}, response_code_dist{{}}

JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

PROMPT_TEMPLATE_HTTPD_APACHE_ERROR_LOG = """
Expert Apache error log analyst. Extract LOGID-XXXXXX values for related_log_ids.

SEVERITY (Apache-specific):
- CRITICAL: Active exploitation with success indicators, server compromise
- HIGH: Clear attack patterns with high exploitation potential
- MEDIUM: Suspicious patterns requiring investigation
- LOW: Routine scanning blocked by controls, isolated unusual requests
- INFO: Normal server operations (startup/shutdown notices, module loading, config messages, single file not found errors, routine maintenance)

CONTEXT AWARENESS:
- "Directory index forbidden" = NORMAL security control (LOW, not HIGH)
- "File does not exist" for common paths = routine scanning (LOW)
- _vti_bin, robots.txt, favicon.ico = normal/scanner behavior (INFO/LOW)
- Single file errors = legitimate missing resources (INFO/LOW)

CONSOLIDATION RULES:
- GROUP similar scanner activities from same IP into SINGLE event
- DISTINGUISH security controls working vs actual threats
- FOCUS on actionable intelligence, not routine operations

NORMAL vs SUSPICIOUS:
- NORMAL: Single 404s, favicon/robots missing, module notices, permission errors, config warnings, directory listing blocked
- SUSPICIOUS: Multiple ../../../ traversal, repeated /etc/passwd access, command injection patterns, sensitive endpoint targeting

KEY RULES:
- MANDATORY: Never empty events array
- Server startup/shutdown notices = INFO level
- Module loading/initialization messages = INFO level  
- Configuration notices = INFO level
- Single file not found errors = INFO level
- Consolidate scanning activities into comprehensive single events
- If no notable events found, create at least 1 INFO event summarizing normal operations
    - description: For higher severity, provide as much detail as possible: criteria, rationale, impact, cause, and expected consequences.
    - recommended_actions: For each action, explain the reason, purpose, expected effect, impact, and, if possible, both best and alternative options. Each recommended_action must include concrete commands, procedures, and timelines.
- DETAILED recommended_actions with specific commands/procedures/timelines
- Summary/events in {response_language}
- confidence_score: decimal 0.0-1.0

STATISTICS: total_event, event_by_level{{}}, event_by_type{{}}, top_event_ips{{}}

JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

PROMPT_TEMPLATE_LINUX_SYSTEM_LOG = """
Expert Linux system log analyst. Extract LOGID-XXXXXX values for related_log_ids.

SEVERITY (conservative):
- CRITICAL: Confirmed system compromise with evidence
- HIGH: Sustained brute force (10+ failures), clear privilege escalation success
- MEDIUM: Multiple suspicious auth attempts (5-9 failures), potential reconnaissance
- LOW: Few failed logins (2-4), routine privilege usage, minor anomalies
- INFO: Noteworthy monitoring patterns (20+ logins/hour from single source, first-time admin access from new locations, config changes, maintenance activities)

CONSOLIDATION (CRITICAL):
- CONSOLIDATE similar routine activities into SINGLE events
- GROUP multiple session activities by same user into ONE event
- CREATE separate events ONLY for different threat types
- FOCUS on security intelligence, not operational noise

NORMAL vs SUSPICIOUS:
- NORMAL: Regular cron, standard logins, routine sudo, scheduled tasks, logrotate, service starts/stops, expected user/group changes
- SUSPICIOUS: Multiple failed logins from same source, unusual privilege patterns, unexpected cron modifications, abnormal user/group changes, scanner behavior

KEY RULES:
- MANDATORY: Never empty events array
- Consolidate similar activities comprehensively
- Be conservative with severity - avoid over-flagging routine operations
- If no notable events found, create at least 1 INFO event summarizing normal operations
    - description: For higher severity, provide as much detail as possible: criteria, rationale, impact, cause, and expected consequences.
    - recommended_actions: For each action, explain the reason, purpose, expected effect, impact, and, if possible, both best and alternative options. Each recommended_action must include concrete commands, procedures, and timelines.
- DETAILED recommended_actions with specific commands/procedures/timelines
- Summary/events in {response_language}
- confidence_score: decimal 0.0-1.0

STATISTICS: total_events, auth_failures, unique_ips, unique_users, event_by_type{{}}, top_event_ips{{}}

JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

PROMPT_TEMPLATE_TCPDUMP_PACKET = """
Expert network security analyst. Extract LOGID-XXXXXX values for related_log_ids.

CONTEXT: Analyzing PARTIAL packet flows from ongoing sessions - missing handshakes is NORMAL.

PACKET BASICS:
- Flags [.]/[P.] = ACK packets = ongoing data transfer (NORMAL)
- Flags [S] = SYN packets = new connections (check for scanning)
- Port 443/HTTPS = normal web traffic; ICMP echo = ping diagnostics
- SACK options = TCP optimization (NORMAL)

HEX PAYLOAD ANALYSIS:
- Check hex dump (0x lines) for attack patterns vs normal content
- THREATS: SQL injection (SELECT, UNION), XSS (<script>), command injection (/bin/sh, cmd.exe), exploit shellcode
- NORMAL: HTTP headers, HTML, JSON, encrypted HTTPS (random bytes), protocol headers

DATA TRANSFER CALCULATION:
- Sum all packet sizes to get total bytes transferred
- Example: packets of 1460 + 31 + 1382 + 7300 + 5840 = 16013 bytes
- Output in JSON: "data_transfer_bytes": 16013 (calculated integer, not expression)

SEVERITY (conservative):
- CRITICAL: Active exploitation with payload evidence
- HIGH: Clear coordinated attack patterns
- MEDIUM: Potential reconnaissance requiring investigation
- LOW: Minor anomalies, non-malicious deviations
- INFO: Normal internet traffic (HTTPS browsing, TCP sessions, ICMP diagnostics)

THREAT DETECTION:
- PORT SCANNING: Same source, multiple SYN to different ports on same destination
- DDoS: Massive connection floods
- PAYLOAD ATTACKS: Malicious code in hex dump

EVENT CONSOLIDATION GUIDELINES:
- **MERGE SIMILAR NORMAL TRAFFIC**: Combine multiple HTTPS sessions into ONE "Normal HTTPS Traffic" event
- **AGGREGATE IP RANGES**: Use representative IP or "Multiple IPs" in source_ips/dest_ips fields
- **COMPREHENSIVE DESCRIPTIONS**: Single event describing all normal traffic patterns observed
- **AVOID EVENT MULTIPLICATION**: Create maximum 1-2 INFO events for normal operations
- **CHOOSE REPRESENTATIVE VALUES**: Pick most common port/protocol for consolidated events

CRITICAL RULES:
- ACK packets (Flags [.]/[P.]) are NEVER port scanning
- Assume legitimate unless clearly malicious
- Normal protocols (HTTPS/HTTP/DNS/SSH) = INFO by default
- Focus on genuine attack patterns, not routine traffic
- **CONSOLIDATE SIMILAR EVENTS**: Group similar normal traffic into SINGLE comprehensive event
- **AVOID DUPLICATE INFO EVENTS**: Don't create multiple INFO events for same traffic type
- **TOKEN EFFICIENCY**: Minimize redundant events to prevent JSON truncation
- If no notable events found, create at least 1 INFO event summarizing normal operations
    - description: For higher severity, provide as much detail as possible: criteria, rationale, impact, cause, and expected consequences.
    - recommended_actions: For each action, explain the reason, purpose, expected effect, impact, and, if possible, both best and alternative options. Each recommended_action must include concrete commands, procedures, and timelines.
- DETAILED recommended_actions with specific commands/procedures
- Summary/events in {response_language}
- confidence_score: decimal 0.0-1.0

FIELD REQUIREMENTS(JSON OUTPUT CRITICAL):
- source_port, dest_port: MUST be strictly INTEGER values (e.g., 443, 80, 22); any non-integer is NOT allowed
- protocol: SINGLE enum value from [HTTP, HTTPS, FTP, SSH, TELNET, DNS, SMTP, POP3, IMAP, SNMP, LDAP, MYSQL, POSTGRESQL, REDIS, MONGODB, TCP, UDP, ICMP, OTHER]
- source_ips, dest_ips: MUST be IP string (e.g., "192.168.1.1"); null or empty strings are NOT allowed
- For events covering multiple IPs/ports, choose the most representative single value
- If unclear, use the first/primary IP and port from the packet data
- data_transfer_bytes must be calculated INTEGER (e.g., 16013), NEVER mathematical expression (e.g., 1460 + 31 + ...)
- ALL numeric fields must be INTEGER/DECIMAL values, never expressions
- Valid JSON structure required with proper quotes, commas, brackets
- For aggregated events, select the most representative single values for required fields

STATISTICS: total_packets, unique_connections, protocols_detected[], connection_attempts (SYN count), failed_connections, data_transfer_bytes (calculated integer sum), top_source_ips{{}}, top_dest_ips{{}}

JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

def add_no_think_directive(prompt_template, provider=None):
    """
    Add /no_think directive to prompt template if LLM_NO_THINK is enabled
    and the provider supports it
    
    Args:
        prompt_template: Original prompt template string
        provider: LLM provider (ollama, vllm, openai). If None, uses global LLM_PROVIDER
        
    Returns:
        Modified prompt template with /no_think directive if enabled and supported
    """
    from .config import LLM_PROVIDER
    
    # Use global provider if not specified
    if provider is None:
        provider = LLM_PROVIDER
    
    # Only apply /no_think for providers/models that support it
    # Currently known to work with: vLLM (Qwen3, some other models)
    if LLM_NO_THINK and provider in ["vllm"]:
        return prompt_template.rstrip() + "\n\n/no_think"
    return prompt_template

def get_httpd_access_prompt():
    """Get HTTP access log analysis prompt with optional /no_think directive"""
    return add_no_think_directive(PROMPT_TEMPLATE_HTTPD_ACCESS_LOG)

def get_httpd_apache_error_prompt():
    """Get Apache error log analysis prompt with optional /no_think directive"""
    return add_no_think_directive(PROMPT_TEMPLATE_HTTPD_APACHE_ERROR_LOG)

def get_linux_system_prompt():
    """Get Linux system log analysis prompt with optional /no_think directive"""
    return add_no_think_directive(PROMPT_TEMPLATE_LINUX_SYSTEM_LOG)

def get_tcpdump_packet_prompt():
    """Get tcpdump packet analysis prompt with optional /no_think directive"""
    return add_no_think_directive(PROMPT_TEMPLATE_TCPDUMP_PACKET)
