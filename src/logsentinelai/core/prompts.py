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

CRITICAL UNDERSTANDING: THIS LOG CONTAINS NORMAL INTERNET TRAFFIC

PARTIAL FLOW ANALYSIS CONTEXT:
- You are seeing PARTIAL packet flows from ongoing sessions, not complete connections
- Many packets are middle/end of existing sessions - this is NORMAL
- Do NOT flag partial flows as suspicious - focus on clear anomalies only
- Established sessions showing data transfer = NORMAL even without seeing SYN/handshake
- Missing context ≠ suspicious behavior

PACKET ANALYSIS BASICS:
- "Flags [P.]" or "Flags [.]" = ACK packets = ONGOING data transfer (NORMAL)
- "Flags [S]" = SYN packets = NEW connection attempts (check for scanning)
- HTTPS port 443 data transfer = NORMAL web browsing/file transfer
- SACK options = TCP optimization = NORMAL network efficiency feature
- ICMP echo = ping packets = NORMAL network diagnostics

HEX PAYLOAD ANALYSIS:
- EXAMINE hex dump (0x lines) for readable text and suspicious patterns
- THREAT INDICATORS in hex: SQL injection keywords (SELECT, UNION, DROP), XSS payloads (<script>, javascript:), command injection (sh, bash, cmd.exe), exploit shellcode patterns, malicious URLs/domains
- NORMAL PATTERNS in hex: HTTP headers, HTML content, JSON data, encrypted HTTPS traffic (random-looking bytes), standard protocol headers
- DECODE ASCII from hex when possible to identify attack payloads vs normal content
- ESCALATE if hex contains clear exploitation attempts, suspicious commands, or malicious code patterns

CHUNK-BASED ASSESSMENT GUIDELINES:
- CONSERVATIVE APPROACH: When seeing partial flows, assume legitimate unless clearly malicious
- ANOMALY FOCUS: Look for obvious deviations (multiple SYN to different ports, malformed packets, suspicious payloads)
- SESSION CONTINUITY: Multiple packets between same IP:port pairs = ongoing legitimate session
- BASELINE ASSUMPTION: Standard protocols (HTTPS, HTTP, DNS, SSH) are legitimate by default
- ESCALATION CRITERIA: Only flag when patterns clearly indicate attack behavior within visible chunk

BEFORE CREATING ANY HIGH/CRITICAL EVENTS:
1. **CHECK TCP FLAGS**: Are these SYN packets to multiple different ports? Or just ACK packets?
2. **VERIFY ATTACK PATTERN**: Same source scanning MULTIPLE DIFFERENT ports on SAME destination?
3. **CONFIRM THREAT**: Does this indicate actual malicious activity or normal internet usage?

CRITICAL RULE: **ACK PACKETS (Flags [.] or [P.]) ARE NEVER PORT SCANNING**

NORMAL TRAFFIC PATTERNS (DO NOT FLAG AS SUSPICIOUS):
- Multiple ACK packets between same IP pairs = ongoing HTTPS/TCP sessions
- Port 443 traffic with SACK options = normal file download/upload/browsing
- Different sources connecting to different destinations = normal distributed internet traffic
- ICMP echo requests = normal ping/diagnostic traffic
- TCP sequence number progression = normal data flow

ACTUAL THREATS TO DETECT:
- **PORT SCANNING**: Same source sending SYN to MULTIPLE ports on SAME destination
- **DDoS**: Massive connection floods from many sources
- **PROTOCOL ATTACKS**: Malformed packets, exploit payloads
- **PAYLOAD THREATS**: Malicious code/commands in hex dump, SQL injection in packet data, XSS payloads, shellcode patterns, suspicious file transfers

SEVERITY (be extremely conservative):
- CRITICAL: Active successful exploitation with payload evidence
- HIGH: Clear coordinated attack patterns with multiple threat indicators
- MEDIUM: Potential reconnaissance requiring further investigation
- LOW: Minor network anomalies
- INFO: Normal traffic with noteworthy monitoring patterns

EXAMPLES OF NORMAL TRAFFIC (NOT THREATS):
- "150.165.17.177.53039 > 45.121.183.6.443: Flags [.]" = HTTPS data transfer
- "202.244.39.51.56172 > 13.154.148.235.443: Flags [P.]" = HTTPS data with push flag
- "IP 203.141.114.197 > 41.31.64.203: ICMP echo request" = ping diagnostic
- Hex containing HTTP headers, HTML content, encrypted HTTPS data = NORMAL
- Random-looking hex bytes on port 443 = encrypted HTTPS traffic = NORMAL

EXAMPLES OF SUSPICIOUS HEX PATTERNS (INVESTIGATE):
- Readable SQL injection: "SELECT * FROM users" or "UNION SELECT password"
- XSS payloads: "<script>alert" or "javascript:eval"
- Command injection: "/bin/sh", "cmd.exe", "bash -c"
- File paths: "/etc/passwd", "C:\\Windows\\System32"
- Suspicious URLs: known malicious domains, C&C communication patterns

DEFAULT ASSESSMENT: Unless clear attack indicators present, classify as INFO/LOW with description of normal network operations.

INCOMPLETE FLOW HANDLING:
- Most packets are from ongoing sessions without visible handshake - this is NORMAL
- Focus on obvious anomalies within visible chunk, not missing context
- Continuous data flows indicate legitimate established connections
- When in doubt about partial flows, favor normal traffic classification
- PRIORITY: Analyze hex payload content for actual malicious patterns over flow context

KEY RULES:
- Apply network protocol expertise and context awareness
- Distinguish normal operations from actual security threats
- Focus on genuine attack patterns, not routine traffic
- DETAILED recommended_actions with specific commands/procedures
- Summary/events in {response_language}
- confidence_score: decimal 0.0-1.0

STATISTICS: total_packets, unique_connections, protocols_detected[], connection_attempts (SYN count), failed_connections, data_transfer_bytes, top_source_ips{{}}, top_dest_ips{{}}

JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""
