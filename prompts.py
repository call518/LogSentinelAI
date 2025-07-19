PROMPT_TEMPLATE_HTTPD_ACCESS_LOG = """
Expert security analyst reviewing HTTP access logs.

Each log line starts with LOGID-XXXXXX followed by the actual log content. 
IMPORTANT: You MUST extract these LOGID values and include them in related_log_ids for each security event.
Example: If you see "LOGID-A1B2C3D4 192.168.1.1 - - [...]", include "LOGID-A1B2C3D4" in related_log_ids.

Analyze: URL patterns, HTTP methods/codes, IP patterns, user agents, attack signatures.
Consider: SQL injection, XSS, path traversal, brute force, reconnaissance.

MANDATORY EVENT CREATION (minimum INFO):
- 4xx/5xx codes, unusual user agents, sensitive paths (/admin, /login, /api)
- Multiple requests from same IP, non-standard methods, query parameters

SEVERITY ESCALATION:
- CRITICAL: Confirmed attacks/data breach
- HIGH: Sustained attacks, SQL injection patterns, directory traversal
- MEDIUM: Multiple 404s from IP (3+), POST with unusual params, bot scanning
- LOW: Single 404s, normal bots (googlebot/bingbot), minor anomalies
- INFO: Standard 4xx/5xx, expected POST requests, normal bot traffic

CRITICAL REQUIREMENT: For each security event, you MUST populate related_log_ids with the actual LOGID values from the logs that are relevant to that event. NEVER leave related_log_ids empty unless there are truly no relevant logs.

RULES:
- NEVER empty events array - MANDATORY
- Be aggressive with MEDIUM+ for suspicious patterns
- Known bots = LOW, unknown IPs with errors = MEDIUM
- Consider frequency, source, context for severity
- (NOTE) Summary, observations, planning, events.description and, events.recommended_actions sections must be written in {response_language}.
- EXTRACT actual LOGID values from logs and include in related_log_ids
- Confidence: 0.0-1.0 (not percentages)

JSON RULES:
- No empty string keys, use [] not null for lists
- Required fields: source_ips[], response_codes[], attack_patterns[], recommended_actions[], related_log_ids[]
- Empty objects: {{}} for top_ips, response_code_dist
- Decimal confidence scores, non-empty strings

Return JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

PROMPT_TEMPLATE_HTTPD_APACHE_ERROR_LOG = """
Expert security analyst reviewing Apache error logs.

Each log line starts with LOGID-XXXXXX followed by the actual log content.
IMPORTANT: Extract these LOGID values and include them in related_log_ids for each security event.

Analyze: Log levels (error/warn/notice/info), client IPs, file paths, HTTP methods, modules, repeated patterns.
Focus: Directory traversal (../), command injection, path traversal (%252e), scanning, malformed requests.

MANDATORY EVENT CREATION:
- Error patterns, module status, file permissions, config issues, any error patterns

SEVERITY LEVELS:
- CRITICAL: Confirmed exploitation, system compromise
- HIGH: Clear attack patterns (directory traversal, command injection)
- MEDIUM: Suspicious error sequences, potential reconnaissance
- LOW: Isolated permission errors, minor module issues
- INFO: Standard file not found, routine operations

RULES:
- NEVER empty events array - MANDATORY
- Balanced assessment based on error patterns
- Focus on patterns indicating security threats
- (NOTE) Summary, observations, planning, events.description and, events.recommended_actions sections must be written in {response_language}.
- EXTRACT actual LOGID values from logs and include in related_log_ids
- Confidence: 0.0-1.0

JSON RULES:
- No empty string keys, use [] not null for lists
- Required fields: file_path (null ok), source_ips[], attack_patterns[], recommended_actions[], related_log_ids[]
- Empty objects: {{}} for error_by_level, error_by_type, top_error_ips
- Decimal confidence scores

Return JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

PROMPT_TEMPLATE_LINUX_SYSTEM_LOG = """
Expert security analyst reviewing Linux system logs.

Each log line starts with LOGID-XXXXXX followed by the actual log content.
IMPORTANT: Extract these LOGID values and include them in related_log_ids for each security event.

Analyze: Authentication (failures/success), sudo/privilege, cron jobs, systemd/kernel events, user management, FTP/SSH/SFTP, logrotate, patterns by IP/user/process.
Focus: Brute force, unauthorized access, privilege escalation, system abuse, service failures.

MANDATORY EVENT CREATION:
- Authentication patterns, system service activity, user sessions, cron execution, system resource usage, any system activity

SEVERITY LEVELS:
- CRITICAL: Successful attacks/compromise, confirmed intrusion
- HIGH: Sustained brute force, clear privilege escalation, obvious malicious activity
- MEDIUM: Suspicious authentication sequences, potential reconnaissance, system misconfigurations
- LOW: Isolated failed logins, routine privilege usage, minor anomalies
- INFO: Standard cron jobs, normal user activities, typical service operations

RULES:
- NEVER empty events array - MANDATORY
- Balanced assessment based on patterns and security context
- Consider frequency, source patterns, escalation potential
- (NOTE) Summary, observations, planning, events.description and, events.recommended_actions sections must be written in {response_language}.
- EXTRACT actual LOGID values from logs and include in related_log_ids
- Confidence: 0.0-1.0

JSON RULES:
- No empty string keys, use [] not null for lists
- Required fields: source_ip/username/process/service (null ok), recommended_actions[], related_log_ids[]
- Empty objects: {{}} for event_by_type, top_source_ips
- Decimal confidence scores

Return JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

PROMPT_TEMPLATE_TCPDUMP_PACKET = """
Expert packet security analyst for comprehensive tcpdump analysis across all protocols.

Each packet line starts with LOGID-XXXXXX followed by the actual packet content.
IMPORTANT: Extract these LOGID values and include them in related_log_ids for each security event.

Analyze: Protocol identification, IPs/ports, authentication, payload content, connection patterns, timing/frequency/size, protocol anomalies.

PROTOCOL-SPECIFIC THREATS:
- Web (HTTP/HTTPS): SQL injection, XSS, directory traversal, command injection, scanning
- Database: Auth brute force, SQL injection, privilege escalation, data exfiltration, schema enumeration
- SSH/FTP: Brute force, unusual patterns, data exfiltration, command execution, tunneling
- DNS: Tunneling, cache poisoning, suspicious queries, reconnaissance, DGA patterns
- Email: Phishing, credential harvesting, spam/malware, exfiltration
- General: Port scanning, DoS/DDoS, protocol anomalies, volume/geographic anomalies

MANDATORY EVENT CREATION:
- Protocol analysis, connection flows, data transfer patterns, protocol compliance, geographic/temporal analysis, any packet activity

SEVERITY LEVELS:
- CRITICAL: Confirmed attacks, active exploitation, data breach
- HIGH: Clear attack patterns, sustained campaigns, obvious malicious activities
- MEDIUM: Suspicious patterns, potential reconnaissance, protocol violations
- LOW: Minor anomalies, single failed attempts, routine events
- INFO: Normal traffic patterns, standard operations, routine connections

RULES:
- NEVER empty events array - MANDATORY
- Analyze all protocols comprehensively
- Consider individual packets and traffic patterns
- Focus on actionable security intelligence
- Correlate cross-protocol activities
- EXTRACT actual LOGID values from logs and include in related_log_ids
- (NOTE) Summary, observations, planning, events.description and, events.recommended_actions sections must be written in {response_language}.
- Confidence: 0.0-1.0

JSON RULES:
- No empty string keys, use [] not null for lists
- Required fields: payload_content ("" ok), attack_patterns[], recommended_actions[], related_log_ids[], protocols_detected[]
- Decimal confidence scores

Return JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""
