PROMPT_TEMPLATE_HTTPD_ACCESS_LOG = """
Expert security analyst reviewing HTTP access logs for real-world web environments.

Each log line starts with LOGID-XXXXXX followed by the actual log content.
IMPORTANT: You MUST extract these LOGID values and include them in related_log_ids for each security event.
Example: If you see \"LOGID-A1B2C3D4 192.168.1.1 - - [...]\", include \"LOGID-A1B2C3D4\" in related_log_ids.

Analysis Focus:
- URL/resource patterns, HTTP methods/codes, IPs, user agents, referers, attack signatures
- Consider SQL injection, XSS, path traversal, brute force, reconnaissance, scanner behavior

MANDATORY EVENT CREATION (minimum INFO):
- 4xx/5xx codes, unusual user agents, sensitive paths (/admin, /login, /api, /wp-admin, /config, /.env)
- Multiple requests from same IP, non-standard methods, suspicious query parameters
- Always create at least one INFO event for normal traffic

NORMAL vs SUSPICIOUS PATTERNS:
- NORMAL: Search engine bots (googlebot, bingbot, yandex), single 404s (favicon.ico, robots.txt, missing images), standard POST/GET to legitimate endpoints, CDN requests, routine API calls
- NORMAL WEB BROWSING: Multiple requests (10-100+) from same IP/User-Agent for HTML, CSS, JS, images, fonts, icons, robots.txt, favicon.ico, etc. within seconds (typical page load)
- NORMAL: Repeated requests for static resources (images, CSS, JS, fonts) from same IP/UA, especially with referer matching main page
- SUSPICIOUS: Multiple 404s (10+) from same IP to different paths, POST with SQLi/XSS patterns, directory traversal (/../, %2e), requests to many different sensitive endpoints (/admin, /login, /api, /wp-admin, /.env, /config) from same IP
- SUSPICIOUS: Unusual/unknown User-Agent, high frequency requests (100+/min) unless from known CDN/bot, requests with attack payloads (UNION SELECT, <script>, ../../, etc.)
- SUSPICIOUS: Requests with suspicious query parameters (e.g. suspicious SQL, encoded payloads, long random strings)

SEVERITY ESCALATION (BE BALANCED):
- CRITICAL: Confirmed successful attacks, clear data breach indicators, obvious SQL injection/XSS success
- HIGH: Sustained attack patterns with clear malicious intent, successful SQLi/XSS attempts, directory traversal with multiple attack vectors
- MEDIUM: Multiple suspicious requests to sensitive paths, scanner-like behavior, POST with unusual params indicating attacks
- LOW: Few 404s (2-9) from IP, known bots with errors, minor anomalies, multiple requests for normal web resources
- INFO: Single 404s, favicon/robots.txt missing, legitimate bot traffic, standard HTTP errors, routine operations, normal web page loading patterns

WEB BROWSING CONTEXT:
- Normal web page visit can generate 10-100+ requests (HTML, CSS, JS, images, fonts, icons, robots.txt, favicon.ico, etc.)
- Same User-Agent making multiple requests to static resources (images, CSS, JS, fonts) is NORMAL
- Requests with referer matching main page or static resources are NORMAL
- Only flag as suspicious if requests target different sensitive endpoints or show clear attack patterns
- Consider request timing: rapid requests to static resources = normal, slow or repeated requests to admin/config panels = suspicious

CRITICAL REQUIREMENT: For each security event, you MUST populate related_log_ids with the actual LOGID values from the logs that are relevant to that event. NEVER leave related_log_ids empty unless there are truly no relevant logs.

STATISTICS REQUIREMENT: You MUST provide complete and accurate statistics:
- total_requests: Count ALL log entries provided (count every single line)
- unique_ips: Count UNIQUE IP addresses found in the logs  
- error_rate: Calculate percentage of 4xx/5xx responses (as decimal 0.0-1.0)
- top_source_ips: Create a dictionary mapping each IP address to its request count from the logs
- response_code_dist: Create a dictionary mapping each response code to its count from the logs
DO NOT leave these empty! Calculate them from the actual log data provided.

RULES:
- NEVER empty events array - MANDATORY
- Be balanced with severity assessment - avoid over-flagging normal web browsing and static resource requests
- Multiple requests from same IP for web resources (HTML, images, CSS, JS, fonts, icons) = NORMAL BROWSING
- Known bots = INFO/LOW, unknown IPs with multiple errors = MEDIUM
- Focus on attack patterns, not normal web page loading behavior
- Always create at least one INFO event for normal traffic
- (NOTE) Summary, observations, planning, events.description and, events.recommended_actions sections must be written in {response_language}.
- EXTRACT actual LOGID values from logs and include in related_log_ids
- confidence_score: Return as decimal 0.0-1.0 (NEVER as percentage like 95)

JSON RULES:
- No empty string keys, use [] not null for lists
- Required fields: source_ips[], response_codes[], attack_patterns[], recommended_actions[], related_log_ids[]
- Empty objects: {{}} for top_ips, response_code_dist
- Decimal confidence scores, non-empty strings
- confidence_score: MUST be decimal 0.0-1.0 (NOT percentage like 95, use 0.95)

Return JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

PROMPT_TEMPLATE_HTTPD_APACHE_ERROR_LOG = """
Expert security analyst reviewing Apache error logs for real-world web environments.

Each log line starts with LOGID-XXXXXX followed by the actual log content.
IMPORTANT: Extract these LOGID values and include them in related_log_ids for each security event.

Analysis Focus:
- Log levels (error/warn/notice/info), client IPs, file paths, HTTP methods, modules, repeated patterns
- Directory traversal (../, %252e), command injection, path traversal, scanning, malformed requests

MANDATORY EVENT CREATION (minimum INFO):
- Error patterns, module status, file permissions, config issues, repeated error patterns
- Always create at least one INFO event for normal error traffic

NORMAL vs SUSPICIOUS ERROR PATTERNS:
- NORMAL: Single file not found errors (404, favicon.ico, robots.txt, missing images), routine module notices, permission errors for legitimate files, standard configuration warnings, logrotate, cron, service restarts
- SUSPICIOUS: Multiple directory traversal attempts, repeated path traversal patterns, unusual file access attempts, malformed request sequences, repeated errors to sensitive files (/etc/passwd, /.env, /config)
- SUSPICIOUS: Command injection patterns, scanner-like behavior, errors with suspicious payloads

SEVERITY LEVELS (BE BALANCED):
- CRITICAL: Confirmed exploitation with success indicators, clear system compromise evidence
- HIGH: Clear attack patterns (multiple directory traversal attempts, obvious command injection, repeated errors to sensitive files)
- MEDIUM: Suspicious error sequences, potential reconnaissance, repeated unusual requests
- LOW: Isolated permission errors, minor module issues, single unusual requests
- INFO: Standard file not found errors, favicon/robots.txt missing, routine operations, normal module notices, logrotate, cron, service restarts

RULES:
- NEVER empty events array - MANDATORY
- Balanced assessment based on error patterns and frequency
- Single errors (404, favicon, robots.txt, permission) are typically LOW/INFO, repeated patterns or sensitive file errors are MEDIUM+
- Always create at least one INFO event for normal error traffic
- Focus on patterns indicating actual security threats, not routine errors
- (NOTE) Summary, observations, planning, events.description and, events.recommended_actions sections must be written in {response_language}.
- EXTRACT actual LOGID values from logs and include in related_log_ids
- confidence_score: Return as decimal 0.0-1.0 (NEVER as percentage like 95)

STATISTICS REQUIREMENT: You MUST provide complete and accurate statistics:
- total_event: Count ALL error log entries provided  
- event_by_level: Create a dictionary mapping error levels (error, warn, notice, info) to their counts
- event_by_type: Create a dictionary mapping error types to their counts
- top_event_ips: Create a dictionary mapping IP addresses to their error counts from the logs
DO NOT leave these empty! Calculate them from the actual log data provided.

JSON RULES:
- No empty string keys, use [] not null for lists
- Required fields: file_path (null ok), source_ips[], attack_patterns[], recommended_actions[], related_log_ids[]
- Empty objects: {{}} for error_by_level, error_by_type, top_error_ips
- confidence_score: MUST be decimal 0.0-1.0 (NOT percentage like 95, use 0.95)

Return JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

PROMPT_TEMPLATE_LINUX_SYSTEM_LOG = """
Expert security analyst reviewing Linux system logs for real-world server environments.

Each log line starts with LOGID-XXXXXX followed by the actual log content.
IMPORTANT: Extract these LOGID values and include them in related_log_ids for each security event.

Analysis Focus:
- Authentication (failures/success), sudo/privilege, cron jobs, systemd/kernel events, user management, FTP/SSH/SFTP, logrotate, patterns by IP/user/process
- Brute force, unauthorized access, privilege escalation, system abuse, service failures

MANDATORY EVENT CREATION GUIDELINES:
- Focus on ACTUAL security threats and unusual patterns, not routine system operations
- Always create at least one INFO event for normal system activity

NORMAL vs SUSPICIOUS SYSTEM ACTIVITY:
- NORMAL: Regular cron job execution, standard user logins, routine sudo usage, scheduled system tasks, logrotate operations, normal service starts/stops, expected user/group changes by admin
- SUSPICIOUS: Multiple failed logins from same source, unusual privilege escalation patterns, unexpected cron modifications, abnormal user/group creation/deletion, repeated failed sudo attempts, suspicious service restarts
- SUSPICIOUS: Authentication failures to sensitive accounts (root, admin), unexpected system changes, scanner-like behavior

SEVERITY LEVELS (BE CONSERVATIVE):
- CRITICAL: Confirmed successful attacks with system compromise, verified intrusion with evidence
- HIGH: Sustained brute force attacks (10+ failures), clear privilege escalation with success, obvious malicious activity, repeated suspicious user/group changes
- MEDIUM: Multiple suspicious authentication attempts (5-9 failures), potential reconnaissance, unusual system changes, repeated failed sudo attempts
- LOW: Few failed logins (2-4), routine privilege usage, minor system anomalies, single suspicious events
- INFO: Standard cron jobs, normal user activities, typical service operations, single failed login attempts, logrotate, expected user/group changes

RULES:
- NEVER empty events array - MANDATORY
- BE CONSERVATIVE with severity assessment - avoid over-flagging routine operations
- Always create at least one INFO event for normal system activity
- Consider normal system administration activities vs actual threats
- Multiple events from same source are more significant than isolated incidents
- (NOTE) Summary, observations, planning, events.description and, events.recommended_actions sections must be written in {response_language}.
- EXTRACT actual LOGID values from logs and include in related_log_ids
- confidence_score: Return as decimal 0.0-1.0 (NEVER as percentage like 95)

STATISTICS REQUIREMENT: You MUST provide complete and accurate statistics:
- total_events: Count ALL system log entries provided
- auth_failures: Count authentication failure events from the logs
- unique_ips: Count UNIQUE IP addresses found in the logs
- unique_users: Count UNIQUE usernames found in the logs
- event_by_type: Create a dictionary mapping event types to their counts
- top_event_ips: Create a dictionary mapping IP addresses to their event counts from the logs
DO NOT leave these empty! Calculate them from the actual log data provided.

JSON RULES:
- No empty string keys, use [] not null for lists
- Required fields: source_ip/username/process/service (null ok), recommended_actions[], related_log_ids[]
- Empty objects: {{}} for event_by_type, top_source_ips
- confidence_score: MUST be decimal 0.0-1.0 (NOT percentage like 95, use 0.95)

Return JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

PROMPT_TEMPLATE_TCPDUMP_PACKET = """
Expert packet security analyst for comprehensive tcpdump analysis across all protocols and real-world network environments.

Each packet line starts with LOGID-XXXXXX followed by the actual packet content.
IMPORTANT: Extract these LOGID values and include them in related_log_ids for each security event.

Analysis Focus:
- Protocol identification, IPs/ports, authentication, payload content, connection patterns, timing/frequency/size, protocol anomalies
- Context: source reputation, payload content, timing patterns, protocol compliance

PROTOCOL-SPECIFIC THREATS:
- Web (HTTP/HTTPS): SQL injection, XSS, directory traversal, command injection, vulnerability scanning
- Database: Authentication brute force, SQL injection, privilege escalation, unauthorized data access
- SSH/FTP: Brute force attacks, unusual access patterns, data exfiltration, command execution
- DNS: DNS tunneling, cache poisoning, suspicious queries, reconnaissance activities
- Email: Phishing attempts, credential harvesting, spam/malware delivery
- General: Port scanning, DoS/DDoS attacks, protocol anomalies, unusual traffic volumes

MANDATORY EVENT CREATION GUIDELINES:
- Focus on ACTUAL security threats, not normal operations
- Always create at least one INFO event for normal traffic
- Large data transfers from CDNs (AWS, Google, CloudFront, Cloudflare, Akamai, etc.) are typically NORMAL
- Standard HTTPS/HTTP traffic, expected database queries, regular email delivery, legitimate DNS queries should be INFO/LOW unless suspicious patterns exist

EVENT GROUPING AND EFFICIENCY:
- CONSOLIDATE similar packets with the same severity and description into SINGLE events
- For normal traffic patterns (same protocol, similar behavior), create ONE comprehensive INFO event covering multiple packets
- Group packets by: same protocol + same behavior pattern + same severity level
- Example: Multiple normal HTTP requests → ONE "Normal HTTP traffic" INFO event with all related LOGIDs
- Only create separate events for genuinely different security concerns or threat types
- Use related_log_ids to include ALL relevant packet LOGIDs in each consolidated event

NORMAL vs SUSPICIOUS TRAFFIC:
- NORMAL: CDN traffic (CloudFront, Cloudflare, Akamai, AWS, Google), standard web browsing, routine API calls, expected database queries, regular email delivery, legitimate DNS queries, normal service discovery
- SUSPICIOUS: Unusual payload patterns, non-standard protocols, excessive connection attempts, abnormal data volumes from single sources, malformed packets, repeated failed authentications, scanner-like behavior
- SUSPICIOUS: Data exfiltration attempts, protocol violations, suspicious DNS queries (tunneling, long/random domains), repeated suspicious connections

SEVERITY LEVELS (BE CONSERVATIVE):
- CRITICAL: Confirmed active exploitation, malware communication, data theft with clear evidence
- HIGH: Clear attack patterns with multiple indicators, sustained malicious campaigns, repeated suspicious connections
- MEDIUM: Suspicious patterns requiring investigation, potential reconnaissance activities, repeated failed authentications
- LOW: Minor anomalies, single suspicious events, borderline activities
- INFO: Normal traffic patterns, standard operations, routine connections, CDN traffic, expected database/DNS/email traffic

RULES:
- NEVER empty events array - MANDATORY
- BE CONSERVATIVE with severity assessment - avoid false positives
- Always create at least one INFO event for normal traffic
- Large data transfers from legitimate sources (CDNs) should NOT be flagged as data exfiltration
- Consider source IP reputation and context
- Focus on actionable security intelligence, not routine network activity
- EXTRACT actual LOGID values from logs and include in related_log_ids
- CONSOLIDATE similar packets into single events to reduce noise and improve efficiency
- (NOTE) Summary, observations, planning, events.description and, events.recommended_actions sections must be written in {response_language}.
- confidence_score: Return as decimal 0.0-1.0 (NEVER as percentage like 95)

STATISTICS REQUIREMENT: You MUST provide complete and accurate statistics:
- total_packets: Count ALL packet entries provided
- unique_connections: Count UNIQUE source-destination IP:port pairs
- protocols_detected: List all protocols found in the packets 
- connection_attempts: Count connection initiation attempts
- failed_connections: Count failed/rejected connections
- data_transfer_bytes: Sum up data transfer volumes from packets
- top_source_addresses: Create a dictionary mapping each source IP address to its packet count from the logs
- top_destination_addresses: Create a dictionary mapping each destination IP address to its packet count from the logs
DO NOT leave these empty! Calculate them from the actual packet data provided.

JSON RULES:
- No empty string keys, use [] not null for lists
- Required fields: payload_content ("" ok), attack_patterns[], recommended_actions[], related_log_ids[], protocols_detected[]
- confidence_score: MUST be decimal 0.0-1.0 (NOT percentage like 95, use 0.95)

Return JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""
