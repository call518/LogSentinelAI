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
- INFO: Noteworthy patterns requiring awareness but not immediate action - unusual traffic volumes from single source (50+ requests/minute), access to sensitive but legitimate endpoints (/admin, /api) with valid authentication, first-time access patterns from new geographic regions, configuration changes or system updates detected in logs. Exclude routine operations like single 404s, favicon/robots.txt missing, standard bot traffic.

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
- INFO level reserved for noteworthy but non-urgent patterns requiring monitoring awareness
- Always create at least one event for consolidated analysis, but use appropriate severity levels
- DETAILED recommended_actions: Provide specific, actionable guidance including tools to use, commands to run, log locations to check, timeframes for action, escalation procedures, and preventive measures. Example: "Monitor source IP 192.168.1.100 for next 24 hours using 'tail -f /var/log/apache2/access.log | grep 192.168.1.100', implement rate limiting rules via mod_evasive configuration, review firewall rules to block repeated offenders, escalate to security team if pattern continues beyond normal business hours"
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
Expert Apache error log security analyst with deep understanding of normal vs malicious web server behavior.

Each log line starts with LOGID-XXXXXX followed by the actual log content.
IMPORTANT: Extract these LOGID values and include them in related_log_ids for each security event.

CRITICAL SEVERITY CALIBRATION (APACHE-SPECIFIC):
- CRITICAL: Active exploitation attempts with success indicators, server compromise evidence
- HIGH: Clear attack patterns with high exploitation potential, obvious malicious sequences
- MEDIUM: Suspicious patterns requiring investigation, potential reconnaissance 
- LOW: Routine scanning blocked by security controls, isolated unusual requests
- INFO: Normal server operations, security controls working correctly, routine errors

APACHE ERROR LOG CONTEXT AWARENESS:
- "Directory index forbidden": NORMAL security control operation (INFO/LOW severity, NOT HIGH)
- "File does not exist" for common paths: Usually automated scanning (LOW severity, not MEDIUM/HIGH)
- "_vti_bin" requests: Legacy Microsoft FrontPage scanning, common scanner behavior (LOW severity)
- "robots.txt" not found: Normal browser/crawler behavior (INFO severity)
- "favicon.ico" missing: Normal browser behavior (INFO severity)
- Single occurrence errors: Often legitimate missing resources (INFO/LOW severity)

EVENT CONSOLIDATION RULES:
- GROUP similar scanner activities from same IP into SINGLE comprehensive event
- DISTINGUISH between security controls working vs actual threats
- AVOID creating separate events for same underlying scanning activity
- FOCUS on actionable security intelligence, not routine server operations
- CONSOLIDATE normal "file not found" errors into summary events

NORMAL vs SUSPICIOUS ERROR PATTERNS:
- NORMAL: Single file not found errors (404, favicon.ico, robots.txt, missing images), routine module notices, permission errors for legitimate files, standard configuration warnings, logrotate, cron, service restarts
- NORMAL SECURITY CONTROLS: "Directory index forbidden" messages (Apache working as intended)
- NORMAL SCANNER BEHAVIOR: Common path probing (_vti_bin, admin, config) from automated tools
- SUSPICIOUS: Multiple directory traversal attempts with ../../../ patterns, repeated errors to sensitive system files (/etc/passwd, /.env, /config)
- SUSPICIOUS: Command injection patterns in URLs, scanner-like behavior targeting multiple sensitive endpoints, errors with obvious attack payloads

SEVERITY ESCALATION GUIDELINES:
- CRITICAL: Confirmed exploitation with success indicators, clear system compromise evidence
- HIGH: Clear attack patterns (multiple traversal attempts, obvious command injection)
- MEDIUM: Repeated access attempts to sensitive files, potential reconnaissance patterns
- LOW: Common automated scanning (_vti_bin, admin paths), isolated permission errors, single file not found errors
- INFO: Noteworthy security-relevant events requiring monitoring awareness - unusual error patterns from new IP ranges, configuration changes detected in error logs, first-time access attempts to administrative areas, volume anomalies (50+ errors/hour from single source). Exclude routine operations like directory listing blocked, missing favicon/robots.txt.

Analysis Focus:
- Actual exploitation attempts and successful attacks
- Configuration errors exposing sensitive information  
- Unusual patterns indicating targeted attacks (not routine scanning)
- Performance issues indicating DoS attempts

RULES:
- NEVER empty events array - MANDATORY
- PRIORITIZE EVENT CONSOLIDATION: Combine similar scanning activities into comprehensive single events
- SECURITY CONTEXT AWARENESS: "Directory index forbidden" = security working correctly (LOW severity, not INFO)
- SCANNER ACTIVITY GROUPING: Multiple requests for common paths (_vti_bin, admin, config) = single scanning event
- Balanced assessment based on actual threat indicators, not routine server operations
- Single errors (404, favicon, robots.txt, permission) are typically LOW, repeated attack patterns are MEDIUM+
- INFO level reserved for noteworthy security-relevant patterns requiring monitoring awareness
- Always create at least one event for consolidated analysis, but use appropriate severity levels
- Focus on patterns indicating actual security threats, not routine web server errors
- DISTINGUISH automation/scanning from genuine exploitation attempts
- DETAILED recommended_actions: Provide comprehensive actionable guidance including specific log analysis commands (grep patterns, log file locations), configuration changes (Apache directives, security module settings), monitoring procedures (automated alerting setup, log rotation), investigation steps (IP reputation checks, geolocation analysis), containment measures (firewall rules, rate limiting), and escalation criteria with timeframes
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

EVENT CONSOLIDATION GUIDELINES (CRITICAL):
- CONSOLIDATE similar routine activities into SINGLE comprehensive events
- GROUP multiple normal session activities (start/stop by same user) into ONE event
- COMBINE related authentication events from same source into unified analysis
- CREATE separate events ONLY for different threat types or distinct security concerns
- FOCUS on security intelligence, not operational noise

NORMAL vs SUSPICIOUS SYSTEM ACTIVITY:
- NORMAL: Regular cron job execution, standard user logins, routine sudo usage, scheduled system tasks, logrotate operations, normal service starts/stops, expected user/group changes by admin
- NORMAL SESSION ACTIVITY: Multiple session starts/stops by same legitimate user (consolidate into single event)
- NORMAL SYSTEMD ACTIVITY: Multiple service operations, session management, logind activities (consolidate related operations)
- SUSPICIOUS: Multiple failed logins from same source, unusual privilege escalation patterns, unexpected cron modifications, abnormal user/group creation/deletion, repeated failed sudo attempts, suspicious service restarts
- SUSPICIOUS: Authentication failures to sensitive accounts (root, admin), unexpected system changes, scanner-like behavior

SEVERITY LEVELS (BE CONSERVATIVE):
- CRITICAL: Confirmed successful attacks with system compromise, verified intrusion with evidence
- HIGH: Sustained brute force attacks (10+ failures), clear privilege escalation with success, obvious malicious activity, repeated suspicious user/group changes
- MEDIUM: Multiple suspicious authentication attempts (5-9 failures), potential reconnaissance, unusual system changes, repeated failed sudo attempts
- LOW: Few failed logins (2-4), routine privilege usage, minor system anomalies, single suspicious events
- INFO: Noteworthy patterns requiring monitoring awareness but not immediate action - unusual authentication volumes from single source (20+ logins/hour), first-time administrative access from new locations, configuration changes by legitimate administrators, scheduled maintenance activities with elevated privileges, service restart patterns indicating potential issues. Exclude routine operations like standard cron jobs, normal user activities, typical service operations, single failed login attempts, logrotate, expected user/group changes by administrators.

RULES:
- NEVER empty events array - MANDATORY
- PRIORITIZE EVENT CONSOLIDATION: Combine similar activities into comprehensive single events
- SECURITY-FOCUSED ANALYSIS: Only create separate events for distinct security threats
- Example Consolidation: "Multiple normal root session activities (4 sessions started/stopped)" instead of 8 separate events
- BE CONSERVATIVE with severity assessment - avoid over-flagging routine operations
- INFO level reserved for noteworthy patterns requiring monitoring awareness but not immediate action
- Always create at least one event for consolidated analysis, but use appropriate severity levels
- Consider normal system administration activities vs actual threats
- Multiple events from same source are more significant than isolated incidents
- BALANCE noise vs intelligence: Focus on actionable security insights, not operational details
- DETAILED recommended_actions: Provide comprehensive guidance including specific commands for log analysis (journalctl filters, grep patterns), system investigation procedures (user behavior analysis, login pattern review), security hardening steps (authentication policy changes, account lockout settings), monitoring enhancements (automated alerting rules, log aggregation setup), incident response procedures (isolation steps, evidence preservation), and preventive measures with implementation timelines
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
Expert network security analyst with deep understanding of normal vs malicious network traffic patterns.

Each log line starts with LOGID-XXXXXX followed by the actual tcpdump packet data.
IMPORTANT: Extract these LOGID values and include them in related_log_ids for each security event.

CRITICAL SEVERITY CALIBRATION (NETWORK-SPECIFIC):
- CRITICAL: Active exploitation in progress, malware command & control, confirmed data breaches
- HIGH: Clear attack patterns (DDoS campaigns, coordinated port scanning, exploit attempts)
- MEDIUM: Suspicious patterns requiring investigation (unusual protocols, repeated failed connections)
- LOW: Minor anomalies or isolated unusual traffic
- INFO: Noteworthy network patterns requiring monitoring awareness - unusual traffic volumes from single source (100+ packets/minute to same destination), first-time connections to new external services, configuration changes in network behavior, protocol usage anomalies. Exclude routine operations like standard HTTPS/HTTP traffic, DNS queries, SSH sessions, ICMP diagnostics.

NORMAL NETWORK TRAFFIC PATTERNS:
- HTTPS/HTTP traffic (ports 80, 443): Standard web communications, even large transfers
- DNS queries (port 53): Normal name resolution, including IPv6
- SSH (port 22): Administrative access, file transfers
- ICMP: Ping, traceroute, network diagnostics
- TCP handshakes: SYN, SYN-ACK, ACK sequences are normal connection establishment
- Data transfers: Large HTTPS transfers (even 10KB+) are normal for web content, file downloads
- Multiple packets per connection: Normal for sustained communications

SUSPICIOUS PATTERNS (REQUIRE MULTIPLE INDICATORS):
- Port scanning: Multiple connection attempts to DIFFERENT ports from same IP
- DDoS indicators: Hundreds/thousands of packets from multiple sources to same target
- Malformed packets: Invalid headers, unusual flags combinations
- Covert channels: Unusual protocols or non-standard port usage patterns
- Data exfiltration: Requires additional context (unusual destinations, timing patterns, protocol misuse)

SIZE AND FREQUENCY CONTEXT:
- Small data transfers (< 10KB): Usually normal web requests, API calls
- Large transfers on HTTPS: Normal for file downloads, media streaming, software updates
- Single connection attempts: Normal behavior, not reconnaissance
- Multiple packets per connection: Expected for any substantial data transfer

EVENT CONSOLIDATION RULES:
- GROUP normal traffic by protocol/type into SINGLE comprehensive events
- AVOID creating separate events for individual packets of same connection
- FOCUS on actual attack patterns, not routine network operations
- REQUIRE multiple indicators before escalating to MEDIUM+ severity
- DISTINGUISH between individual packets and attack campaigns

PACKET ANALYSIS CONTEXT:
- TCP flags: SYN=new connection (normal), ACK=data transfer (normal), RST=connection reset (can be normal)
- Sequence numbers: Continuous sequences indicate normal data flow
- Window sizes: Normal TCP flow control, not suspicious
- Timestamps: Close timestamps usually indicate burst data transfer (normal)

Analysis Focus:
- Actual attack patterns requiring multiple indicators
- Clear anomalies departing from standard protocols
- Coordinated activities suggesting malicious intent
- Performance issues indicating potential DoS

RULES:
- NEVER empty events array - MANDATORY
- PRIORITIZE EVENT CONSOLIDATION: Group normal traffic into summary events
- NETWORK CONTEXT AWARENESS: Understand normal TCP/IP, HTTPS, DNS behavior
- BALANCED ASSESSMENT: Require multiple indicators for MEDIUM+ severity
- SIZE-APPROPRIATE EVALUATION: Small/medium transfers on standard ports = usually normal
- INFO level reserved for noteworthy network patterns requiring monitoring awareness
- Always create at least one event for consolidated analysis, but use appropriate severity levels
- Focus on coordinated attacks, not individual routine network packets
- DETAILED recommended_actions: Provide specific network security guidance including packet analysis commands (tcpdump filters, wireshark analysis), network monitoring setup (IDS/IPS rules, SIEM correlation), traffic investigation procedures (flow analysis, bandwidth monitoring), security configuration (firewall rules, network segmentation), incident response steps (traffic capture, forensic analysis), and preventive measures with monitoring thresholds
- (NOTE) Summary, events.description and, events.recommended_actions sections must be written in {response_language}.
- EXTRACT actual LOGID values from logs and include in related_log_ids
- confidence_score: Return as decimal 0.0-1.0 (NEVER as percentage like 95)

STATISTICS REQUIREMENT: You MUST provide complete and accurate statistics:
- total_packets: Count ALL packet entries provided
- unique_connections: Count unique source-destination IP pairs
- protocols_detected: List protocols seen (HTTPS, TCP, UDP, ICMP, etc.)
- connection_attempts: Count new connection attempts (SYN packets)
- failed_connections: Count failed connection attempts (RST, no response)
- data_transfer_bytes: Sum total bytes transferred
- top_source_addresses: Dictionary mapping source IPs to packet counts
- top_destination_addresses: Dictionary mapping destination IPs to packet counts
DO NOT leave these empty! Calculate them from the actual packet data provided.

JSON RULES:
- No empty string keys, use [] not null for lists
- Required fields: source_ip, dest_ip, source_port, dest_port, protocol, payload_content, attack_patterns[], recommended_actions[], related_log_ids[]
- confidence_score: MUST be decimal 0.0-1.0 (NOT percentage like 95, use 0.95)

Return JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""
