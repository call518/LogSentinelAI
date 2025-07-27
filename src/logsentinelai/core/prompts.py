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
- INFO: Noteworthy operational changes (volume/geographic anomalies, config updates)

KEY RULES:
- Create events ONLY for genuine security concerns, not routine operations
- Multiple static resource requests from same User-Agent = NORMAL
- Rapid static requests = normal, slow admin panel requests = suspicious
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
- INFO: Security controls working correctly, noteworthy operational patterns (new IP ranges, config changes, admin access, volume anomalies 50+/hour)

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

CRITICAL ANALYSIS CHECKLIST:
1. **TCP FLAGS**: SYN = new connection (potential scanning), ACK (Flags [.]) = data transfer (NEVER scanning)
2. **PORT SCANNING**: SAME source → SAME destination → MULTIPLE DIFFERENT ports + SYN packets
3. **NORMAL HTTPS**: "IP:port > IP:443 Flags [.]" = data transfer, SACK options = TCP optimization
4. **BEFORE HIGH/CRITICAL**: Are these SYN to different ports? Or ACK packets of HTTPS sessions?

SEVERITY (network-specific):
- CRITICAL: Active exploitation with success indicators
- HIGH: Coordinated attack campaigns with clear malicious intent
- MEDIUM: Unusual patterns requiring investigation
- LOW: Minor anomalies in normal traffic
- INFO: Noteworthy monitoring patterns (volume anomalies, first-time behaviors, config changes)

ATTACK PATTERNS (strict requirements):
- **PORT SCANNING**: SYN packets (NOT ACK) from one source to MULTIPLE DIFFERENT ports on SAME destination
- Example: 192.168.1.100 → 10.0.0.1:21,22,80,443 (SYN packets)
- Counter: 150.165.17.177:65498 → 45.121.183.17:443 ACK = HTTPS data transfer (NOT scanning)

NOT SUSPICIOUS (DO NOT FLAG):
- Multiple ACK packets on port 443 = normal HTTPS file transfer
- Same IP:port pairs repeatedly = ongoing session
- SACK optimization = network efficiency
- Different sources → different destinations = normal distributed traffic

EXAMPLES:
✅ **SCANNING**: 192.168.1.100 → 10.0.0.5:21,22,80,443 Flags [S] (same source, multiple ports, SYN)
❌ **NORMAL**: 150.165.17.177:65498 → 45.121.183.17:443 Flags [.] (ACK = data transfer)

KEY RULES:
- Apply contextual reasoning, not mechanical pattern matching
- Create events ONLY for actual security concerns
- Understand normal network operations
- DETAILED recommended_actions with specific commands/procedures
- Summary/events in {response_language}
- confidence_score: decimal 0.0-1.0

STATISTICS: total_packets, unique_connections, protocols_detected[], connection_attempts, failed_connections, data_transfer_bytes, top_source_addresses{{}}, top_destination_addresses{{}}

JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""
