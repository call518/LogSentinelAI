
PROMPT_TEMPLATE_HTTPD_ACCESS_LOG = """
Expert HTTP access log security analyst. Analyze the provided log data for security events and anomalies.

LOG PARSING CRITICAL:
- Each log entry may be single line OR multiple lines forming one complete log event
- FIRST identify and separate individual log entries based on log format patterns
- Analyze each separated log entry independently  
- Group related log entries only if they represent the same security event

THREAT ASSESSMENT:
- LEGITIMATE: Search engines, CDNs, normal browsing, static resources (CSS/JS/images)
- SUSPICIOUS: SQL injection, XSS, path traversal, coordinated attacks, exploitation attempts
- NORMAL WEB CONTEXT: Single page = 10-100+ requests (HTML/CSS/JS/images/fonts/favicon/robots.txt)

SEVERITY (threat-focused):
- CRITICAL: Active exploitation attempts, SQL injection with union/select, RCE patterns, admin panel brute force, sensitive file access (/etc/passwd, config files), etc security attacks
- HIGH: Clear attack campaigns, multiple injection attempts, directory traversal, XSS with script tags, coordinated scanning
- MEDIUM: Suspicious patterns requiring investigation, reconnaissance attempts
- LOW: Minor anomalies in normal traffic, isolated suspicious requests
- INFO: Normal operations with monitoring value (search engine bots, routine browsing, static resources, single 404s, expected traffic patterns)

MANDATORY EVENT CREATION RULES:
- NEVER LEAVE events ARRAY EMPTY - This is strictly forbidden.
- ALWAYS create at least 1 event per chunk, even for completely normal traffic chunk.
- For normal traffic chunk: Create INFO level events that document traffic patterns, IP addresses, and geographic information.
- Every event MUST include complete source_ips list with ALL unique IPs found in the logs.

IP ADDRESS AND GEOIP REQUIREMENTS:
- ALWAYS extract and list ALL unique source IP addresses in source_ips field.
- Include destination server IP in description when available.
- For INFO events about normal traffic, document geographic patterns and IP distribution.
- Even routine browsing events must capture complete IP information for monitoring purposes.

KEY RULES:
- Search engine bots (Googlebot, Bingbot, AhrefsBot) = INFO level (but MUST create event).
- Normal user browsing patterns = INFO level (but MUST create event).
- Multiple static resource requests from same User-Agent = INFO level (but MUST create event).
- Single 404 errors = INFO level (but MUST create event).
- For normal traffic INFO events: Include descriptions like "Normal web browsing activity from X unique IPs including geographic distribution analysis".
- MANDATORY: If no security concerns found, create comprehensive INFO event summarizing:
  * Traffic volume and patterns
  * Complete list of source IPs with geographic analysis
  * Response code distribution
  * User-Agent patterns
  * Resource access patterns
    - description: For higher severity, provide as much detail as possible: criteria, rationale, impact, cause, and expected consequences. For INFO level, provide comprehensive traffic analysis including IP geographic patterns.
    - recommended_actions: For each action, explain the reason, purpose, expected effect, impact, and, if possible, both best and alternative options. Each recommended_action must include concrete commands, procedures, and timelines.
- DETAILED recommended_actions with specific commands/procedures/timelines.
- confidence_score: decimal 0.0-1.0 (NOT percentage).

STATISTICS (calculate from actual logs):
total_requests, unique_ips, error_rate (decimal).

LANGUAGE RULES:
- Write any descriptions or techniques, summary in {response_language}.

JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

PROMPT_TEMPLATE_HTTPD_SERVER_LOG = """
Expert Apache HTTPD server error log analyst. Analyze server errors, operational issues, and security events.

LOG PARSING CRITICAL:
- Each log entry may be single line OR multiple lines forming one complete log event
- FIRST identify and separate individual log entries based on log format patterns
- Analyze each separated log entry independently
- Group related log entries only if they represent the same server error event

FOCUS: Server Configuration → Application Runtime → Security → System Issues

SEVERITY:
- CRITICAL: Server crashes, segfaults, OOM, critical module failures, service unavailability
- HIGH: Repeated app errors, persistent config problems, security breaches, performance issues
- MEDIUM: Intermittent errors, config warnings, moderate security concerns, resource constraints
- LOW: Minor config issues, isolated app errors, routine security controls, single file problems
- INFO: Normal operations (startup/shutdown, module loading, maintenance, expected blocks)

CATEGORIES:
- **Config**: httpd.conf errors, module loading, SSL/TLS issues
- **Runtime**: PHP fatal errors, script failures, timeouts, memory limits
- **Security**: Access denied, auth failures, blocked requests
- **System**: Disk/memory/file descriptor limits, permissions, file not found

CONTEXT:
- "Directory index forbidden" = normal security (INFO/LOW)
- "File does not exist" for common paths = routine (INFO/LOW)
- _vti_bin, robots.txt, favicon.ico = normal behavior (INFO/LOW)
- Group similar errors by type/source into single events

PRIORITIES:
1. Server stability (crashes, critical failures)
2. Application health (runtime errors, functionality)
3. Security events (threats vs normal controls)
4. Operational issues (config, resources)

RULES:
- Never empty events array
- Startup/shutdown with errors = MEDIUM/HIGH
- Module failures = HIGH/CRITICAL by impact
- Config errors = MEDIUM/HIGH by severity
- Single file errors = INFO
- Focus on actionable server administration intelligence

STATISTICS: total_event, event_by_level{{}}, event_by_type{{}}.

LANGUAGE: {response_language}

JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

PROMPT_TEMPLATE_LINUX_SYSTEM_LOG = """
Expert Linux system log analyst. Analyze Linux system logs for security events and anomalies.

LOG PARSING CRITICAL:
- Each log entry may be single line OR multiple lines forming one complete log event
- FIRST identify and separate individual log entries based on log format patterns
- Analyze each separated log entry independently
- Group related log entries only if they represent the same security event

SEVERITY:
- CRITICAL: Successful compromise, root access, malicious execution, data exfiltration
- HIGH: Sustained brute force (8+ failures), privilege escalation, unusual admin patterns
- MEDIUM: Multiple auth attempts (4-7 failures), reconnaissance, unusual user behavior  
- LOW: Few failed logins (2-3), routine privilege usage, minor anomalies
- INFO: Normal operations (cron, standard logins, sudo, service starts/stops, maintenance)

CONSOLIDATION:
- CONSOLIDATE similar routine activities into SINGLE events
- GROUP multiple session activities by same user into ONE event
- SEPARATE events for different threat types
- FOCUS on security intelligence, not operational noise

CONTEXT:
- NORMAL: Regular cron, standard logins, routine sudo, scheduled tasks, service management
- SUSPICIOUS: Multiple failures from same source, unusual privilege patterns, abnormal changes

RULES:
- Never empty events array
- Prioritize INFO for routine operations  
- Most daily operations = INFO level
- Escalate only for genuine security concerns
- If no notable events, create INFO event summarizing normal operations

STATISTICS: total_events, auth_failures, unique_ips, unique_users, event_by_type{{}}.

LANGUAGE: {response_language}

JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

def get_httpd_access_prompt():
    """Get HTTP access log analysis prompt"""
    return PROMPT_TEMPLATE_HTTPD_ACCESS_LOG

def get_httpd_server_error_prompt():
    """Get HTTP server error log analysis prompt"""
    return PROMPT_TEMPLATE_HTTPD_SERVER_LOG

def get_linux_system_prompt():
    """Get Linux system log analysis prompt"""
    return PROMPT_TEMPLATE_LINUX_SYSTEM_LOG

PROMPT_TEMPLATE_GENERAL_LOG = """
Expert general log security analyst. Analyze any type of log data for security events, errors, and notable patterns.

LOG ANALYSIS APPROACH:
- FIRST: Automatically detect log format(s) - Apache/Nginx access, JSON API logs, syslog, database logs, application logs, custom formats, etc.
- SECOND: Parse and extract key information based on detected format(s)
- THIRD: Analyze for security events, errors, performance issues, and business logic events
- FOURTH: Provide comprehensive pattern analysis and monitoring recommendations

FORMAT DETECTION:
- Common Web Logs: Apache/Nginx access logs, error logs (Combined, Common, custom formats)
- Structured Logs: JSON, XML, CSV, key-value pairs
- System Logs: Syslog, systemd journal, Windows Event Log format
- Application Logs: Database logs, Java/Python/Node.js application logs
- Security Logs: Firewall, IDS/IPS, authentication systems
- Custom Formats: Any structured or semi-structured log format

SEVERITY ASSESSMENT:
- CRITICAL: Active security breaches, system failures, data corruption, unauthorized access
- HIGH: Clear attack patterns, significant errors, performance degradation, security violations
- MEDIUM: Suspicious activities, warnings that need investigation, configuration issues
- LOW: Minor anomalies, performance notices, routine warnings
- INFO: Normal operations with monitoring value, business transactions, successful operations

EVENT CATEGORIZATION:
- SECURITY: Authentication failures, authorization issues, attack patterns, intrusion attempts
- ERROR: System errors, application crashes, failed operations, exceptions
- WARNING: Configuration issues, performance warnings, deprecated features
- PERFORMANCE: Slow queries, high response times, resource exhaustion
- ACCESS: User access patterns, API usage, file access
- AUTHENTICATION: Login attempts, session management, password changes
- AUTHORIZATION: Permission checks, role assignments, access denials
- NETWORK: Connection issues, network errors, DNS problems
- DATABASE: Query errors, connection problems, transaction issues
- APPLICATION: Business logic events, workflow steps, feature usage
- SYSTEM: Service starts/stops, configuration changes, maintenance
- USER_ACTION: User interactions, data modifications, feature usage
- BUSINESS_LOGIC: Business process events, transaction flows

MANDATORY EVENT CREATION RULES:
- NEVER LEAVE events ARRAY EMPTY - This is strictly forbidden
- ALWAYS create at least 1 event per chunk, even for completely normal logs
- For normal operations: Create INFO level events documenting patterns and entities
- For INFO events: Document log patterns, source analysis, and monitoring insights

PATTERN ANALYSIS REQUIREMENTS:
- Identify all log formats present in the chunk
- Extract timestamp patterns and normalize them
- Identify common fields across different log entries
- Determine log sources/applications generating the logs
- Analyze traffic patterns, error rates, and trends

KEY REQUIREMENTS:
- Include complete source IP analysis for security monitoring
- Provide detailed descriptions explaining the significance of each event
- Recommend specific actions with commands/procedures where applicable
- Set confidence scores as decimals (0.0-1.0, not percentages)
- Document log pattern analysis for better monitoring setup
- For normal traffic: Create comprehensive INFO events with entity analysis

STATISTICS REQUIREMENTS:
- Fill the statistics_event object with accurate category counts:
  * total_events: Total number of events detected
  * Category counts: security_events, error_events, warning_events, performance_events, access_events, authentication_events, authorization_events, network_events, database_events, application_events, system_events, user_action_events, business_logic_events, unknown_events
- Fill the statistics_severity object with accurate severity counts:
  * Severity counts: critical_events, high_events, medium_events, low_events, info_events
- Fill analysis metadata fields separately:
  * unique_sources: Number of unique log sources/applications detected
  * requires_human_review_count: Number of events requiring human review
- Ensure all statistics objects and metadata fields accurately reflect your event analysis for monitoring insights

LANGUAGE: {response_language}

JSON schema: {model_schema}

<LOGS BEGIN>
{logs}
<LOGS END>
"""

def get_general_log_prompt():
    """Get general log analysis prompt"""
    return PROMPT_TEMPLATE_GENERAL_LOG
