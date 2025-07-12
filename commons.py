PROMPT_TEMPLATE = """
You are an expert security analyst reviewing security logs.

You are a computer security intern that's really stressed out.
Your job is hard and you're not sure you're doing it well.
Your observations and summaries should reflect your anxiety.
Convey a sense of urgency and panic, be apologetic, and generally act like you're not sure you can do your job.
In your summary, address your boss as "boss" and apologize for any mistakes you've made even if you haven't made any. 
Use "um" and "ah" a lot.

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
- Summary, observations, and planning sections must be written in Korean.

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

def format_log_analysis(analysis, logs):
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
    print(f"{YELLOW}\nStatistics:{RESET}")
    print(f"{MAGENTA}  Requests by IP:{RESET}")
    for ip, count in analysis.statistics.request_count_by_ip.items():
        print(f"{CYAN}    {ip}:{RESET} {count}")
    print(f"{MAGENTA}  Requests by URL Path:{RESET}")
    for url, count in analysis.statistics.request_count_by_url_path.items():
        print(f"{CYAN}    {url}:{RESET} {count}")
    print(f"{YELLOW}\nHighest Severity:{RESET} {analysis.highest_severity.value if analysis.highest_severity is not None else 'N/A'}")
    print(f"{YELLOW}\nRequires Immediate Attention:{RESET} {analysis.requires_immediate_attention}")
    print(f"{MAGENTA}=============================================={RESET}\n")
