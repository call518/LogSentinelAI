from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional
import datetime
import re
import hashlib
import argparse

from commons import initialize_llm_model
from commons import process_log_chunk
from commons import wait_on_failure
from commons import get_llm_config
from commons import get_analysis_config
from commons import create_realtime_monitor
from prompts import PROMPT_TEMPLATE_TCPDUMP_PACKET
from commons import chunked_iterable
from commons import print_chunk_contents

### Install the required packages
# uv pip install outlines ollama openai python-dotenv numpy elasticsearch

#---------------------------------- Enums and Models ----------------------------------
class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class PacketSecurityEvent(str, Enum):
    # Web Application Attacks
    SQL_INJECTION = "SQL_INJECTION"
    XSS_ATTACK = "XSS_ATTACK"
    DIRECTORY_TRAVERSAL = "DIRECTORY_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    
    # Authentication & Authorization
    BRUTE_FORCE_ATTACK = "BRUTE_FORCE_ATTACK"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING"
    
    # Network Attacks
    PORT_SCANNING = "PORT_SCANNING"
    NETWORK_RECONNAISSANCE = "NETWORK_RECONNAISSANCE"
    DOS_ATTACK = "DOS_ATTACK"
    DDOS_ATTACK = "DDOS_ATTACK"
    
    # Data Exfiltration
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    SUSPICIOUS_DATA_TRANSFER = "SUSPICIOUS_DATA_TRANSFER"
    LARGE_DATA_DOWNLOAD = "LARGE_DATA_DOWNLOAD"
    
    # Protocol Specific
    DNS_TUNNELING = "DNS_TUNNELING"
    HTTP_SMUGGLING = "HTTP_SMUGGLING"
    SSL_TLS_ANOMALY = "SSL_TLS_ANOMALY"
    
    # General
    SUSPICIOUS_PATTERN = "SUSPICIOUS_PATTERN"
    UNUSUAL_TRAFFIC = "UNUSUAL_TRAFFIC"
    PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"
    UNKNOWN = "UNKNOWN"

class PacketProtocol(str, Enum):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    FTP = "FTP"
    SSH = "SSH"
    TELNET = "TELNET"
    DNS = "DNS"
    SMTP = "SMTP"
    POP3 = "POP3"
    IMAP = "IMAP"
    SNMP = "SNMP"
    LDAP = "LDAP"
    MYSQL = "MYSQL"
    POSTGRESQL = "POSTGRESQL"
    REDIS = "REDIS"
    MONGODB = "MONGODB"
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"

class SecurityEvent(BaseModel):
    event_type: str = Field(description="Security event type")
    severity: SeverityLevel
    description: str = Field(description="Detailed event description")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Confidence level (0.0-1.0)")
    source_ip: str = Field(description="Source IP address")
    dest_ip: str = Field(description="Destination IP address")
    source_port: int = Field(description="Source port number")
    dest_port: int = Field(description="Destination port number")
    protocol: PacketProtocol
    payload_content: str = Field(description="Payload content if detected")
    attack_patterns: list[PacketSecurityEvent] = Field(description="Detected attack patterns")
    recommended_actions: list[str] = Field(description="Recommended actions")
    requires_human_review: bool = Field(description="Whether human review is required")
    related_log_ids: list[str] = Field(description="Related LOGID list (e.g., ['LOGID-7DD17B008706AC22C60AD6DF9AC5E2E9', 'LOGID-F3B6E3F03EC9E5BC1F65624EB65C6C51'])")

class Statistics(BaseModel):
    total_packets: int = Field(description="Total number of packets")
    unique_connections: int = Field(description="Number of unique connections")
    protocols_detected: list[PacketProtocol] = Field(description="Detected protocols")
    connection_attempts: int = Field(description="Number of connection attempts")
    failed_connections: int = Field(description="Number of failed connections")
    data_transfer_bytes: int = Field(description="Total data transfer in bytes")

class PacketAnalysis(BaseModel):
    summary: str = Field(description="Analysis summary")
    events: list[SecurityEvent] = Field(
        min_items=1,
        description="List of security events - must include at least one"
    )
    statistics: Statistics
    highest_severity: SeverityLevel
    requires_immediate_attention: bool = Field(description="Requires immediate attention")
#--------------------------------------------------------------------------------------

def parse_tcpdump_packets(content):
    """Parse tcpdump content into individual packets - supports all tcpdump timestamp formats"""
    packets = []
    current_packet = []
    
    lines = content.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Check if this is a new packet header by looking for common patterns:
        # 1. Starts with timestamp (various formats: HH:MM:SS, YYYY-MM-DD HH:MM:SS, epoch.microseconds, etc.)
        # 2. Contains "IP" keyword which indicates packet header
        # 3. Does not start with hex offset (0x0000:, 0x0010:, etc.)
        is_packet_header = (
            # Timestamp patterns (covers -t, -tt, -ttt, -tttt options)
            re.match(r'^\d{2}:\d{2}:\d{2}\.\d{6}', line) or  # HH:MM:SS.microseconds
            re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}', line) or  # YYYY-MM-DD HH:MM:SS.microseconds (-tttt)
            re.match(r'^\d{10}\.\d{6}', line) or  # epoch.microseconds (-tt)
            re.match(r'^ \d{2}:\d{2}:\d{2}\.\d{6}', line) or  # space + HH:MM:SS.microseconds (-ttt)
            # No timestamp case (-t option)
            (line.startswith('IP ') or ' IP ' in line)
        ) and not re.match(r'^\s*0x[0-9a-fA-F]{4}:', line)  # Not a hex dump line
        
        if is_packet_header:
            # Save previous packet if exists
            if current_packet:
                packets.append('\n'.join(current_packet))
            current_packet = [line]
        else:
            # This is a continuation of the current packet (hex dump or other data)
            current_packet.append(line)
    
    # Add the last packet
    if current_packet:
        packets.append('\n'.join(current_packet))
    
    return packets

def assign_logid_to_packets(packets):
    """Assign LOGID to each packet (multi-line chunk) and convert to single line format"""
    packets_with_logid = []
    
    for packet in packets:
        # 패킷 전체 내용을 해시값으로 변환
        hash_object = hashlib.md5(packet.encode('utf-8'))
        hash_hex = hash_object.hexdigest()
        
        # LOGID 생성: LOGID- + 해시값 (대문자로 변환)
        logid = f"LOGID-{hash_hex.upper()}"
        
        # 멀티라인 패킷을 하나의 라인으로 변환 (개행문자를 \\n으로 대체)
        packet_single_line = packet.replace('\n', '\\n')
        
        # 패킷 앞에 LOGID 추가하고 개행 문자 추가 (다른 분석 파일들과 동일한 형식)
        packet_with_logid = f"{logid} {packet_single_line}\n"
        packets_with_logid.append(packet_with_logid)
    
    return packets_with_logid

#--------------------------------------------------------------------------------------

def run_batch_analysis():
    """Run batch analysis on static log file"""
    print("=" * 70)
    print("LogSentinelAI - TCPDump Packet Analysis (Batch Mode)")
    print("=" * 70)
    
    # Get LLM configuration from commons
    llm_provider, llm_model_name = get_llm_config()
    
    # Get analysis configuration (can override chunk_size if needed)
    # config = get_analysis_config("tcpdump_packet", chunk_size=3)  # Override chunk_size
    config = get_analysis_config("tcpdump_packet")  # Use default chunk_size
    
    print(f"Log file:          {config['log_path']}")
    print(f"Chunk size:        {config['chunk_size']}")
    print(f"Response language: {config['response_language']}")
    print(f"Analysis mode:     {config['analysis_mode']}")
    
    log_path = config["log_path"]
    chunk_size = config["chunk_size"]
    response_language = config["response_language"]
    
    model = initialize_llm_model()
    
    # Read and preprocess tcpdump file (special handling for multi-line packets)
    with open(log_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    # Parse tcpdump packets and assign LOGID
    packets = parse_tcpdump_packets(content)
    packets_with_logid = assign_logid_to_packets(packets)
    
    # Create file-like object for standard chunked processing
    from io import StringIO
    processed_file = StringIO(''.join(packets_with_logid))
    
    # Standard processing pattern (same as other analysis files)
    with processed_file as f:
        for i, chunk in enumerate(chunked_iterable(f, chunk_size, debug=False)):
            # 분석 시작 시간 기록
            chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
            logs = "".join(chunk).replace('\\n', '\n')  # Convert escaped newlines back
            model_schema = PacketAnalysis.model_json_schema()
            prompt = PROMPT_TEMPLATE_TCPDUMP_PACKET.format(logs=logs, model_schema=model_schema, response_language=response_language)
            print(f"\n--- Chunk {i+1} ---")
            print_chunk_contents(chunk)
            
            # 공통 처리 함수 사용 (분석 완료 시간은 함수 내부에서 기록)
            success, parsed_data = process_log_chunk(
                model=model,
                prompt=prompt,
                model_class=PacketAnalysis,
                chunk_start_time=chunk_start_time,
                chunk_end_time=None,  # 함수 내부에서 계산
                elasticsearch_index="tcpdump_packet",
                chunk_number=i+1,
                chunk_data=chunk,
                llm_provider=llm_provider,
                llm_model=llm_model_name,
                processing_mode="batch"
            )
            
            if success:
                print("Analysis completed successfully")
            else:
                print("Analysis failed")
                wait_on_failure(30)  # 실패 시 30초 대기
            
            print("-" * 50)


def run_realtime_analysis(chunk_size=None, log_path=None, processing_mode=None, sampling_threshold=None):
    """Run real-time analysis on live log file with sampling support"""
    print("=" * 70)
    print("LogSentinelAI - TCPDump Packet Analysis (Real-time Mode)")
    print("=" * 70)
    
    # Log type for this analysis
    log_type = "tcpdump_packet"
    
    # Override environment variables if specified
    if processing_mode:
        import os
        os.environ["REALTIME_PROCESSING_MODE"] = processing_mode
    if sampling_threshold:
        import os
        os.environ["REALTIME_SAMPLING_THRESHOLD"] = str(sampling_threshold)
    
    # Get configuration
    config = get_analysis_config(log_type, chunk_size, analysis_mode="realtime")
    
    # Override log path if specified
    if log_path:
        config["log_path"] = log_path
    
    print(f"Log file:          {config['log_path']}")
    print(f"Chunk size:        {config['chunk_size']}")
    print(f"Response language: {config['response_language']}")
    print(f"Analysis mode:     {config['analysis_mode']}")
    
    # Initialize LLM model
    print("\nInitializing LLM model...")
    model = initialize_llm_model()
    
    # Create real-time monitor
    try:
        monitor = create_realtime_monitor(log_type, chunk_size)
    except ValueError as e:
        print(f"ERROR: Configuration error: {e}")
        print("Please check your config file for real-time log paths")
        return
    
    # Custom callback for processing results
    def process_result_callback(result, chunk, chunk_id):
        """Custom callback to handle analysis results"""
        print(f"Analysis complete for chunk {chunk_id}")
        
        if result and 'security_events' in result:
            event_count = len(result['security_events'])
            print(f"Found {event_count} security events")
            
            # Show high severity events
            high_severity_events = [
                event for event in result['security_events'] 
                if event.get('severity') in ['HIGH', 'CRITICAL']
            ]
            
            if high_severity_events:
                print(f"WARNING: HIGH/CRITICAL events: {len(high_severity_events)}")
                for event in high_severity_events:
                    print(f"   {event.get('event_type', 'UNKNOWN')}: {event.get('description', 'No description')}")
        
        print("-" * 40)
    
    # Function to create analysis prompt
    def create_analysis_prompt(chunk, response_language):
        # For real-time tcpdump, we need to handle the raw data differently
        # since it won't be pre-processed like batch mode
        logs = "".join(chunk)
        model_schema = PacketAnalysis.model_json_schema()
        return PROMPT_TEMPLATE_TCPDUMP_PACKET.format(
            logs=logs, 
            model_schema=model_schema, 
            response_language=response_language
        )
    
    # Start real-time monitoring
    try:
        monitor.monitor_and_analyze(
            model=model,
            analysis_prompt_func=create_analysis_prompt,
            analysis_schema_class=PacketAnalysis,
            process_callback=process_result_callback
        )
    except FileNotFoundError:
        print(f"ERROR: Log file not found: {config['log_path']}")
        print("NOTE: Make sure the log file exists and is readable")
        print("NOTE: You may need to run with appropriate permissions")
    except PermissionError:
        print(f"ERROR: Permission denied: {config['log_path']}")
        print("NOTE: You may need to run with sudo or adjust file permissions")
    except Exception as e:
        print(f"ERROR: Unexpected error: {e}")


def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(description='TCPDump Packet Analysis')
    parser.add_argument('--mode', choices=['batch', 'realtime'], default='batch',
                       help='Analysis mode: batch (default) or realtime')
    parser.add_argument('--chunk-size', type=int, default=None,
                       help='Override default chunk size')
    parser.add_argument('--log-path', type=str, default=None,
                       help='Override default log file path')
    parser.add_argument('--processing-mode', choices=['full', 'sampling'], default=None,
                       help='Real-time processing mode: full (process all) or sampling (latest only)')
    parser.add_argument('--sampling-threshold', type=int, default=None,
                       help='Auto-switch to sampling if accumulated lines exceed this (only for full mode)')
    args = parser.parse_args()
    
    if args.mode == 'realtime':
        run_realtime_analysis(args.chunk_size, args.log_path, args.processing_mode, args.sampling_threshold)
    else:
        run_batch_analysis()


if __name__ == "__main__":
    main()
