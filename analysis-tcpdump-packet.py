from pydantic import BaseModel, Field
from enum import Enum
from typing import Literal, Optional
import json
import os
import sys
import datetime
import subprocess
from dotenv import load_dotenv
import re

from commons import send_to_elasticsearch
from commons import initialize_llm_model
from commons import process_log_chunk
from commons import wait_on_failure
from commons import get_llm_config
from prompts import PROMPT_TEMPLATE_TCPDUMP_PACKET
from commons import chunked_iterable
from commons import print_chunk_contents
import hashlib

### Install the required packages
# uv add outlines ollama openai python-dotenv numpy

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

# LLM Response Language - Choose from "english", "korean"
# response_language = "english"
response_language = "korean"

# Get LLM configuration from commons
llm_provider, llm_model_name = get_llm_config()

model = initialize_llm_model()

# log_path = "sample-logs/tcpdump-packet-39.log"
log_path = "sample-logs/tcpdump-packet-2k.log"

chunk_size = 2  # Process 3 packets at a time

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
            llm_model=llm_model_name
        )
        
        if success:
            print("✅ Analysis completed successfully")
        else:
            print("❌ Analysis failed")
            wait_on_failure(30)  # 실패 시 30초 대기
        
        print("-" * 50)
