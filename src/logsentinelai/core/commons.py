"""
LogSentinelAI Commons Module
Main analysis functions and common interfaces for log processing

This module provides the core functionality for log analysis,
including batch and real-time processing capabilities.
"""
import json
from rich import print_json
import datetime
import hashlib
from typing import Dict, Any, Optional, List

# Import from modularized components
from .config import (
    get_analysis_config, LLM_PROVIDER, LLM_MODELS, 
    LLM_TEMPERATURE, LLM_TOP_P
)
from .llm import initialize_llm_model, generate_with_model, wait_on_failure
from .elasticsearch import send_to_elasticsearch_raw
from .geoip import enrich_source_ips_with_geoip
from .utils import chunked_iterable, print_chunk_contents
from .monitoring import RealtimeLogMonitor, create_realtime_monitor

def send_to_elasticsearch(analysis_data: Dict[str, Any], log_type: str, chunk_id: Optional[int] = None, chunk: Optional[List] = None) -> bool:
    """
    Send analysis results to Elasticsearch with GeoIP enrichment.
    
    Args:
        analysis_data: Analysis result data
        log_type: Log type
        chunk_id: Chunk number (optional)
        chunk: Original log chunk (optional)
    
    Returns:
        bool: Whether transmission was successful
    """
    # Enrich with GeoIP information before sending
    enriched_data = enrich_source_ips_with_geoip(analysis_data)
    return send_to_elasticsearch_raw(enriched_data, log_type, chunk_id)

def process_log_chunk(model, prompt, model_class, chunk_start_time, chunk_end_time, 
                     elasticsearch_index, chunk_number, chunk_data, llm_provider=None, llm_model=None,
                     processing_mode=None, log_path=None, access_mode=None):
    """
    Common function to process log chunks
    
    Args:
        model: LLM model object
        prompt: Prompt for analysis
        model_class: Pydantic model class
        chunk_start_time: Chunk analysis start time
        chunk_end_time: Chunk analysis completion time (if None, will be calculated after LLM processing)
        elasticsearch_index: Elasticsearch index name
        chunk_number: Chunk number
        chunk_data: Original chunk data
        llm_provider: LLM provider name
        llm_model: LLM model name
        processing_mode: Processing mode information (default: "batch")
        log_path: Log file path to include in metadata
        access_mode: Access mode (local/ssh) to include in metadata
    
    Returns:
        (success: bool, parsed_data: dict or None)
    """
    try:
        # Generate response using LLM
        review = generate_with_model(model, prompt, model_class, llm_provider)
        
        # Record end time if not provided
        if chunk_end_time is None:
            chunk_end_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        
        # Parse JSON response
        parsed = json.loads(review)

        # Print raw LLM response JSON (before any post-processing)
        print("\n✅ [LLM Raw Response JSON]")
        print("-" * 30)
        try:
            print_json(json.dumps(parsed, ensure_ascii=False, indent=4))
        except Exception as e:
            print(f"(Failed to pretty-print LLM response: {e})\nRaw: {review}")
        
        # Create log ID mapping
        log_raw_data = {}
        log_count = 0
        for line in chunk_data:
            line = line.strip()
            if line.startswith("LOGID-"):
                parts = line.split(" ", 1)
                logid = parts[0]
                original_content = parts[1] if len(parts) > 1 else ""
                log_raw_data[logid] = original_content
                log_count += 1
        
        # Add metadata
        parsed.update({
            "@chunk_analysis_start_utc": chunk_start_time,
            "@chunk_analysis_end_utc": chunk_end_time,
            "@processing_result": "success",
            "@log_count": log_count,
            "@log_raw_data": log_raw_data,
            "@processing_mode": processing_mode or "batch",
            "@access_mode": access_mode or "local"
        })
        
        # Add optional metadata
        if llm_provider:
            parsed["@llm_provider"] = llm_provider
        if llm_model:
            parsed["@llm_model"] = llm_model
        if log_path:
            parsed["@log_path"] = log_path
        
        # Validate with Pydantic model
        model_class.model_validate(parsed)

        # Enrich with GeoIP and print final data before ES input
        enriched_data = enrich_source_ips_with_geoip(parsed)
        print("\n✅ [Final ES Input JSON]")
        print("-" * 30)
        print_json(json.dumps(enriched_data, ensure_ascii=False, indent=4))

        # Send to Elasticsearch
        print(f"\nSending data to Elasticsearch...")
        success = send_to_elasticsearch(enriched_data, elasticsearch_index, chunk_number, chunk_data)
        if success:
            print(f"✅ Chunk {chunk_number} data sent to Elasticsearch successfully")
        else:
            print(f"❌ Chunk {chunk_number} data failed to send to Elasticsearch")

        return True, enriched_data
        
    except json.JSONDecodeError as e:
        return _handle_processing_error(e, "json_parse_error", chunk_start_time, chunk_end_time,
                                      chunk_number, chunk_data, processing_mode, llm_provider, 
                                      llm_model, log_path, elasticsearch_index, raw_response=review)
        
    except Exception as e:
        return _handle_processing_error(e, "processing_error", chunk_start_time, chunk_end_time,
                                      chunk_number, chunk_data, processing_mode, llm_provider,
                                      llm_model, log_path, elasticsearch_index, raw_response=None)

def _handle_processing_error(error, error_type, chunk_start_time, chunk_end_time, chunk_number, 
                           chunk_data, processing_mode, llm_provider, llm_model, log_path, elasticsearch_index, raw_response=None):
    """Handle processing errors and send failure information to Elasticsearch"""
    print(f"❌ {error_type.replace('_', ' ').title()}: {error}")
    
    # If this is a JSON parse error and we have the raw response, print it for debugging
    if error_type == "json_parse_error" and raw_response:
        print(f"\n🔍 [Debug] Raw LLM Response (for debugging JSON parse error):")
        print("-" * 80)
        print(raw_response)
        print("-" * 80)
        print(f"Response length: {len(raw_response)} characters")
        
        # Also try to show where the error might be occurring
        if hasattr(error, 'pos'):
            error_pos = error.pos
            start_pos = max(0, error_pos - 100)
            end_pos = min(len(raw_response), error_pos + 100)
            print(f"Error position: {error_pos}")
            print(f"Context around error position:")
            print(f"'{raw_response[start_pos:end_pos]}'")
    
    if chunk_end_time is None:
        chunk_end_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    
    log_count = sum(1 for line in chunk_data if line.strip().startswith("LOGID-"))
    
    failure_data = {
        "@chunk_analysis_start_utc": chunk_start_time,
        "@chunk_analysis_end_utc": chunk_end_time,
        "@processing_result": "failed",
        "@error_type": error_type,
        "@error_message": str(error)[:200],
        "@chunk_id": chunk_number,
        "@log_count": log_count,
        "@processing_mode": processing_mode or "batch"
    }
    
    # Add optional metadata
    if llm_provider:
        failure_data["@llm_provider"] = llm_provider
    if llm_model:
        failure_data["@llm_model"] = llm_model
    if log_path:
        failure_data["@log_path"] = log_path
    
    print(f"\nSending failure information to Elasticsearch...")
    success = send_to_elasticsearch(failure_data, elasticsearch_index, chunk_number, chunk_data)
    if success:
        print(f"✅ Chunk {chunk_number} failure information sent to Elasticsearch successfully")
    else:
        print(f"❌ Chunk {chunk_number} failure information failed to send to Elasticsearch")
    
    return False, None

def run_generic_batch_analysis(log_type: str, analysis_schema_class, prompt_template, analysis_title: str,
                             log_path: Optional[str] = None, chunk_size: Optional[int] = None,
                             remote_mode: Optional[str] = None, ssh_config: Optional[Dict[str, Any]] = None,
                             remote_log_path: Optional[str] = None):
    """
    Generic batch analysis function for all log types
    
    Args:
        log_type: Type of log ("httpd_access", "httpd_apache_error", "linux_system")
        analysis_schema_class: Pydantic schema class for structured output
        prompt_template: Prompt template string
        analysis_title: Title to display in output header
        log_path: Override log file path (for local files)
        chunk_size: Override chunk size
        remote_mode: "local" or "ssh" (overrides config default)
        ssh_config: Custom SSH configuration dict
        remote_log_path: Custom remote log path
    """
    print("=" * 70)
    print(f"LogSentinelAI - {analysis_title} (Batch Mode)")
    print("=" * 70)
    
    # Get LLM configuration
    llm_provider = LLM_PROVIDER
    llm_model_name = LLM_MODELS.get(LLM_PROVIDER, "unknown")
    
    # Get analysis configuration
    config = get_analysis_config(
        log_type,
        chunk_size=chunk_size,
        analysis_mode="batch",
        remote_mode=remote_mode,
        ssh_config=ssh_config,
        remote_log_path=log_path if remote_mode == "ssh" else remote_log_path
    )
    
    # Override log path if provided (for local files)
    if log_path and config["access_mode"] == "local":
        config["log_path"] = log_path
    
    print(f"Access mode:       {config['access_mode'].upper()}")
    print(f"Log file:          {config['log_path']}")
    print(f"Chunk size:        {config['chunk_size']}")
    print(f"Response language: {config['response_language']}")
    print(f"LLM Provider:      {llm_provider}")
    print(f"LLM Model:         {llm_model_name}")
    if config["access_mode"] == "ssh":
        ssh_info = config["ssh_config"]
        print(f"SSH Target:        {ssh_info.get('user', 'unknown')}@{ssh_info.get('host', 'unknown')}:{ssh_info.get('port', 22)}")
    print("=" * 70)
    
    log_path = config["log_path"]
    chunk_size = config["chunk_size"]
    response_language = config["response_language"]
    
    model = initialize_llm_model()
    
    with open(log_path, "r", encoding="utf-8") as f:
        for i, chunk in enumerate(chunked_iterable(f, chunk_size, debug=False)):
            # Record analysis start time
            chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
            logs = "".join(chunk).rstrip("\n")
            model_schema = analysis_schema_class.model_json_schema()
            prompt = prompt_template.format(logs=logs, model_schema=model_schema, response_language=response_language)
            prompt = prompt.strip()
            if i == 0:
                print("\n[LLM Prompt Submitted]")
                print("-" * 50)
                print(prompt)
                print("-" * 50)
            print(f"\n--- Chunk {i+1} ---")
            print_chunk_contents(chunk)
            
            # Process chunk using common function
            success, parsed_data = process_log_chunk(
                model=model,
                prompt=prompt,
                model_class=analysis_schema_class,
                chunk_start_time=chunk_start_time,
                chunk_end_time=None,  # Will be calculated in function
                elasticsearch_index=log_type,
                chunk_number=i+1,
                chunk_data=chunk,
                llm_provider=llm_provider,
                llm_model=llm_model_name,
                processing_mode="batch",
                log_path=log_path,
                access_mode=config["access_mode"]
            )
            
            if success:
                print("✅ Analysis completed successfully")
            else:
                print("❌ Analysis failed")
                wait_on_failure(30)  # Wait 30 seconds on failure
            
            print("-" * 50)

def run_generic_realtime_analysis(log_type: str, analysis_schema_class, prompt_template, analysis_title: str,
                                 chunk_size=None, log_path=None, processing_mode=None, sampling_threshold=None,
                                 remote_mode=None, ssh_config=None, remote_log_path=None):
    """
    Generic real-time analysis function for all log types
    
    Args:
        log_type: Type of log ("httpd_access", "httpd_apache_error", "linux_system")
        analysis_schema_class: Pydantic schema class for structured output
        prompt_template: Prompt template string
        analysis_title: Title to display in output header
        chunk_size: Override default chunk size
        log_path: Override default log file path (local mode only)
        processing_mode: Processing mode (full/sampling)
        sampling_threshold: Sampling threshold
        remote_mode: "local" or "ssh"
        ssh_config: SSH configuration dict
        remote_log_path: Remote log file path
    """
    print("=" * 70)
    print(f"LogSentinelAI - {analysis_title} (Real-time Mode)")
    print("=" * 70)
    
    # Override environment variables if specified
    if processing_mode:
        import os
        os.environ["REALTIME_PROCESSING_MODE"] = processing_mode
    if sampling_threshold:
        import os
        os.environ["REALTIME_SAMPLING_THRESHOLD"] = str(sampling_threshold)
    
    # Get LLM configuration  
    llm_provider = LLM_PROVIDER
    llm_model_name = LLM_MODELS.get(LLM_PROVIDER, "unknown")
    
    # Get configuration
    config = get_analysis_config(
        log_type, 
        chunk_size, 
        analysis_mode="realtime",
        remote_mode=remote_mode,
        ssh_config=ssh_config,
        remote_log_path=log_path if remote_mode == "ssh" else None
    )
    
    # Override local log path if specified (for local mode only)
    if log_path and config["access_mode"] == "local":
        config["log_path"] = log_path
    
    print(f"Access mode:       {config['access_mode'].upper()}")
    print(f"Log file:          {config['log_path']}")
    print(f"Chunk size:        {config['chunk_size']}")
    print(f"Response language: {config['response_language']}")
    print(f"Analysis mode:     {config['analysis_mode']}")
    print(f"LLM Provider:      {llm_provider}")
    print(f"LLM Model:         {llm_model_name}")
    if config["access_mode"] == "ssh":
        ssh_info = config["ssh_config"]
        print(f"SSH Target:        {ssh_info.get('user', 'unknown')}@{ssh_info.get('host', 'unknown')}:{ssh_info.get('port', 22)}")
    print("=" * 70)
    
    # Initialize LLM model
    print("\nInitializing LLM model...")
    model = initialize_llm_model()
    
    # Create real-time monitor
    try:
        monitor = RealtimeLogMonitor(log_type, config)
    except ValueError as e:
        print(f"ERROR: Configuration error: {e}")
        print("Please check your configuration settings")
        return
    
    # Function to create analysis prompt and convert chunk to LOGID format
    def prepare_chunk_for_analysis(chunk, response_language):
        # Add LOGID prefix to each line for consistency with batch mode
        lines_with_logid = []
        for line in chunk:
            if line.strip():  # Skip empty lines
                # Generate LOGID for the line
                logid = f"LOGID-{hashlib.md5(line.strip().encode()).hexdigest().upper()}"
                # Add LOGID prefix to the line
                lines_with_logid.append(f"{logid} {line.strip()}")
        
        # Create prompt
        logs = "\n".join(lines_with_logid)
        model_schema = analysis_schema_class.model_json_schema()
        prompt = prompt_template.format(
            logs=logs, 
            model_schema=model_schema, 
            response_language=response_language
        )
        
        return prompt, lines_with_logid
    
    # Start real-time monitoring
    try:
        print("\nStarting real-time monitoring... (Press Ctrl+C to stop)")
        print("Waiting for new log entries...")
        
        chunk_counter = 0
        import time
        
        while True:
            # Check for new chunks
            for chunk in monitor.get_new_log_chunks():
                chunk_counter += 1
                chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
                
                print(f"\n--- Chunk {chunk_counter} (Real-time) ---")
                
                # Show the chunk contents (this was missing!)
                print_chunk_contents(chunk)
                
                # Prepare chunk for analysis 
                prompt, lines_with_logid = prepare_chunk_for_analysis(chunk, config["response_language"])
                
                # Process chunk using common function
                success, parsed_data = process_log_chunk(
                    model=model,
                    prompt=prompt,
                    model_class=analysis_schema_class,
                    chunk_start_time=chunk_start_time,
                    chunk_end_time=None,
                    elasticsearch_index=log_type,
                    chunk_number=chunk_counter,
                    chunk_data=lines_with_logid,  # Pass LOGID formatted data
                    llm_provider=llm_provider,
                    llm_model=llm_model_name,
                    processing_mode="realtime",
                    log_path=config["log_path"],
                    access_mode=config["access_mode"]
                )
                
                if success:
                    print("✅ Real-time analysis completed successfully")
                    
                    # Show high severity events summary
                    if parsed_data and 'events' in parsed_data:
                        event_count = len(parsed_data['events'])
                        print(f"Found {event_count} security events in this chunk")
                        
                        # Show high severity events
                        high_severity_events = [
                            event for event in parsed_data['events'] 
                            if event.get('severity') in ['HIGH', 'CRITICAL']
                        ]
                        
                        if high_severity_events:
                            print(f"⚠️  WARNING: HIGH/CRITICAL events: {len(high_severity_events)}")
                            for event in high_severity_events:
                                print(f"   {event.get('event_type', 'UNKNOWN')}: {event.get('description', 'No description')}")
                else:
                    print("❌ Real-time analysis failed")
                    wait_on_failure(30)  # Wait 30 seconds on failure
                
                print("-" * 50)
            
            # Sleep for polling interval
            time.sleep(config["realtime_config"]["polling_interval"])
            
    except KeyboardInterrupt:
        print("\n\n🛑 Real-time monitoring stopped by user")
        print("Position saved. You can resume monitoring from where you left off.")
    except FileNotFoundError:
        print(f"ERROR: Log file not found: {config['log_path']}")
        print("NOTE: Make sure the log file exists and is readable")
    except PermissionError:
        print(f"ERROR: Permission denied: {config['log_path']}")
        print("NOTE: You may need to run with sudo or adjust file permissions")
    except Exception as e:
        print(f"ERROR: Unexpected error: {e}")
        import traceback
        traceback.print_exc()

def create_argument_parser(description: str):
    """
    Create a standard argument parser for all analysis scripts
    
    Args:
        description: Description for the argument parser
    
    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    import argparse
    parser = argparse.ArgumentParser(description=description)
    
    # Analysis mode
    parser.add_argument('--mode', choices=['batch', 'realtime'], default='batch',
                       help='Analysis mode: batch (default) or realtime')
    
    # Chunk configuration
    parser.add_argument('--chunk-size', type=int, default=None,
                       help='Override default chunk size')
    
    # Log file path
    parser.add_argument('--log-path', type=str, default=None,
                       help='Log file path (local: /path/to/log, remote: /var/log/remote.log)')
    
    # Remote access configuration
    parser.add_argument('--remote', action='store_true',
                       help='Enable remote log access via SSH')
    parser.add_argument('--ssh', type=str, default=None,
                       help='SSH connection info: user@host[:port] (required with --remote)')
    parser.add_argument('--ssh-key', type=str, default=None,
                       help='SSH private key file path')
    parser.add_argument('--ssh-password', type=str, default=None,
                       help='SSH password (if no key file provided)')
    
    # Real-time processing configuration
    parser.add_argument('--processing-mode', choices=['full', 'sampling'], default=None,
                       help='Real-time processing mode: full (process all) or sampling (latest only)')
    parser.add_argument('--sampling-threshold', type=int, default=None,
                       help='Auto-switch to sampling if accumulated lines exceed this (only for full mode)')
    
    return parser

def parse_ssh_config_from_args(args) -> Optional[Dict[str, Any]]:
    """
    Parse SSH configuration from command line arguments
    
    Args:
        args: Parsed command line arguments
    
    Returns:
        Dict or None: SSH configuration dictionary or None if not remote mode
    """
    if not getattr(args, 'remote', False):
        return None
    
    ssh_config = {}
    
    # Parse SSH connection string (user@host[:port])
    if hasattr(args, 'ssh') and args.ssh:
        ssh_parts = args.ssh.split('@')
        if len(ssh_parts) != 2:
            raise ValueError("SSH format must be: user@host[:port]")
        
        user, host_port = ssh_parts
        ssh_config['user'] = user
        
        # Parse host and optional port
        if ':' in host_port:
            host, port = host_port.split(':', 1)
            ssh_config['host'] = host
            try:
                ssh_config['port'] = int(port)
            except ValueError:
                raise ValueError(f"Invalid SSH port: {port}")
        else:
            ssh_config['host'] = host_port
            ssh_config['port'] = 22  # Default port
    
    # Authentication method
    if hasattr(args, 'ssh_key') and args.ssh_key:
        ssh_config['key_path'] = args.ssh_key
    
    if hasattr(args, 'ssh_password') and args.ssh_password:
        ssh_config['password'] = args.ssh_password
    
    return ssh_config if ssh_config else None

def validate_args(args):
    """
    Validate command line arguments for consistency and requirements
    
    Args:
        args: Parsed command line arguments
    
    Raises:
        ValueError: If arguments are invalid or inconsistent
    """
    # Remote mode validation
    if getattr(args, 'remote', False):
        # SSH connection info is required
        if not getattr(args, 'ssh', None):
            raise ValueError("--ssh user@host[:port] is required when using --remote")
        
        # At least one authentication method is required
        if not getattr(args, 'ssh_key', None) and not getattr(args, 'ssh_password', None):
            raise ValueError("Either --ssh-key or --ssh-password is required with --remote")
        
        # Validate SSH format
        ssh = getattr(args, 'ssh', '')
        if '@' not in ssh:
            raise ValueError("SSH format must be: user@host[:port]")
    
    # Local mode validation - warn about unused SSH options
    else:
        ssh_options = ['ssh', 'ssh_key', 'ssh_password']
        for opt in ssh_options:
            if getattr(args, opt, None):
                print(f"WARNING: --{opt.replace('_', '-')} is ignored in local mode")

def get_remote_mode_from_args(args) -> str:
    """
    Determine access mode from command line arguments
    
    Args:
        args: Parsed command line arguments
    
    Returns:
        str: "ssh" if remote mode, "local" otherwise
    """
    return "ssh" if getattr(args, 'remote', False) else "local"

def get_log_path_from_args(args) -> Optional[str]:
    """
    Get log path from command line arguments
    
    Args:
        args: Parsed command line arguments
    
    Returns:
        str or None: Log file path or None if not specified
    """
    return getattr(args, 'log_path', None)

def handle_ssh_arguments(args):
    """
    Handle SSH configuration setup from command line arguments
    
    Args:
        args: Parsed command line arguments
    
    Returns:
        dict or None: SSH configuration dictionary or None for local mode
    """
    if not getattr(args, 'remote', False):
        return None
    
    # Validate arguments
    validate_args(args)
    
    # Parse SSH configuration
    ssh_config = parse_ssh_config_from_args(args)
    return ssh_config

# Legacy compatibility functions (simplified versions of removed complex functionality)
def create_ssh_client(ssh_config):
    """
    Create SSH client from configuration (simplified version)
    
    Args:
        ssh_config: SSH configuration dictionary
    
    Returns:
        Simple connection info or None if failed
    """
    if not ssh_config:
        return None
    
    print(f"Note: SSH client creation moved to ssh.py module")
    print(f"Target: {ssh_config.get('user', 'unknown')}@{ssh_config.get('host', 'unknown')}")
    return ssh_config

def read_file_content(log_path: str, ssh_config=None) -> str:
    """
    Read file content either locally or via SSH (simplified version)
    
    Args:
        log_path: Path to the log file
        ssh_config: SSH configuration dictionary for remote access (optional)
    
    Returns:
        str: File content
    """
    if ssh_config:
        # For SSH access, recommend using the SSH module
        print(f"Note: For SSH file access, use RemoteSSHLogMonitor from ssh.py module")
        raise NotImplementedError("SSH file reading moved to ssh.py module")
    else:
        # Read local file
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            print(f"✗ Failed to read local file {log_path}: {e}")
            raise
