"""
LogSentinelAI Commons Module
Main analysis functions and common interfaces for log processing

This module provides the core functionality for log analysis,
including batch and real-time processing capabilities.
"""


import logging
import os
from contextvars import ContextVar

# Add context for @log_type so every log line can include it in the header
LOG_TYPE_CTX: ContextVar[str] = ContextVar("log_type", default="unknown")

def set_log_type(log_type: str):
    """Set current @log_type context used by the logging filter."""
    try:
        LOG_TYPE_CTX.set(str(log_type) if log_type else "unknown")
    except Exception:
        LOG_TYPE_CTX.set("unknown")

def setup_logger(name="logsentinelai", level=None):
    """
    Set up and return a logger with the specified name and level.
    """
    # Read environment variables at runtime to ensure config file has been loaded
    log_level = level or os.getenv("LOG_LEVEL", "INFO")
    log_file = os.getenv("LOG_FILE", "logsentinelai.log")
    
    logger = logging.getLogger(name)
    if not logger.hasHandlers():
        # Include @log_type right after LOG_LEVEL in the header
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(log_type)s] (%(name)s) %(message)s')
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        # Inject @log_type into each record
        class LogTypeFilter(logging.Filter):
            def filter(self, record: logging.LogRecord) -> bool:
                try:
                    record.log_type = LOG_TYPE_CTX.get()
                except Exception:
                    record.log_type = "unknown"
                return True
        logger.addFilter(LogTypeFilter())
    logger.setLevel(getattr(logging, str(log_level).upper(), logging.INFO))
    return logger

# 공통 logger 객체 생성
logger = setup_logger("logsentinelai.core.commons")
import json
from rich import print_json
import datetime
import glob
from typing import Dict, Any, Optional, List

# Import from modularized components
from . import config as config_module
from .llm import initialize_llm_model, generate_with_model, wait_on_failure
from .elasticsearch import send_to_elasticsearch_raw
from .geoip import enrich_source_ips_with_geoip
from ..utils.general import chunked_iterable, print_chunk_contents
from .monitoring import RealtimeLogMonitor, create_realtime_monitor
from .token_utils import count_tokens

def expand_file_patterns(file_patterns: List[str]) -> List[str]:
    """
    Expand file patterns (wildcards) to actual file paths
    
    Args:
        file_patterns: List of file patterns (can include wildcards like *, ?, [])
        
    Returns:
        List of actual file paths that match the patterns
    """
    expanded_files = []
    
    for pattern in file_patterns:
        # Use glob to expand wildcards
        matches = glob.glob(pattern)
        
        if matches:
            # Sort for consistent processing order
            matches.sort()
            expanded_files.extend(matches)
            logger.info(f"Pattern '{pattern}' expanded to {len(matches)} files: {matches}")
        else:
            # If no matches, treat as literal path (might be a single file)
            expanded_files.append(pattern)
            logger.warning(f"Pattern '{pattern}' did not match any files, treating as literal path")
    
    # Remove duplicates while preserving order
    seen = set()
    unique_files = []
    for file_path in expanded_files:
        if file_path not in seen:
            seen.add(file_path)
            unique_files.append(file_path)
    
    logger.info(f"Final expanded file list: {unique_files}")
    return unique_files

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
    # Ensure @log_type is set for this send path
    set_log_type(log_type)
    # Enrich with GeoIP information before sending
    enriched_data = enrich_source_ips_with_geoip(analysis_data)
    logger.info(f"Sending data to Elasticsearch (log_type={log_type}, chunk_id={chunk_id})")
    return send_to_elasticsearch_raw(enriched_data, log_type, chunk_id)

def process_log_chunk(model, prompt, model_class, chunk_start_time, chunk_end_time, 
                     elasticsearch_index, chunk_number, chunk_data, llm_provider=None, llm_model=None,
                     processing_mode=None, log_path=None, access_mode=None, token_size_input: int | None = None):
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
        # Make sure @log_type context is set within this processing scope
        if elasticsearch_index:
            set_log_type(elasticsearch_index)

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

        # Print LLM response token count (approximate) right after raw response output
        try:
            resp_tokens = count_tokens(review, llm_model)
            print(f"✅ LLM response tokens (approx.): {resp_tokens}")
            # Log token count with provider/model for traceability
            logger.info(
                f"LLM response tokens (approx.): {resp_tokens} (provider={llm_provider}, model={llm_model})"
            )
        except Exception:
            resp_tokens = None
            logger.warning(
                f"Failed to count LLM response tokens (provider={llm_provider}, model={llm_model})"
            )

        # Count log lines
        log_count = len([line for line in chunk_data if line.strip()])

        # Compute elapsed analysis time in seconds (start/end are ISO strings with 'Z')
        elapsed_seconds = None
        try:
            start_dt = None
            end_dt = None
            if isinstance(chunk_start_time, str):
                start_dt = datetime.datetime.fromisoformat(chunk_start_time.replace('Z', '+00:00'))
            elif isinstance(chunk_start_time, datetime.datetime):
                start_dt = chunk_start_time
            if isinstance(chunk_end_time, str):
                end_dt = datetime.datetime.fromisoformat(chunk_end_time.replace('Z', '+00:00'))
            elif isinstance(chunk_end_time, datetime.datetime):
                end_dt = chunk_end_time
            if start_dt and end_dt:
                elapsed_seconds = int((end_dt - start_dt).total_seconds())
        except Exception:
            elapsed_seconds = None

        # Log the computed elapsed time for observability
        logger.info(
            f"Chunk {chunk_number} analysis elapsed time: {elapsed_seconds}s (start={chunk_start_time}, end={chunk_end_time})"
        )

        # Add metadata
        parsed.update({
            "@chunk_analysis_start_utc": chunk_start_time,
            "@chunk_analysis_end_utc": chunk_end_time,
            "@chunk_analysis_elapsed_time": elapsed_seconds,
            "@processing_result": "success",
            "@log_count": log_count,
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
        # Token sizes (for ES indexing)
        token_in = int(token_size_input) if token_size_input is not None else None
        token_out = int(resp_tokens) if resp_tokens is not None else None
        if token_in is not None:
            parsed["@token_size_input"] = token_in
        if token_out is not None:
            parsed["@token_size_output"] = token_out
        # Removed @token_size_total as requested

        # Validate with Pydantic model
        model_class.model_validate(parsed)

        # Enrich with GeoIP
        enriched_data = enrich_source_ips_with_geoip(parsed)

        # Send to Elasticsearch
        logger.info(f"Processing chunk {chunk_number}: sending data to Elasticsearch.")
        success = send_to_elasticsearch(enriched_data, elasticsearch_index, chunk_number, chunk_data)
        if success:
            logger.info(f"Chunk {chunk_number} data sent to Elasticsearch successfully.")
            print(f"✅ Chunk {chunk_number} data sent to Elasticsearch successfully")
        else:
            logger.error(f"Chunk {chunk_number} data failed to send to Elasticsearch.")
            print(f"❌ Chunk {chunk_number} data failed to send to Elasticsearch")

        return True, enriched_data

    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in chunk {chunk_number}: {e}")
        return _handle_processing_error(e, "json_parse_error", chunk_start_time, chunk_end_time,
                                      chunk_number, chunk_data, processing_mode, llm_provider, 
                                      llm_model, log_path, elasticsearch_index, raw_response=review)

    except Exception as e:
        logger.error(f"Processing error in chunk {chunk_number}: {e}")
        return _handle_processing_error(e, "processing_error", chunk_start_time, chunk_end_time,
                                      chunk_number, chunk_data, processing_mode, llm_provider,
                                      llm_model, log_path, elasticsearch_index, raw_response=None)

def _handle_processing_error(error, error_type, chunk_start_time, chunk_end_time, chunk_number, 
                           chunk_data, processing_mode, llm_provider, llm_model, log_path, elasticsearch_index, raw_response=None):
    """Handle processing errors and send failure information to Elasticsearch"""
    logger.error(f"{error_type.replace('_', ' ').title()} in chunk {chunk_number}: {error}")
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

    log_count = len([line for line in chunk_data if line.strip()])

    # Compute elapsed analysis time in seconds for failure as well
    elapsed_seconds = None
    try:
        start_dt = None
        end_dt = None
        if isinstance(chunk_start_time, str):
            start_dt = datetime.datetime.fromisoformat(chunk_start_time.replace('Z', '+00:00'))
        elif isinstance(chunk_start_time, datetime.datetime):
            start_dt = chunk_start_time
        if isinstance(chunk_end_time, str):
            end_dt = datetime.datetime.fromisoformat(chunk_end_time.replace('Z', '+00:00'))
        elif isinstance(chunk_end_time, datetime.datetime):
            end_dt = chunk_end_time
        if start_dt and end_dt:
            elapsed_seconds = int((end_dt - start_dt).total_seconds())
    except Exception:
        elapsed_seconds = None

    # Log the computed elapsed time for the failure path
    logger.info(
        f"Chunk {chunk_number} analysis elapsed time (failure): {elapsed_seconds}s (start={chunk_start_time}, end={chunk_end_time})"
    )

    failure_data = {
        "@chunk_analysis_start_utc": chunk_start_time,
        "@chunk_analysis_end_utc": chunk_end_time,
        "@chunk_analysis_elapsed_time": elapsed_seconds,
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

    logger.info(f"Sending failure information to Elasticsearch for chunk {chunk_number}.")
    print(f"\nSending failure information to Elasticsearch...")
    success = send_to_elasticsearch(failure_data, elasticsearch_index, chunk_number, chunk_data)
    if success:
        logger.info(f"Chunk {chunk_number} failure information sent to Elasticsearch successfully.")
        print(f"✅ Chunk {chunk_number} failure information sent to Elasticsearch successfully")
    else:
        logger.error(f"Chunk {chunk_number} failure information failed to send to Elasticsearch.")
        print(f"❌ Chunk {chunk_number} failure information failed to send to Elasticsearch")

    return False, None

def run_generic_batch_analysis(log_type: str, analysis_schema_class, prompt_template, analysis_title: str,
                             log_path: Optional[str] = None, chunk_size: Optional[int] = None,
                             remote_mode: Optional[str] = None, ssh_config: Optional[Dict[str, Any]] = None,
                             remote_log_path: Optional[str] = None):
    """
    Generic batch analysis function for all log types
    Support wildcard patterns for multiple file processing
    
    Args:
        log_type: Type of log ("httpd_access", "httpd_server", "linux_system")
        analysis_schema_class: Pydantic schema class for structured output
        prompt_template: Prompt template string
        analysis_title: Title to display in output header
        log_path: Override log file path (supports wildcards like *.log, /var/log/apache*.log)
        chunk_size: Override chunk size
        remote_mode: "local" or "ssh" (overrides config default)
        ssh_config: Custom SSH configuration dict
        remote_log_path: Custom remote log path
    """
    # Set @log_type context for this run
    set_log_type(log_type)
    logger.info(f"Starting batch analysis for {log_type} ({analysis_title})")
    print("=" * 70)
    print(f"LogSentinelAI - {analysis_title} (Batch Mode)")
    print("=" * 70)
    
    # Get LLM configuration
    llm_provider = config_module.LLM_PROVIDER
    llm_model_name = config_module.LLM_MODELS.get(config_module.LLM_PROVIDER, "unknown")
    logger.info(f"Using LLM provider: {llm_provider}, model: {llm_model_name}")
    
    # Get analysis configuration
    try:
        config = config_module.get_analysis_config(
            log_type,
            chunk_size=chunk_size,
            analysis_mode="batch",
            remote_mode=remote_mode,
            ssh_config=ssh_config,
            remote_log_path=log_path if remote_mode == "ssh" else remote_log_path
        )
        logger.info(f"Analysis configuration loaded successfully for {log_type}")
    except Exception as e:
        logger.error(f"Failed to get analysis configuration: {e}")
        raise
    
    # Handle wildcard file patterns for local mode
    if config["access_mode"] == "local":
        # Determine file patterns to process
        if log_path:
            # Use provided log_path (may contain wildcards)
            file_patterns = [log_path]
            logger.info(f"Using provided log path pattern: {log_path}")
        else:
            # Use config log_path
            file_patterns = [config["log_path"]]
            logger.info(f"Using config log path: {config['log_path']}")
        
        # Expand wildcard patterns to actual files
        log_files = expand_file_patterns(file_patterns)
        
        if not log_files:
            logger.error(f"No files found matching patterns: {file_patterns}")
            print(f"ERROR: No files found matching patterns: {file_patterns}")
            raise FileNotFoundError(f"No files found matching patterns: {file_patterns}")
        
        logger.info(f"Found {len(log_files)} files to process: {log_files}")
        print(f"Files to process: {len(log_files)}")
        for i, file_path in enumerate(log_files, 1):
            print(f"  {i}. {file_path}")
        
    else:
        # SSH mode - single file only (no wildcard support for remote files yet)
        if log_path:
            config["log_path"] = log_path
            logger.info(f"Overriding remote log path to: {log_path}")
        log_files = [config["log_path"]]
        logger.info(f"SSH mode - processing single remote file: {config['log_path']}")
    
    chunk_size = config["chunk_size"]
    response_language = config["response_language"]
    
    # Display configuration summary
    logger.info(f"Final configuration - Access mode: {config['access_mode']}, Files: {len(log_files)}, Chunk size: {chunk_size}")
    print(f"Access mode:       {config['access_mode'].upper()}")
    print(f"Total files:       {len(log_files)}")
    print(f"Chunk size:        {chunk_size}")
    print(f"Response language: {response_language}")
    print(f"LLM Provider:      {llm_provider}")
    print(f"LLM Model:         {llm_model_name}")
    if config["access_mode"] == "ssh":
        ssh_info = config["ssh_config"]
        ssh_target = f"{ssh_info.get('user', 'unknown')}@{ssh_info.get('host', 'unknown')}:{ssh_info.get('port', 22)}"
        logger.info(f"SSH target configured: {ssh_target}")
        print(f"SSH Target:        {ssh_target}")
    print("=" * 70)
    
    logger.info("Initializing LLM model...")
    model = initialize_llm_model()
    logger.info("LLM model initialized successfully.")
    
    # Process all files
    total_chunks_processed = 0
    successful_files = 0
    failed_files = 0
    
    for file_index, current_log_path in enumerate(log_files, 1):
        print(f"\n📁 Processing file {file_index}/{len(log_files)}: {current_log_path}")
        logger.info(f"Starting analysis of file {file_index}/{len(log_files)}: {current_log_path}")
        
        try:
            # Use streaming batch processing for memory safety and logrotate handling
            chunk_count = _process_file_streaming_batch(
                log_path=current_log_path,
                chunk_size=chunk_size,
                model=model,
                analysis_schema_class=analysis_schema_class,
                prompt_template=prompt_template,
                response_language=response_language,
                log_type=log_type,
                llm_provider=llm_provider,
                llm_model_name=llm_model_name,
                config=config
            )
            total_chunks_processed += chunk_count
            successful_files += 1
            logger.info(f"File {file_index} completed successfully. Chunks processed: {chunk_count}")
            print(f"✅ File {file_index} completed successfully. Chunks processed: {chunk_count}")
            
        except FileNotFoundError:
            failed_files += 1
            logger.error(f"File {file_index} not found: {current_log_path}")
            print(f"❌ ERROR: File {file_index} not found: {current_log_path}")
            # Continue with next file instead of raising
            continue
        except PermissionError:
            failed_files += 1
            logger.error(f"Permission denied accessing file {file_index}: {current_log_path}")
            print(f"❌ ERROR: Permission denied: {current_log_path}")
            # Continue with next file instead of raising
            continue
        except Exception as e:
            failed_files += 1
            logger.error(f"Unexpected error processing file {file_index} ({current_log_path}): {e}")
            print(f"❌ ERROR processing file {file_index}: {e}")
            # Continue with next file instead of raising
            continue
    
    # Final summary
    print(f"\n" + "=" * 70)
    print(f"BATCH ANALYSIS SUMMARY")
    print(f"=" * 70)
    print(f"Total files processed: {successful_files}/{len(log_files)}")
    print(f"Failed files:          {failed_files}")
    print(f"Total chunks:          {total_chunks_processed}")
    print(f"=" * 70)
    
    logger.info(f"Batch analysis completed. Files: {successful_files}/{len(log_files)}, Failed: {failed_files}, Total chunks: {total_chunks_processed}")
    
    # Raise error only if all files failed
    if successful_files == 0 and len(log_files) > 0:
        raise RuntimeError(f"All {len(log_files)} files failed to process")
        print(f"ERROR: Unexpected error: {e}")
        raise

def run_generic_realtime_analysis(log_type: str, analysis_schema_class, prompt_template, analysis_title: str,
                                 chunk_size=None, log_path=None, only_sampling_mode=None, sampling_threshold=None,
                                 remote_mode=None, ssh_config=None, remote_log_path=None):
    """
    Generic real-time analysis function for all log types
    
    Args:
        log_type: Type of log ("httpd_access", "httpd_server", "linux_system")
        analysis_schema_class: Pydantic schema class for structured output
        prompt_template: Prompt template string
        analysis_title: Title to display in output header
        chunk_size: Override default chunk size
        log_path: Override default log file path (local mode only)
        only_sampling_mode: Force sampling mode if True
        sampling_threshold: Sampling threshold
        remote_mode: "local" or "ssh"
        ssh_config: SSH configuration dict
        remote_log_path: Remote log file path
    """
    # Set @log_type context for this run
    set_log_type(log_type)
    logger.info(f"Starting real-time analysis for {log_type} ({analysis_title})")
    print("=" * 70)
    print(f"LogSentinelAI - {analysis_title} (Real-time Mode)")
    print("=" * 70)
    
    # Override environment variables if specified
    if only_sampling_mode:
        import os
        os.environ["REALTIME_ONLY_SAMPLING_MODE"] = "true"
        logger.info("Sampling mode forced via parameter")
    if sampling_threshold:
        import os
        os.environ["REALTIME_SAMPLING_THRESHOLD"] = str(sampling_threshold)
        logger.info(f"Sampling threshold set to: {sampling_threshold}")
    
    # Get LLM configuration  
    llm_provider = config_module.LLM_PROVIDER
    llm_model_name = config_module.LLM_MODELS.get(config_module.LLM_PROVIDER, "unknown")
    logger.info(f"Using LLM provider: {llm_provider}, model: {llm_model_name}")
    
    # Get configuration
    try:
        config = config_module.get_analysis_config(
            log_type, 
            chunk_size, 
            analysis_mode="realtime",
            remote_mode=remote_mode,
            ssh_config=ssh_config,
            remote_log_path=log_path if remote_mode == "ssh" else None
        )
        logger.info(f"Real-time analysis configuration loaded successfully for {log_type}")
    except Exception as e:
        logger.error(f"Failed to get real-time analysis configuration: {e}")
        raise
    
    # Override local log path if specified (for local mode only)
    if log_path and config["access_mode"] == "local":
        config["log_path"] = log_path
        logger.info(f"Overriding log path to: {log_path}")
    
    logger.info(f"Final real-time configuration - Access mode: {config['access_mode']}, Log file: {config['log_path']}, Chunk size: {config['chunk_size']}")
    print(f"Access mode:       {config['access_mode'].upper()}")
    print(f"Log file:          {config['log_path']}")
    print(f"Chunk size:        {config['chunk_size']}")
    print(f"Response language: {config['response_language']}")
    print(f"Analysis mode:     {config['analysis_mode']}")
    print(f"LLM Provider:      {llm_provider}")
    print(f"LLM Model:         {llm_model_name}")
    if config["access_mode"] == "ssh":
        ssh_info = config["ssh_config"]
        ssh_target = f"{ssh_info.get('user', 'unknown')}@{ssh_info.get('host', 'unknown')}:{ssh_info.get('port', 22)}"
        logger.info(f"SSH target configured for real-time: {ssh_target}")
        print(f"SSH Target:        {ssh_target}")
    print("=" * 70)
    
    # Initialize LLM model
    logger.info("Initializing LLM model for real-time analysis...")
    print("\nInitializing LLM model...")
    model = initialize_llm_model()
    logger.info("LLM model initialized successfully for real-time analysis.")
    
    # Create real-time monitor
    try:
        logger.info("Creating real-time log monitor...")
        monitor = RealtimeLogMonitor(log_type, config)
        logger.info("Real-time log monitor created successfully.")
    except ValueError as e:
        logger.error(f"Configuration error creating real-time monitor: {e}")
        print(f"ERROR: Configuration error: {e}")
        print("Please check your configuration settings")
        return
    except Exception as e:
        logger.error(f"Failed to create real-time monitor: {e}")
        print(f"ERROR: Failed to create monitor: {e}")
        return
    
    # Function to create analysis prompt from raw chunk data
    def prepare_chunk_for_analysis(chunk, response_language):
        # Create prompt with original log lines
        logs = "\n".join(line.strip() for line in chunk if line.strip())  # Skip empty lines
        model_schema = analysis_schema_class.model_json_schema()
        prompt = prompt_template.format(
            logs=logs, 
            model_schema=model_schema, 
            response_language=response_language
        )
        
        return prompt, chunk
    
    # Start real-time monitoring
    try:
        logger.info("Starting real-time monitoring...")
        print("\nStarting real-time monitoring... (Press Ctrl+C to stop)")
        print("Waiting for new log entries...")
        
        chunk_counter = 0
        import time
        
        while True:
            # Check for new chunks
            for chunk in monitor.get_new_log_chunks():
                chunk_counter += 1
                logger.debug(f"Processing real-time chunk {chunk_counter}")
                chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
                
                print(f"\n--- Chunk {chunk_counter} (Real-time) ---")
                
                # Show the chunk contents (this was missing!)
                print_chunk_contents(chunk)
                
                # Prepare chunk for analysis 
                prompt, chunk_lines = prepare_chunk_for_analysis(chunk, config["response_language"])

                # Token count for prompt (approximate)
                try:
                    prompt_tokens = count_tokens(prompt, llm_model_name)
                    # Log token count with provider/model for traceability
                    logger.info(
                        f"Prompt tokens (approx.): {prompt_tokens} (provider={llm_provider}, model={llm_model_name})"
                    )
                except Exception:
                    prompt_tokens = None
                    logger.warning(
                        f"Failed to count prompt tokens (provider={llm_provider}, model={llm_model_name})"
                    )
                
                # DEBUG 레벨에서 실시간 분석용 최종 프롬프트 로깅
                logger.debug(f"Final realtime prompt for chunk {chunk_counter}:\n{prompt}")
                
                # Always print the final prompt for each realtime chunk
                print("\n[LLM Prompt Submitted]")
                print("-" * 50)
                print(prompt)
                print("-" * 50)
                # Print prompt token count right after the prompt output
                if prompt_tokens is not None:
                    print(f"✅ Prompt tokens (approx.): {prompt_tokens} (model: {llm_model_name})")
                
                # Process chunk using common function
                success, parsed_data = process_log_chunk(
                    model=model,
                    prompt=prompt,
                    model_class=analysis_schema_class,
                    chunk_start_time=chunk_start_time,
                    chunk_end_time=None,
                    elasticsearch_index=log_type,
                    chunk_number=chunk_counter,
                    chunk_data=chunk_lines,  # Pass original chunk data
                    llm_provider=llm_provider,
                    llm_model=llm_model_name,
                    processing_mode="realtime",
                    log_path=config["log_path"],
                    access_mode=config["access_mode"],
                    token_size_input=prompt_tokens,
                )
                
                if success:
                    logger.info(f"Real-time chunk {chunk_counter} analyzed successfully")
                    print("✅ Real-time analysis completed successfully")
                    
                    # Mark chunk as processed (this updates the position)
                    monitor.mark_chunk_processed(chunk_lines)
                    
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
                            logger.warning(f"HIGH/CRITICAL events found in chunk {chunk_counter}: {len(high_severity_events)}")
                            print(f"⚠️  WARNING: HIGH/CRITICAL events: {len(high_severity_events)}")
                            for event in high_severity_events:
                                print(f"   {event.get('event_type', 'UNKNOWN')}: {event.get('description', 'No description')}")
                else:
                    logger.error(f"Real-time chunk {chunk_counter} analysis failed")
                    print("❌ Real-time analysis failed")
                    wait_on_failure(30)  # Wait 30 seconds on failure
                
                print("-" * 50)
            
            # Sleep for polling interval
            time.sleep(config["realtime_config"]["polling_interval"])            
    except KeyboardInterrupt:
        logger.info("Real-time monitoring stopped by user (Ctrl+C)")
        print("\n\n🛑 Real-time monitoring stopped by user")
        # Save current position (pending lines will be reprocessed on restart)
        if 'monitor' in locals():
            monitor.save_state_on_exit()
        print("Position saved. You can resume monitoring from where you left off.")
    except FileNotFoundError:
        logger.error(f"Log file not found during real-time monitoring: {config['log_path']}")
        print(f"ERROR: Log file not found: {config['log_path']}")
        print("NOTE: Make sure the log file exists and is readable")
    except PermissionError:
        logger.error(f"Permission denied during real-time monitoring: {config['log_path']}")
        print(f"ERROR: Permission denied: {config['log_path']}")
        print("NOTE: You may need to run with sudo or adjust file permissions")
    except Exception as e:
        logger.error(f"Unexpected error during real-time monitoring: {e}")
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
    
    # Log file path with wildcard support
    parser.add_argument('--log-path', type=str, default=None,
                       help='Log file path or pattern (supports wildcards: /var/log/*.log, /path/to/apache*.log, etc.)')
    
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
    parser.add_argument('--only-sampling-mode', action='store_true',
                       help='Force sampling mode (always keep latest chunks only, no auto-switching)')
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
        logger.debug("Remote mode not enabled, skipping SSH config parsing")
        return None
    
    logger.debug("Parsing SSH configuration from arguments")
    ssh_config = {}
    
    # Parse SSH connection string (user@host[:port])
    if hasattr(args, 'ssh') and args.ssh:
        logger.debug(f"Parsing SSH connection string: {args.ssh}")
        ssh_parts = args.ssh.split('@')
        if len(ssh_parts) != 2:
            logger.error(f"Invalid SSH format: {args.ssh}")
            raise ValueError("SSH format must be: user@host[:port]")
        
        user, host_port = ssh_parts
        ssh_config['user'] = user
        
        # Parse host and optional port
        if ':' in host_port:
            host, port = host_port.split(':', 1)
            ssh_config['host'] = host
            try:
                ssh_config['port'] = int(port)
                logger.debug(f"SSH port parsed: {port}")
            except ValueError:
                logger.error(f"Invalid SSH port: {port}")
                raise ValueError(f"Invalid SSH port: {port}")
        else:
            ssh_config['host'] = host_port
            ssh_config['port'] = 22  # Default port
            logger.debug("Using default SSH port 22")
    
    # Authentication method
    if hasattr(args, 'ssh_key') and args.ssh_key:
        ssh_config['key_path'] = args.ssh_key
        logger.info(f"SSH key authentication configured: {args.ssh_key}")
    
    if hasattr(args, 'ssh_password') and args.ssh_password:
        ssh_config['password'] = args.ssh_password
        logger.info("SSH password authentication configured")
    
    logger.info(f"SSH config parsed successfully: {ssh_config}")
    return ssh_config if ssh_config else None

def validate_args(args):
    """
    Validate command line arguments for consistency and requirements
    
    Args:
        args: Parsed command line arguments
    
    Raises:
        ValueError: If arguments are invalid or inconsistent
    """
    logger.debug("Validating command line arguments")
    
    # Remote mode validation
    if getattr(args, 'remote', False):
        logger.info("Remote mode enabled, validating SSH parameters")
        
        # SSH connection info is required
        if not getattr(args, 'ssh', None):
            logger.error("SSH connection info missing for remote mode")
            raise ValueError("--ssh user@host[:port] is required when using --remote")
        
        # At least one authentication method is required
        if not getattr(args, 'ssh_key', None) and not getattr(args, 'ssh_password', None):
            logger.error("No SSH authentication method provided")
            raise ValueError("Either --ssh-key or --ssh-password is required with --remote")
        
        # Validate SSH format
        ssh = getattr(args, 'ssh', '')
        if '@' not in ssh:
            logger.error(f"Invalid SSH format: {ssh}")
            raise ValueError("SSH format must be: user@host[:port]")
        
        logger.info("Remote mode arguments validated successfully")
    
    # Local mode validation - warn about unused SSH options
    else:
        logger.debug("Local mode enabled, checking for unused SSH options")
        ssh_options = ['ssh', 'ssh_key', 'ssh_password']
        for opt in ssh_options:
            if getattr(args, opt, None):
                logger.warning(f"SSH option --{opt.replace('_', '-')} ignored in local mode")
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
        logger.info("SSH not enabled (local mode)")
        return None

    # Validate arguments
    try:
        validate_args(args)
        logger.info("SSH arguments validated successfully.")
    except Exception as e:
        logger.error(f"SSH argument validation failed: {e}")
        raise

    # Parse SSH configuration
    try:
        ssh_config = parse_ssh_config_from_args(args)
        logger.info(f"Parsed SSH config: {ssh_config}")
    except Exception as e:
        logger.error(f"Failed to parse SSH config: {e}")
        raise
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
        logger.warning("No SSH config provided, cannot create SSH client.")
        return None

    logger.info(f"Creating SSH client for {ssh_config.get('user', 'unknown')}@{ssh_config.get('host', 'unknown')}:{ssh_config.get('port', 22)}")
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
        logger.warning(f"Attempted SSH file read for {log_path} (not implemented here)")
        raise NotImplementedError("SSH file reading moved to ssh.py module")
    else:
        # Read local file
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                logger.info(f"Successfully read local file: {log_path}")
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read local file {log_path}: {e}")
            print(f"✗ Failed to read local file {log_path}: {e}")
            raise


# ============================================================================
# STREAMING BATCH PROCESSING - Memory Safe & Logrotate Resistant
# ============================================================================

def _process_file_streaming_batch(log_path: str, chunk_size: int, model, analysis_schema_class,
                                prompt_template: str, response_language: str, log_type: str,
                                llm_provider: str, llm_model_name: str, config: dict) -> int:
    """
    Process local file using streaming approach - memory efficient and logrotate safe
    
    Args:
        log_path: Path to the log file
        chunk_size: Number of lines per chunk
        model: LLM model instance
        analysis_schema_class: Pydantic schema class
        prompt_template: Template for prompts
        response_language: Language for responses
        log_type: Type of log being processed
        llm_provider: LLM provider name
        llm_model_name: LLM model name
        config: Analysis configuration
    
    Returns:
        int: Number of chunks processed
    """
    if not os.path.exists(log_path):
        logger.error(f"Log file not found: {log_path}")
        raise FileNotFoundError(f"Log file not found: {log_path}")
    
    # Record initial file state for snapshot boundary and rotation detection
    initial_stat = os.stat(log_path)
    initial_inode = initial_stat.st_ino
    initial_size = initial_stat.st_size
    
    logger.info(f"📸 Starting streaming batch analysis")
    logger.info(f"   📄 File: {log_path}")
    logger.info(f"   📏 Size: {initial_size:,} bytes")
    logger.info(f"   🔢 Inode: {initial_inode}")
    logger.info(f"   🧩 Chunk size: {chunk_size} lines")
    logger.info(f"   ⚠️  Will detect logrotate/truncation during processing")
    
    # Check if file is actively growing (optional warning)
    _check_growing_file_warning(log_path, initial_size)
    
    chunk_buffer = []
    chunk_count = 0
    total_lines_processed = 0
    last_position = 0
    
    try:
        logger.info(f"Successfully opened log file for streaming: {log_path}")
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            
            line_number = 0
            while True:
                current_position = f.tell()
                line = f.readline()
                
                # End of file reached
                if not line:
                    break
                
                line_number += 1
                
                # Check for file rotation every 1000 lines
                if line_number % 1000 == 0:
                    if _check_file_rotation(log_path, initial_inode, current_position):
                        logger.warning(f"🔄 File rotation detected at line {line_number}")
                        logger.warning(f"📊 Processing up to current position: {current_position:,} bytes")
                        break
                
                # Check snapshot boundary
                if current_position > initial_size:
                    logger.info(f"🛑 Reached original snapshot boundary at line {line_number}")
                    logger.info(f"📊 Processed exactly {initial_size:,} bytes as planned")
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                chunk_buffer.append(line)
                last_position = current_position
                
                # Process chunk when buffer is full
                if len(chunk_buffer) >= chunk_size:
                    chunk_count += 1
                    progress_pct = (current_position / initial_size) * 100
                    logger.info(f"Processing chunk {chunk_count} (Progress: {progress_pct:.1f}%)")
                    
                    # Process the chunk
                    success = _process_single_chunk_streaming(
                        chunk_buffer=chunk_buffer,
                        chunk_number=chunk_count,
                        model=model,
                        analysis_schema_class=analysis_schema_class,
                        prompt_template=prompt_template,
                        response_language=response_language,
                        log_type=log_type,
                        llm_provider=llm_provider,
                        llm_model_name=llm_model_name,
                        config=config
                    )
                    
                    total_lines_processed += len(chunk_buffer)
                    chunk_buffer = []  # Clear buffer to free memory
                    
                    if not success:
                        logger.warning(f"Chunk {chunk_count} processing failed, continuing with next chunk")
                        wait_on_failure(30)
                
                # Progress logging
                if line_number % 5000 == 0:
                    progress_pct = (current_position / initial_size) * 100
                    logger.info(f"📖 Read {line_number:,} lines ({progress_pct:.1f}% of snapshot)")
            
            # Process final chunk if buffer has remaining lines
            if chunk_buffer:
                chunk_count += 1
                logger.info(f"Processing final chunk {chunk_count}")
                success = _process_single_chunk_streaming(
                    chunk_buffer=chunk_buffer,
                    chunk_number=chunk_count,
                    model=model,
                    analysis_schema_class=analysis_schema_class,
                    prompt_template=prompt_template,
                    response_language=response_language,
                    log_type=log_type,
                    llm_provider=llm_provider,
                    llm_model_name=llm_model_name,
                    config=config
                )
                total_lines_processed += len(chunk_buffer)
                
                if not success:
                    logger.warning(f"Final chunk {chunk_count} processing failed")
    
    except (IOError, OSError) as e:
        logger.error(f"💥 File I/O error during streaming processing: {e}")
        logger.warning(f"📊 Partial analysis completed: {total_lines_processed:,} lines processed")
        
        # Diagnose file state
        final_check = _diagnose_file_state(log_path, initial_inode)
        logger.info(f"🔍 File state diagnosis: {final_check}")
        
        if chunk_count > 0:
            logger.info("✅ Returning partial streaming analysis results")
        else:
            logger.error("❌ No streaming analysis chunks completed")
            
    except Exception as e:
        logger.error(f"💥 Unexpected error during streaming file processing: {e}")
        logger.debug("Full traceback:", exc_info=True)
        raise
    
    # Generate final processing report
    final_state = _get_final_processing_report(log_path, initial_inode, initial_size, 
                                             total_lines_processed, chunk_count)
    logger.info(final_state)
    
    return chunk_count

def _check_growing_file_warning(file_path: str, initial_size: int):
    """Check if file is actively growing and warn user"""
    try:
        import time
        time.sleep(1)  # Wait 1 second
        current_size = os.path.getsize(file_path)
        
        if current_size > initial_size:
            growth_bytes = current_size - initial_size
            logger.warning(f"⚠️  File is actively growing: +{growth_bytes:,} bytes in 1 second")
            logger.warning(f"📝 Batch mode processes snapshot only (up to {initial_size:,} bytes)")
            logger.warning(f"🔄 Consider using --mode realtime for continuously growing files")
            print(f"⚠️  WARNING: File is actively growing (+{growth_bytes:,} bytes/sec)")
            print(f"📝 Batch mode will process snapshot only (up to {initial_size:,} bytes)")
            print(f"🔄 Consider using --mode realtime for live monitoring")
    except Exception as e:
        logger.debug(f"Could not check file growth: {e}")

def _check_file_rotation(file_path: str, original_inode: int, current_position: int) -> bool:
    """Detect file rotation/truncation"""
    try:
        if not os.path.exists(file_path):
            logger.warning(f"📁 File disappeared: {file_path}")
            return True
        
        current_stat = os.stat(file_path)
        current_inode = current_stat.st_ino
        current_size = current_stat.st_size
        
        # Inode changed = file was moved/deleted and new file created
        if current_inode != original_inode:
            logger.warning(f"🔄 Inode changed: {original_inode} → {current_inode} (file rotated)")
            return True
        
        # File size is smaller than current read position = truncated
        if current_size < current_position:
            logger.warning(f"✂️  File truncated: size {current_size} < position {current_position}")
            return True
        
        return False
        
    except (OSError, IOError) as e:
        logger.warning(f"⚠️  Cannot check file rotation: {e}")
        return True  # Assume rotation for safety

def _diagnose_file_state(file_path: str, original_inode: int) -> str:
    """Diagnose current file state"""
    try:
        if not os.path.exists(file_path):
            return f"File not found (likely rotated/deleted)"
        
        current_stat = os.stat(file_path)
        current_inode = current_stat.st_ino
        current_size = current_stat.st_size
        
        if current_inode != original_inode:
            return f"Inode changed ({original_inode} → {current_inode}) - file was rotated"
        else:
            return f"Same file (inode {current_inode}), current size: {current_size:,} bytes"
            
    except Exception as e:
        return f"Cannot diagnose: {e}"

def _process_single_chunk_streaming(chunk_buffer: List[str], chunk_number: int, model, 
                                  analysis_schema_class, prompt_template: str, response_language: str,
                                  log_type: str, llm_provider: str, llm_model_name: str, config: dict) -> bool:
    """Process a single chunk using streaming approach with retry logic"""
    max_retries = 2
    
    for attempt in range(max_retries + 1):
        try:
            # Record analysis start time
            chunk_start_time = datetime.datetime.utcnow().isoformat(timespec='seconds') + 'Z'
            
            # Prepare chunk data as string (same format as original)
            logs = "\n".join(chunk_buffer).rstrip("\n")
            model_schema = analysis_schema_class.model_json_schema()
            prompt = prompt_template.format(logs=logs, model_schema=model_schema, response_language=response_language)
            prompt = prompt.strip()

            # Token count for prompt
            try:
                prompt_tokens = count_tokens(prompt, llm_model_name)
                logger.info(f"Prompt tokens (approx.): {prompt_tokens} (provider={llm_provider}, model={llm_model_name})")
            except Exception:
                prompt_tokens = None
                logger.warning(f"Failed to count prompt tokens (provider={llm_provider}, model={llm_model_name})")
            
            # Debug logging
            logger.debug(f"Final prompt for streaming chunk {chunk_number}:\n{prompt}")
            
            # Print prompt and chunk info (same format as original)
            print("\n[LLM Prompt Submitted]")
            print("-" * 50)
            print(prompt)
            print("-" * 50)
            if prompt_tokens is not None:
                print(f"✅ Prompt tokens (approx.): {prompt_tokens} (model: {llm_model_name})")
            print(f"\n--- Chunk {chunk_number} ---")
            print_chunk_contents(chunk_buffer)  # chunk_buffer is already a list of strings
            
            # Process chunk using common function
            success, parsed_data = process_log_chunk(
                model=model,
                prompt=prompt,
                model_class=analysis_schema_class,
                chunk_start_time=chunk_start_time,
                chunk_end_time=None,  # Will be calculated in function
                elasticsearch_index=log_type,
                chunk_number=chunk_number,
                chunk_data=chunk_buffer,
                llm_provider=llm_provider,
                llm_model=llm_model_name,
                processing_mode="batch",
                log_path=config.get("log_path", "unknown"),
                access_mode=config.get("access_mode", "local"),
                token_size_input=prompt_tokens,
            )
            
            if success:
                print("✅ Analysis completed successfully")
                return True
            else:
                print("❌ Analysis failed")
                if attempt < max_retries:
                    logger.warning(f"⚠️  Chunk {chunk_number} analysis failed (attempt {attempt + 1}/{max_retries + 1})")
                    import time
                    time.sleep(1)  # Short wait before retry
                    continue
                else:
                    logger.error(f"💥 Chunk {chunk_number} analysis failed after {max_retries + 1} attempts")
                    return False
                    
        except Exception as e:
            if attempt < max_retries:
                logger.warning(f"⚠️  Chunk {chunk_number} processing error (attempt {attempt + 1}/{max_retries + 1}): {e}")
                import time
                time.sleep(1)
                continue
            else:
                logger.error(f"💥 Chunk {chunk_number} processing failed after {max_retries + 1} attempts: {e}")
                logger.debug(f"Failed chunk preview: {chunk_buffer[:2] if chunk_buffer else 'empty'}")
                return False
    
    print("-" * 50)
    return False

def _get_final_processing_report(file_path: str, original_inode: int, original_size: int, 
                               lines_processed: int, chunks_analyzed: int) -> str:
    """Generate final processing report"""
    try:
        if os.path.exists(file_path):
            final_stat = os.stat(file_path)
            final_inode = final_stat.st_ino
            final_size = final_stat.st_size
            
            if final_inode != original_inode:
                status = f"🔄 File was rotated during processing"
            elif final_size != original_size:
                size_change = final_size - original_size
                status = f"📈 File grew by {size_change:,} bytes during processing"
            else:
                status = f"📊 File remained stable during processing"
        else:
            status = f"📁 File no longer exists (rotated/deleted)"
        
        return (f"✅ Streaming batch analysis completed:\n"
               f"   📄 Lines processed: {lines_processed:,}\n" 
               f"   🧩 Chunks analyzed: {chunks_analyzed}\n"
               f"   📏 Original size: {original_size:,} bytes\n"
               f"   {status}")
               
    except Exception as e:
        return f"⚠️  Cannot generate final report: {e}"
