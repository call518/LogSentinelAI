"""LogSentinelAI Core Package

This package contains core functionality shared across all analyzers:
- config: Configuration management and environment variables
- llm: LLM model initialization and interaction
- elasticsearch: Elasticsearch integration
- geoip: GeoIP lookup and enrichment
- ssh: SSH remote access functionality
- monitoring: Real-time log monitoring
- utils: Utility functions for log processing
- commons: Main analysis functions and interfaces
- prompts: LLM prompt templates for different log types
"""

# Import main interfaces from commons
from .commons import (
    process_log_chunk,
    run_generic_batch_analysis,
    run_generic_realtime_analysis,
    create_argument_parser,
    parse_ssh_config_from_args,
    validate_args,
    send_to_elasticsearch,
    handle_ssh_arguments
)

# Import configuration
from .config import get_analysis_config

# Import LLM functionality
from .llm import initialize_llm_model, wait_on_failure

# Import utilities
from ..utils.general import chunked_iterable, print_chunk_contents

# Import monitoring
from .monitoring import create_realtime_monitor

# Import GeoIP
from .geoip import enrich_source_ips_with_geoip

__all__ = [
    # Main analysis functions
    'process_log_chunk',
    'run_generic_batch_analysis', 
    'run_generic_realtime_analysis',
    
    # Configuration
    'get_analysis_config',
    
    # LLM functionality
    'initialize_llm_model',
    'wait_on_failure',
    
    # Utilities
    'chunked_iterable',
    'print_chunk_contents',
    
    # Monitoring
    'create_realtime_monitor',
    
    # GeoIP
    'enrich_source_ips_with_geoip',
    
    # Elasticsearch
    'send_to_elasticsearch',
    
    # Argument parsing and SSH
    'create_argument_parser',
    'parse_ssh_config_from_args',
    'validate_args',
    'handle_ssh_arguments'
]
