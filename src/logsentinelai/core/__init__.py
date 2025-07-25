"""LogSentinelAI Core Package

This package contains core functionality shared across all analyzers:
- commons: Common utilities, LLM initialization, and processing functions
- prompts: LLM prompt templates for different log types
"""

from .commons import (
    initialize_llm_model,
    get_analysis_config,
    process_log_chunk,
    run_generic_batch_analysis,
    run_generic_realtime_analysis,
    create_argument_parser,
    handle_ssh_arguments
)

__all__ = [
    'initialize_llm_model',
    'get_analysis_config',
    'process_log_chunk', 
    'run_generic_batch_analysis',
    'run_generic_realtime_analysis',
    'create_argument_parser',
    'handle_ssh_arguments'
]
