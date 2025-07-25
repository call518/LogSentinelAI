"""LogSentinelAI - AI-Powered Log Analyzer

LogSentinelAI is a system that leverages LLM (Large Language Model) to analyze 
various log files and detect security events. It automatically analyzes Apache HTTP logs, 
Linux system logs, and other log types to identify security threats and stores them 
as structured data in Elasticsearch for visualization and analysis.
"""

__version__ = "0.1.0"
__author__ = "JungJungIn"
__email__ = "call518@gmail.com"

# Import main functionality
from .core.commons import (
    initialize_llm_model,
    get_analysis_config,
    process_log_chunk,
    run_generic_batch_analysis,
    run_generic_realtime_analysis
)

from .utils.geoip_downloader import download_geoip_database

__all__ = [
    'initialize_llm_model',
    'get_analysis_config', 
    'process_log_chunk',
    'run_generic_batch_analysis',
    'run_generic_realtime_analysis',
    'download_geoip_database'
]
