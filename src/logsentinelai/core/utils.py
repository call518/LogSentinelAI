"""
Utility functions for log processing and data manipulation
"""
import hashlib
from typing import List, Generator, Dict

def chunked_iterable(iterable, size, debug=False):
    """
    Split an iterable into chunks of specified size with LOGID generation
    
    Args:
        iterable: Input iterable to chunk
        size: Size of each chunk
        debug: Enable debug output
    
    Yields:
        List of lines with LOGID prefixes
    """
    chunk = []
    for item in iterable:
        log_content = item.rstrip()
        
        # Create LOGID for the line
        if log_content.startswith("LOGID-"):
            new_item = f"{log_content}\n"
        else:
            # Generate new LOGID for regular log lines
            hash_object = hashlib.md5(log_content.encode('utf-8'))
            hash_hex = hash_object.hexdigest()
            logid = f"LOGID-{hash_hex.upper()}"
            new_item = f"{logid} {log_content}\n"
        
        chunk.append(new_item)
        
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
    """
    Print chunk contents in a readable format (removes LOGID for display)
    
    Args:
        chunk: List of log lines with LOGID prefixes
    """
    print(f"\n[LOG DATA]")
    for idx, line in enumerate(chunk, 1):
        line = line.strip()
        
        # Extract original content by removing LOGID prefix
        if line.startswith("LOGID-"):
            parts = line.split(" ", 1)
            original_content = parts[1] if len(parts) > 1 else ""
        else:
            original_content = line
        
        # Handle multiline data
        if "\\n" in original_content:
            multiline_content = original_content.replace('\\n', '\n')
            print(f"{idx:2d}: {multiline_content}")
        else:
            print(f"{idx:2d}: {original_content}")
    print("")

def create_log_hash_mapping_realtime(chunk: List[str]) -> Dict[str, str]:
    """
    Create LOGID -> original log content mapping for real-time chunks.
    Real-time chunks contain raw log lines without LOGID prefixes.
    
    Args:
        chunk: List of raw log lines
    
    Returns:
        Dict[str, str]: {logid: original_content} mapping
    """
    mapping = {}
    for line in chunk:
        if line.strip():  # Skip empty lines
            # Generate LOGID for raw log line
            logid = f"LOGID-{hashlib.md5(line.strip().encode()).hexdigest().upper()}"
            mapping[logid] = line.strip()
    return mapping
