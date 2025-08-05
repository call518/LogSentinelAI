"""
Utility functions for log processing and data manipulation
"""
from typing import List, Generator

def chunked_iterable(iterable, size, debug=False):
    """
    Split an iterable into chunks of specified size
    
    Args:
        iterable: Input iterable to chunk
        size: Size of each chunk
        debug: Enable debug output
    
    Yields:
        List of original log lines
    """
    chunk = []
    for item in iterable:
        log_content = item.rstrip()
        chunk.append(f"{log_content}\n")
        
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
    Print chunk contents in a readable format
    
    Args:
        chunk: List of log lines
    """
    print(f"\n[LOG DATA]")
    for idx, line in enumerate(chunk, 1):
        line = line.strip()
        
        # Handle multiline data
        if "\\n" in line:
            multiline_content = line.replace('\\n', '\n')
            print(f"{idx:2d}: {multiline_content}")
        else:
            print(f"{idx:2d}: {line}")
    print("")


