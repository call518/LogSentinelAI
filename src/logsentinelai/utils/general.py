"""
Utility functions for log processing and data manipulation
"""
from typing import List, Generator
import socket
import subprocess
import re

# Cache host metadata at module load time for performance
_HOST_METADATA_CACHE = None

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


def _get_hostname_fqdn() -> str:
    """
    Get the fully qualified domain name (FQDN) of the current host.
    
    Returns:
        str: FQDN of the host
    """
    try:
        return socket.getfqdn()
    except Exception:
        return socket.gethostname()


def _get_host_ip_addresses() -> List[str]:
    """
    Get all IP addresses of the current host with their network masks.
    
    Returns:
        List[str]: List of IP addresses with CIDR notation (e.g., ["192.168.1.10/24"])
    """
    ip_addresses = []
    
    try:
        # Use 'ip addr show' command to get detailed network information
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            # Parse the output to extract IP addresses with CIDR notation
            lines = result.stdout.split('\n')
            for line in lines:
                # Look for inet lines (IPv4) - exclude loopback
                inet_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', line)
                if inet_match:
                    ip_cidr = inet_match.group(1)
                    # Exclude loopback address
                    if not ip_cidr.startswith('127.'):
                        ip_addresses.append(ip_cidr)
        else:
            # Fallback: try using socket to get primary IP
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip and not ip.startswith('127.'):
                ip_addresses.append(f"{ip}/32")  # Default to /32 if we can't determine subnet
                
    except Exception:
        # Final fallback: try to get at least one IP
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip and not ip.startswith('127.'):
                ip_addresses.append(f"{ip}/32")
        except Exception:
            pass
    
    return ip_addresses


def _initialize_host_metadata() -> dict:
    """
    Initialize host metadata cache with hostname and IP addresses.
    This is called once when the module is loaded.
    
    Returns:
        dict: Dictionary containing @host with nested hostname and ip_addresses
    """
    return {
        "@host": {
            "hostname": _get_hostname_fqdn(),
            "ip_addresses": _get_host_ip_addresses()
        }
    }


def get_host_metadata() -> dict:
    """
    Get cached host metadata including hostname (FQDN) and IP addresses.
    Host information is cached at module load time for performance.
    
    Returns:
        dict: Dictionary containing @host with nested hostname and ip_addresses
    """
    global _HOST_METADATA_CACHE
    if _HOST_METADATA_CACHE is None:
        _HOST_METADATA_CACHE = _initialize_host_metadata()
    return _HOST_METADATA_CACHE


# Initialize host metadata cache when module is imported
_HOST_METADATA_CACHE = _initialize_host_metadata()


