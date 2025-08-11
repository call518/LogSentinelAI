#!/usr/bin/env python3
"""
Test script for the new chunk timeout feature
"""
import os
import time
import sys
import tempfile

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from logsentinelai.core.config import apply_config
from logsentinelai.core.monitoring import create_realtime_monitor

def test_timeout_feature():
    """Test the new timeout feature with a temporary log file"""
    
    # Create a temporary log file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        temp_log_path = f.name
        # Write some initial log lines
        f.write("Initial log line 1\n")
        f.write("Initial log line 2\n")
        f.flush()
    
    print(f"Created temporary log file: {temp_log_path}")
    
    try:
        # Set environment variables for testing before applying config
        os.environ['REALTIME_CHUNK_TIMEOUT'] = '1'  # 1 minute timeout for testing
        os.environ['LOG_PATH_GENERAL_LOG'] = temp_log_path
        
        # Apply configuration (this will pick up the new REALTIME_CHUNK_TIMEOUT setting)
        apply_config('./config')
        
    try:
        # Set environment variables for testing before applying config
        os.environ['REALTIME_CHUNK_TIMEOUT'] = '0.5'  # 0.5 minutes (30 seconds) timeout for testing
        os.environ['LOG_PATH_GENERAL_LOG'] = temp_log_path
        
        # Apply configuration (this will pick up the new REALTIME_CHUNK_TIMEOUT setting)
        apply_config('./config')
        
        # Create monitor for general log type
        monitor = create_realtime_monitor(
            log_type="general_log",
            chunk_size=5,  # Small chunk size so we can test timeout
            remote_mode="local"
        )
        
        print(f"Monitor created with chunk size: {monitor.chunk_size}")
        print(f"Chunk timeout: {monitor.chunk_timeout} minutes")
        print("Starting monitoring test...")
        
        # Append some lines to test file
        with open(temp_log_path, 'a') as f:
            f.write("New log line 1\n")
            f.write("New log line 2\n")
            f.write("New log line 3\n")  # Only 3 lines, less than chunk_size=5
            f.flush()
        
        print("Added 3 new lines to log file")
        print("Waiting for timeout to trigger (30 seconds)...")
        
        # Test the chunk generator
        chunk_count = 0
        start_time = time.time()
        timeout_seconds = 40  # 40 seconds = slightly more than 30 seconds timeout
        
        while time.time() - start_time < timeout_seconds:
            for chunk in monitor.get_new_log_chunks():
                chunk_count += 1
                print(f"Received chunk #{chunk_count} with {len(chunk)} lines:")
                for line in chunk:
                    print(f"  - {line}")
                break  # Process one chunk at a time
            
            if chunk_count > 0:
                break
                
            time.sleep(2)  # Wait a bit before next check
        
        if chunk_count > 0:
            print(f"SUCCESS: Timeout feature worked! Received {chunk_count} chunk(s)")
        else:
            print("TIMEOUT: No chunks received within test timeout period")
            
    finally:
        # Clean up temp file
        try:
            os.unlink(temp_log_path)
            print(f"Cleaned up temporary log file: {temp_log_path}")
        except:
            pass

if __name__ == "__main__":
    test_timeout_feature()
