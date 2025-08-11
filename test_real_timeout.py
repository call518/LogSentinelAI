#!/usr/bin/env python3
"""
Real-world test for the timeout feature
"""
import os
import time
import sys

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from logsentinelai.core.config import apply_config
from logsentinelai.core.monitoring import create_realtime_monitor

def test_real_timeout():
    """Test timeout with a real log file"""
    
    log_path = "/tmp/test-realtime.log"
    
    # Apply configuration
    apply_config('./config')
    
    # Create monitor for general log type
    monitor = create_realtime_monitor(
        log_type="general_log",
        chunk_size=5,
        remote_mode="local"
    )
    
    print(f"Monitor created with chunk size: {monitor.chunk_size}")
    print(f"Chunk timeout: {monitor.chunk_timeout} minutes")
    print(f"Monitoring file: {log_path}")
    
    # Append some test lines to trigger monitoring
    with open(log_path, 'a') as f:
        f.write("Test line 1 - " + str(time.time()) + "\n")
        f.write("Test line 2 - " + str(time.time()) + "\n") 
        f.write("Test line 3 - " + str(time.time()) + "\n")  # Only 3 lines, less than chunk_size=5
        f.flush()
    
    print("Added 3 new test lines to log file")
    print("Waiting for timeout to trigger (30 seconds)...")
    
    # Test the chunk generator
    chunk_count = 0
    start_time = time.time()
    timeout_seconds = 40  # 40 seconds
    
    while time.time() - start_time < timeout_seconds:
        print(f"Checking for chunks... (elapsed: {int(time.time() - start_time)}s)")
        
        for chunk in monitor.get_new_log_chunks():
            chunk_count += 1
            print(f"SUCCESS! Received chunk #{chunk_count} with {len(chunk)} lines:")
            for line in chunk:
                print(f"  - {line}")
            break  # Process one chunk at a time
        
        if chunk_count > 0:
            break
            
        time.sleep(5)  # Wait 5 seconds before next check
    
    if chunk_count > 0:
        print(f"SUCCESS: Timeout feature worked! Received {chunk_count} chunk(s)")
    else:
        print("TIMEOUT: No chunks received within test timeout period")

if __name__ == "__main__":
    test_real_timeout()
