#!/usr/bin/env python3
"""
Test the updated timeout feature with seconds
"""
import os
import time
import sys

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_updated_timeout():
    """Test the updated timeout feature"""
    
    # Create a temp log file
    log_path = "/tmp/test-pending-timeout.log"
    with open(log_path, 'w') as f:
        f.write("Initial log line\n")
    
    try:
        # Set environment variables for testing (30 second timeout)
        os.environ['REALTIME_CHUNK_PENDING_TIMEOUT'] = '30'
        os.environ['LOG_PATH_GENERAL_LOG'] = log_path
        
        from logsentinelai.core.config import apply_config
        from logsentinelai.core.monitoring import create_realtime_monitor
        
        # Apply configuration
        apply_config('./config')
        
        # Create monitor
        monitor = create_realtime_monitor(
            log_type="general_log",
            chunk_size=5,
            remote_mode="local"
        )
        
        print(f"✅ Monitor created successfully!")
        print(f"   Chunk size: {monitor.chunk_size}")
        print(f"   Pending timeout: {monitor.chunk_pending_timeout} seconds")
        
        # Append test lines
        with open(log_path, 'a') as f:
            f.write("Test line 1\n")
            f.write("Test line 2\n")
            f.write("Test line 3\n")  # Only 3 lines, less than chunk_size=5
            f.flush()
        
        print(f"✅ Added 3 test lines to {log_path}")
        print(f"🕐 Waiting for 30-second timeout...")
        
        # Test the timeout
        start_time = time.time()
        chunk_received = False
        
        while time.time() - start_time < 40:  # Wait up to 40 seconds
            for chunk in monitor.get_new_log_chunks():
                chunk_received = True
                print(f"✅ SUCCESS! Received timeout chunk with {len(chunk)} lines:")
                for line in chunk:
                    print(f"   - {line}")
                break
            
            if chunk_received:
                break
                
            time.sleep(5)
        
        if chunk_received:
            print(f"🎉 SUCCESS: Pending timeout feature works correctly!")
        else:
            print(f"❌ FAILED: No chunk received within test period")
            
    finally:
        # Clean up
        try:
            os.unlink(log_path)
            print(f"🧹 Cleaned up {log_path}")
        except:
            pass

if __name__ == "__main__":
    test_updated_timeout()
