"""
Real-time log monitoring module
Handles continuous monitoring and processing of log files
"""
import os
from typing import Dict, Any, List, Generator
from .config import get_analysis_config
from .ssh import RemoteSSHLogMonitor

class RealtimeLogMonitor:
    """Real-time log file monitoring and analysis"""
    
    def __init__(self, log_type: str, config: Dict[str, Any]):
        """
        Initialize real-time log monitor
        
        Args:
            log_type: Type of log to monitor
            config: Configuration dictionary from get_analysis_config()
        """
        self.log_type = log_type
        self.log_path = config["log_path"]
        self.chunk_size = config["chunk_size"]
        self.response_language = config["response_language"]
        self.realtime_config = config["realtime_config"]
        
        # Access mode and SSH configuration
        self.access_mode = config["access_mode"]
        self.ssh_config = config["ssh_config"]
        self.ssh_monitor = None
        
        # Sampling configuration
        self.processing_mode = self.realtime_config["processing_mode"]
        self.sampling_threshold = self.realtime_config["sampling_threshold"]
        
        # Position tracking
        self.position_file_dir = self.realtime_config["position_file_dir"]
        self.position_file = os.path.join(
            self.position_file_dir, 
            f"{log_type}_position.txt"
        )
        
        # Create position file directory
        os.makedirs(self.position_file_dir, exist_ok=True)
        
        # Buffer management
        self.line_buffer = []
        self.pending_lines = []
        
        # File tracking for rotation detection
        self.last_position = 0
        self.last_inode = None
        self.last_size = 0
        
        # Initialize SSH monitor if needed
        if self.access_mode == "ssh":
            self._initialize_ssh_monitor()
        
        # Load position and file info
        self._load_position_and_file_info()
        
        # Display initialization info
        self._print_initialization_info()
    
    def _initialize_ssh_monitor(self):
        """SSH 원격 모니터 초기화"""
        try:
            if not self.log_path:
                raise ValueError(f"No remote log path configured for {self.log_type}")
            
            self.ssh_monitor = RemoteSSHLogMonitor(self.ssh_config, self.log_path)
            
            print("🔗 Testing SSH connection...")
            if self.ssh_monitor.test_connection():
                print("✅ SSH connection successful")
            else:
                raise ConnectionError("SSH connection test failed")
                
        except Exception as e:
            print(f"❌ SSH initialization failed: {e}")
            print("💡 Please check your SSH configuration")
            raise
    
    def _print_initialization_info(self):
        """Display initialization information"""
        print("=" * 80)
        print(f"REALTIME LOG MONITOR INITIALIZED")
        print("=" * 80)
        print(f"Log Type:         {self.log_type}")
        print(f"Access Mode:      {self.access_mode.upper()}")
        print(f"Monitoring:       {self.log_path}")
        print(f"Mode:             {self.processing_mode.upper()}")
        if self.processing_mode == "full":
            unit = 'lines'
            print(f"Auto-sampling:    {self.sampling_threshold} {unit} threshold")
        elif self.processing_mode == "sampling":
            unit = 'lines'
            print(f"Sampling:         Always keep latest {self.chunk_size} {unit}")
        print(f"Poll Interval:    {self.realtime_config['polling_interval']}s")
        unit = 'lines'
        print(f"Chunk Size:       {self.chunk_size} {unit}")
        print("=" * 80)
    
    def _load_position_and_file_info(self):
        """Load last read position and file info from position file"""
        try:
            if os.path.exists(self.position_file):
                with open(self.position_file, 'r') as f:
                    content = f.read().strip()
                    parts = content.split(':')
                    if len(parts) >= 1:
                        self.last_position = int(parts[0])
                    if len(parts) >= 2:
                        self.last_inode = int(parts[1]) if parts[1] != 'None' else None
                    if len(parts) >= 3:
                        self.last_size = int(parts[2])
                    
                    print(f"Loaded state: position={self.last_position}, inode={self.last_inode}, size={self.last_size}")
                    
                    # Verify current file matches saved state
                    self._verify_file_state()
                    return
        except (ValueError, IOError) as e:
            print(f"WARNING: Error loading position file: {e}")
        
        # Initialize from file end if no position file exists
        self._initialize_from_file_end()
    
    def _verify_file_state(self):
        """Verify current file state matches saved state"""
        if self.access_mode == "ssh":
            if self.ssh_monitor:
                current_size = self.ssh_monitor.get_file_size()
                current_inode = self.ssh_monitor.get_file_inode()
                
                if self.last_inode and current_inode and current_inode != self.last_inode:
                    print(f"NOTICE: Remote log rotation detected")
                    self._reset_position()
                elif current_size < self.last_position:
                    print(f"NOTICE: Remote file truncated")
                    self._reset_position()
                
                if current_inode:
                    self.last_inode = current_inode
                self.last_size = current_size
                self._save_position_and_file_info()
        else:
            if os.path.exists(self.log_path):
                current_stat = os.stat(self.log_path)
                current_inode = current_stat.st_ino
                current_size = current_stat.st_size
                
                if self.last_inode and current_inode != self.last_inode:
                    print(f"NOTICE: Local log rotation detected")
                    self._reset_position()
                elif current_size < self.last_position:
                    print(f"NOTICE: Local file truncated")
                    self._reset_position()
    
    def _reset_position(self):
        """Reset position to beginning of file"""
        self.last_position = 0
        self.line_buffer = []
        self._save_position_and_file_info()
    
    def _initialize_from_file_end(self):
        """Initialize position from file end for first-time setup"""
        try:
            if self.access_mode == "ssh":
                if self.ssh_monitor:
                    current_size = self.ssh_monitor.get_file_size()
                    current_inode = self.ssh_monitor.get_file_inode()
                    
                    # Start from recent position for initial run
                    if current_size > 10000:  # 10KB+
                        self.last_position = max(0, current_size - 5000)
                        print(f"📍 Starting from recent position in remote file: position={self.last_position}")
                    else:
                        self.last_position = 0
                        print(f"📍 Starting from beginning of remote file")
                    
                    self.last_inode = current_inode
                    self.last_size = current_size
                    self._save_position_and_file_info()
            else:
                if os.path.exists(self.log_path):
                    file_stat = os.stat(self.log_path)
                    current_size = file_stat.st_size
                    
                    if current_size > 10000:  # 10KB+
                        self.last_position = max(0, current_size - 5000)
                        print(f"📍 Starting from recent position in file: position={self.last_position}")
                    else:
                        self.last_position = 0
                        print(f"📍 Starting from beginning of file")
                    
                    self.last_inode = file_stat.st_ino
                    self.last_size = current_size
                    self._save_position_and_file_info()
                else:
                    print(f"WARNING: Local log file does not exist: {self.log_path}")
                    self.last_position = 0
                    self.last_inode = None
                    self.last_size = 0
        except Exception as e:
            print(f"WARNING: Error accessing log file: {e}")
            self.last_position = 0
            self.last_inode = None
            self.last_size = 0
    
    def _save_position_and_file_info(self):
        """Save current read position and file info to position file"""
        try:
            with open(self.position_file, 'w') as f:
                f.write(f"{self.last_position}:{self.last_inode}:{self.last_size}")
        except IOError as e:
            print(f"WARNING: Error saving position: {e}")
    
    def _read_new_lines(self) -> List[str]:
        """Read new lines from log file since last position"""
        if self.access_mode == "ssh":
            return self._read_remote_new_lines()
        else:
            return self._read_local_new_lines()
    
    def _read_local_new_lines(self) -> List[str]:
        """Read new lines from local log file"""
        try:
            if not os.path.exists(self.log_path):
                print(f"WARNING: Log file does not exist: {self.log_path}")
                return []
            
            # Get current file stats
            file_stat = os.stat(self.log_path)
            current_size = file_stat.st_size
            current_inode = file_stat.st_ino
            
            # Handle file rotation or truncation
            if self.last_inode and current_inode != self.last_inode:
                print(f"NOTICE: Log rotation detected")
                self._reset_position()
                self.last_inode = current_inode
                self.last_size = current_size
            elif current_size < self.last_position:
                print(f"NOTICE: File truncated")
                self._reset_position()
                self.last_size = current_size
            
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.last_position)
                new_content = f.read()
                new_position = f.tell()
                
                if not new_content:
                    return []
                
                # Split into lines and handle incomplete lines
                lines = new_content.split('\n')
                
                if new_content.endswith('\n'):
                    complete_lines = lines[:-1]  # Remove empty last element
                    self.line_buffer = []
                else:
                    complete_lines = lines[:-1]  # All but last incomplete line
                    self.line_buffer = [lines[-1]]  # Save incomplete line
                
                # Prepend buffered content to first line
                if self.line_buffer and complete_lines:
                    complete_lines[0] = self.line_buffer[0] + complete_lines[0]
                    self.line_buffer = []
                
                # Update position
                if complete_lines:
                    self.last_position = new_position - len(self.line_buffer[0].encode('utf-8')) if self.line_buffer else new_position
                
                # Filter out empty lines
                complete_lines = [line.strip() for line in complete_lines if line.strip()]
                return complete_lines
                
        except IOError as e:
            print(f"WARNING: Error reading local log file: {e}")
            return []
    
    def _read_remote_new_lines(self) -> List[str]:
        """Read new lines from remote log file via SSH"""
        try:
            if not self.ssh_monitor:
                print(f"WARNING: SSH monitor not initialized")
                return []
            
            current_size = self.ssh_monitor.get_file_size()
            current_inode = self.ssh_monitor.get_file_inode()
            
            # Handle file rotation or truncation
            if self.last_inode and current_inode and current_inode != self.last_inode:
                print(f"NOTICE: Remote log rotation detected")
                self._reset_position()
                self.last_inode = current_inode
                self.last_size = current_size
            elif current_size < self.last_position:
                print(f"NOTICE: Remote file truncated")
                self._reset_position()
                self.last_size = current_size
            
            # No new content
            if current_size <= self.last_position:
                return []
            
            # Read new lines from remote file
            new_lines = self.ssh_monitor.read_from_position(self.last_position)
            
            if new_lines:
                # Update position (rough estimate)
                self.last_position = current_size
                self.last_size = current_size
                self._save_position_and_file_info()
            
            return new_lines
            
        except Exception as e:
            print(f"WARNING: Error reading remote log file: {e}")
            return []
    
    def get_new_log_chunks(self) -> Generator[List[str], None, None]:
        """
        Generator that yields chunks of new log lines
        
        Yields:
            List[str]: Chunk of new log lines
        """
        # Regular line-based processing
        new_lines = self._read_new_lines()
        
        if not new_lines:
            return
        
        # Limit lines per batch
        max_lines = self.realtime_config["max_lines_per_batch"]
        if len(new_lines) > max_lines:
            print(f"WARNING: Too many new lines ({len(new_lines)}), limiting to {max_lines}")
            new_lines = new_lines[:max_lines]
        
        # Add to pending buffer
        self.pending_lines.extend(new_lines)
        
        # Determine effective processing mode and apply auto-sampling logic
        effective_mode = self.processing_mode
        should_sample = False
        
        if self.processing_mode == "sampling":
            should_sample = True
            effective_mode = "sampling"
        elif self.processing_mode == "full" and len(self.pending_lines) > self.sampling_threshold:
            print(f"AUTO-SWITCH: Pending lines ({len(self.pending_lines)}) exceed threshold ({self.sampling_threshold})")
            print("SWITCHING TO SAMPLING MODE")
            should_sample = True
            effective_mode = "sampling"
        
        # Status update with correct effective mode
        if len(new_lines) > 0:
            status_msg = f"[{effective_mode.upper()}] Pending: {len(self.pending_lines)} lines (+{len(new_lines)} new)"
            print(f"STATUS: {status_msg}")
        
        # Apply sampling if needed
        if should_sample and len(self.pending_lines) > self.chunk_size:
            discarded_count = len(self.pending_lines) - self.chunk_size
            self.pending_lines = self.pending_lines[-self.chunk_size:]
            if discarded_count > 0:
                print(f"SAMPLING: Discarded {discarded_count} older lines, keeping latest {self.chunk_size}")
        
        # Yield complete chunks
        while len(self.pending_lines) >= self.chunk_size:
            chunk = self.pending_lines[:self.chunk_size]
            self.pending_lines = self.pending_lines[self.chunk_size:]
            print(f"CHUNK READY: {len(chunk)} lines | Remaining: {len(self.pending_lines)}")
            yield chunk

def create_realtime_monitor(log_type: str, 
                          chunk_size=None, 
                          remote_mode=None, 
                          ssh_config=None, 
                          remote_log_path=None) -> RealtimeLogMonitor:
    """
    Create a real-time log monitor
    
    Args:
        log_type: Type of log to monitor
        chunk_size: Override chunk size
        remote_mode: Access mode ("local" or "ssh")
        ssh_config: SSH configuration
        remote_log_path: Remote log file path
    
    Returns:
        RealtimeLogMonitor: Initialized monitor instance
    """
    # Get configuration
    config = get_analysis_config(
        log_type=log_type,
        chunk_size=chunk_size,
        analysis_mode="realtime",
        remote_mode=remote_mode,
        ssh_config=ssh_config,
        remote_log_path=remote_log_path
    )
    
    return RealtimeLogMonitor(log_type, config)
