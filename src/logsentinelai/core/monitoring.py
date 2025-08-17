"""
Real-time log monitoring module
Handles continuous monitoring and processing of log files
"""
import os
import time
from typing import Dict, Any, List, Generator, Optional
from .config import get_analysis_config
from .ssh import RemoteSSHLogMonitor
from .commons import setup_logger

logger = setup_logger("logsentinelai.core.monitoring")

class RealtimeLogMonitor:
    """Real-time log file monitoring and analysis"""
    
    def __init__(self, log_type: str, config: Dict[str, Any]):
        """
        Initialize real-time log monitor
        
        Args:
            log_type: Type of log to monitor
            config: Configuration dictionary from get_analysis_config()
        """
        logger.info(f"Initializing RealtimeLogMonitor for log_type: {log_type}")
        logger.debug(f"Monitor configuration: {config}")
        
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
        self.only_sampling_mode = self.realtime_config["only_sampling_mode"]
        self.sampling_threshold = self.realtime_config["sampling_threshold"]
        
        # Chunk pending timeout configuration
        self.chunk_pending_timeout = self.realtime_config["chunk_pending_timeout"]  # seconds
        
        # Buffer management
        self.line_buffer = []
        self.pending_lines = []
        self.pending_start_time: Optional[float] = None  # Track when pending logs started
        
        # File state tracking (for rotation detection only)
        self.current_file_size = 0
        self.current_inode = None
        
        # Initialize SSH monitor if needed
        if self.access_mode == "ssh":
            self._initialize_ssh_monitor()
        
        # Initialize file state
        self._initialize_file_state()
        
        # Display initialization info
        self._print_initialization_info()
        
        logger.info(f"RealtimeLogMonitor initialized successfully for {self.log_type}")
        logger.debug(f"Final monitor state - access_mode: {self.access_mode}, log_path: {self.log_path}, chunk_size: {self.chunk_size}")
    
    def _initialize_ssh_monitor(self):
        """SSH 원격 모니터 초기화"""
        logger.info("Initializing SSH monitor")
        logger.debug(f"SSH config: {self.ssh_config}")
        
        try:
            if not self.log_path:
                raise ValueError(f"No remote log path configured for {self.log_type}")
            
            logger.debug(f"Creating RemoteSSHLogMonitor for path: {self.log_path}")
            self.ssh_monitor = RemoteSSHLogMonitor(self.ssh_config, self.log_path)
            
            print("🔗 Testing SSH connection...")
            logger.info("Testing SSH connection")
            if self.ssh_monitor.test_connection():
                print("✅ SSH connection successful")
                logger.info("SSH connection test successful")
            else:
                raise ConnectionError("SSH connection test failed")
                
        except Exception as e:
            print(f"❌ SSH initialization failed: {e}")
            print("💡 Please check your SSH configuration")
            logger.error(f"SSH monitoring initialization failed: {e}")
            raise
    
    def _initialize_file_state(self):
        """파일 상태 초기화 - 현재 파일 끝에서 시작"""
        logger.info(f"Initializing file state for {self.access_mode} mode")
        logger.debug(f"Log path: {self.log_path}")
        
        try:
            if self.access_mode == "ssh":
                if self.ssh_monitor:
                    self.current_file_size = self.ssh_monitor.get_file_size()
                    self.current_inode = self.ssh_monitor.get_file_inode()
                    print(f"📍 Starting from end of remote file (size: {self.current_file_size})")
                    logger.info(f"Remote file state initialized - size: {self.current_file_size}, inode: {self.current_inode}")
            else:
                if os.path.exists(self.log_path):
                    file_stat = os.stat(self.log_path)
                    self.current_file_size = file_stat.st_size
                    self.current_inode = file_stat.st_ino
                    print(f"📍 Starting from end of local file (size: {self.current_file_size})")
                    logger.info(f"Local file state initialized - size: {self.current_file_size}, inode: {self.current_inode}")
                else:
                    print(f"WARNING: Log file does not exist: {self.log_path}")
                    logger.warning(f"Log file does not exist: {self.log_path}")
                    self.current_file_size = 0
                    self.current_inode = None
        except Exception as e:
            print(f"WARNING: Error accessing log file: {e}")
            logger.error(f"Error accessing log file during initialization: {e}")
            self.current_file_size = 0
            self.current_inode = None
    
    def _print_initialization_info(self):
        """Display initialization information"""
        print("=" * 80)
        print(f"REALTIME LOG MONITOR INITIALIZED")
        print("=" * 80)
        print(f"Log Type:         {self.log_type}")
        print(f"Access Mode:      {self.access_mode.upper()}")
        print(f"Monitoring:       {self.log_path}")
        print(f"Mode:             {'SAMPLING-ONLY' if self.only_sampling_mode else 'FULL'}")
        if not self.only_sampling_mode:
            unit = 'lines'
            print(f"Auto-sampling:    {self.sampling_threshold} {unit} threshold")
        else:
            unit = 'lines'
            print(f"Sampling:         Always keep latest {self.chunk_size} {unit}")
        print(f"Poll Interval:    {self.realtime_config['polling_interval']}s")
        unit = 'lines'
        print(f"Chunk Size:       {self.chunk_size} {unit}")
        if self.chunk_pending_timeout > 0:
            print(f"Pending Timeout:  {self.chunk_pending_timeout} seconds ({self.chunk_pending_timeout//60} minutes)")
        else:
            print(f"Pending Timeout:  Disabled (wait indefinitely)")
        print(f"Starting Mode:    NEW LOGS ONLY (realtime)")
        print("=" * 80)
    
    def _read_new_lines(self) -> List[str]:
        """새로운 로그 라인들을 읽어옴 (현재 파일 크기에서 증가분만)"""
        logger.debug("Reading new lines from log file")
        
        if self.access_mode == "ssh":
            return self._read_remote_new_lines()
        else:
            return self._read_local_new_lines()
    
    def _read_local_new_lines(self) -> List[str]:
        """로컬 파일에서 새로운 로그 라인들을 읽어옴"""
        logger.debug(f"Reading local new lines from: {self.log_path}")
        
        try:
            if not os.path.exists(self.log_path):
                print(f"WARNING: Log file does not exist: {self.log_path}")
                logger.warning(f"Log file does not exist: {self.log_path}")
                return []
            
            # 현재 파일 상태 확인
            file_stat = os.stat(self.log_path)
            new_size = file_stat.st_size
            new_inode = file_stat.st_ino
            
            logger.debug(f"File state check - current_size: {self.current_file_size}, new_size: {new_size}, current_inode: {self.current_inode}, new_inode: {new_inode}")
            
            # 파일 회전이나 새 파일 감지
            if self.current_inode and new_inode != self.current_inode:
                print(f"NOTICE: Log rotation detected - starting fresh")
                logger.info(f"Log rotation detected - inode changed from {self.current_inode} to {new_inode}")
                self.current_file_size = new_size  # 새 파일 끝에서 시작
                self.current_inode = new_inode
                self.line_buffer = []
                return []
            
            # 파일이 줄어든 경우 (truncated)
            if new_size < self.current_file_size:
                print(f"NOTICE: File truncated - starting fresh")
                logger.info(f"File truncated - size changed from {self.current_file_size} to {new_size}")
                self.current_file_size = new_size
                self.current_inode = new_inode
                self.line_buffer = []
                return []
            
            # 새로운 내용이 없는 경우
            if new_size <= self.current_file_size:
                logger.debug("No new content in file")
                return []
            
            # 새로운 내용 읽기
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.current_file_size)
                new_content = f.read()
                
                if not new_content:
                    logger.debug("No new content found after seeking")
                    return []
                
                logger.debug(f"Read {len(new_content)} new characters from file")
                
                # 라인으로 분할하고 불완전한 라인 처리
                lines = new_content.split('\n')
                
                if new_content.endswith('\n'):
                    complete_lines = lines[:-1]  # 마지막 빈 요소 제거
                    incomplete_line = ""
                else:
                    complete_lines = lines[:-1]  # 마지막 불완전한 라인 제외
                    incomplete_line = lines[-1]  # 불완전한 라인 저장
                
                # 버퍼된 내용과 첫 번째 라인 합치기
                if self.line_buffer and complete_lines:
                    complete_lines[0] = self.line_buffer[0] + complete_lines[0]
                
                # 파일 위치 업데이트 (불완전한 라인 제외)
                if complete_lines or not incomplete_line:
                    incomplete_bytes = len(incomplete_line.encode('utf-8')) if incomplete_line else 0
                    self.current_file_size = new_size - incomplete_bytes
                    self.current_inode = new_inode
                
                # 라인 버퍼 업데이트
                self.line_buffer = [incomplete_line] if incomplete_line else []
                
                # 빈 라인 필터링
                complete_lines = [line.strip() for line in complete_lines if line.strip()]
                
                if complete_lines:
                    logger.debug(f"Processed {len(complete_lines)} complete new lines")
                else:
                    logger.debug("No complete lines found after filtering")
                    
                return complete_lines
                
        except IOError as e:
            print(f"WARNING: Error reading local log file: {e}")
            logger.error(f"Error reading local log file: {e}")
            return []
    
    def _read_remote_new_lines(self) -> List[str]:
        """SSH로 원격 파일에서 새로운 로그 라인들을 읽어옴"""
        logger.debug(f"Reading remote new lines from: {self.log_path}")
        
        try:
            if not self.ssh_monitor:
                print(f"WARNING: SSH monitor not initialized")
                logger.warning("SSH monitor not initialized")
                return []
            
            new_size = self.ssh_monitor.get_file_size()
            new_inode = self.ssh_monitor.get_file_inode()
            
            logger.debug(f"Remote file state check - current_size: {self.current_file_size}, new_size: {new_size}, current_inode: {self.current_inode}, new_inode: {new_inode}")
            
            # 파일 회전이나 새 파일 감지
            if self.current_inode and new_inode and new_inode != self.current_inode:
                print(f"NOTICE: Remote log rotation detected - starting fresh")
                logger.info(f"Remote log rotation detected - inode changed from {self.current_inode} to {new_inode}")
                self.current_file_size = new_size  # 새 파일 끝에서 시작
                self.current_inode = new_inode
                return []
            
            # 파일이 줄어든 경우 (truncated)
            if new_size < self.current_file_size:
                print(f"NOTICE: Remote file truncated - starting fresh")
                logger.info(f"Remote file truncated - size changed from {self.current_file_size} to {new_size}")
                self.current_file_size = new_size
                self.current_inode = new_inode
                return []
            
            # 새로운 내용이 없는 경우
            if new_size <= self.current_file_size:
                logger.debug("No new content in remote file")
                return []
            
            # 새로운 라인들 읽기
            new_lines = self.ssh_monitor.read_from_position(self.current_file_size)
            
            if new_lines:
                # 파일 위치 업데이트
                self.current_file_size = new_size
                self.current_inode = new_inode
                logger.debug(f"Read {len(new_lines)} new lines from remote file")
            else:
                logger.debug("No new lines received from remote file")
            
            return new_lines
            
        except Exception as e:
            print(f"WARNING: Error reading remote log file: {e}")
            logger.error(f"Error reading remote log file: {e}")
            return []
    
    def get_new_log_chunks(self) -> Generator[List[str], None, None]:
        """
        새로운 로그 청크를 반환하는 제너레이터
        
        Yields:
            List[str]: 새로운 로그 라인들의 청크
        """
        logger.debug("Getting new log chunks")
        
        # 새로운 라인 읽기
        new_lines = self._read_new_lines()
        
        if not new_lines and not self.pending_lines:
            logger.debug("No new lines and no pending lines")
            return
        
        # 배치당 라인 수 제한
        max_lines = self.realtime_config["max_lines_per_batch"]
        if len(new_lines) > max_lines:
            print(f"WARNING: Too many new lines ({len(new_lines)}), limiting to {max_lines}")
            logger.warning(f"Too many new lines ({len(new_lines)}), limiting to {max_lines}")
            new_lines = new_lines[:max_lines]
        
        # 대기 중인 버퍼에 추가
        if new_lines:
            # 새로운 라인이 추가되는 시점에서 pending_start_time 설정
            if not self.pending_lines:
                self.pending_start_time = time.time()
                logger.debug(f"Starting new pending batch at {self.pending_start_time}")
                if self.chunk_pending_timeout > 0:
                    logger.info(f"Started pending batch timer - will timeout in {self.chunk_pending_timeout} seconds if chunk size ({self.chunk_size}) not reached")
            
            self.pending_lines.extend(new_lines)
            logger.info(f"Added {len(new_lines)} new lines to buffer, total pending: {len(self.pending_lines)}")
            
            # 타임아웃 경과 시간 로깅 (디버그 레벨)
            if self.pending_start_time and self.chunk_pending_timeout > 0:
                elapsed = time.time() - self.pending_start_time
                logger.debug(f"Pending batch elapsed time: {elapsed:.1f}s / {self.chunk_pending_timeout}s")
        
        # 처리 모드 결정 및 자동 샘플링 로직 적용
        should_sample = False
        
        if self.only_sampling_mode:
            should_sample = True
            effective_mode = "sampling"
            logger.debug("Using sampling mode (always-on)")
        elif len(self.pending_lines) > self.sampling_threshold:
            print(f"AUTO-SWITCH: Pending lines ({len(self.pending_lines)}) exceed threshold ({self.sampling_threshold})")
            print("SWITCHING TO SAMPLING MODE")
            logger.info(f"Auto-switching to sampling mode - pending lines ({len(self.pending_lines)}) exceed threshold ({self.sampling_threshold})")
            should_sample = True
            effective_mode = "sampling"
        else:
            effective_mode = "full"
            logger.debug("Using full processing mode")
        
        # 타임아웃 체크
        timeout_triggered = False
        if (self.pending_lines and 
            self.chunk_pending_timeout > 0 and 
            self.pending_start_time and 
            time.time() - self.pending_start_time >= self.chunk_pending_timeout):
            timeout_triggered = True
            print(f"TIMEOUT: Chunk pending timeout reached ({self.chunk_pending_timeout} seconds), processing {len(self.pending_lines)} pending lines")
            logger.info(f"Chunk pending timeout triggered after {self.chunk_pending_timeout} seconds with {len(self.pending_lines)} pending lines")
        
        # 상태 업데이트
        if len(new_lines) > 0 or self.pending_lines:
            if len(new_lines) > 0:
                status_msg = f"[{effective_mode.upper()}] Pending: {len(self.pending_lines)} lines"
                # 타임아웃 남은 시간 표시
                if (self.pending_lines and 
                    self.chunk_pending_timeout > 0 and 
                    self.pending_start_time):
                    elapsed = time.time() - self.pending_start_time
                    remaining = max(0, self.chunk_pending_timeout - elapsed)
                    if timeout_triggered:
                        status_msg += " [TIMEOUT TRIGGERED]"
                    else:
                        status_msg += f" [Timeout: {int(remaining)}s]"
                elif timeout_triggered:
                    status_msg += " [TIMEOUT]"
                
                status_msg += f" (+{len(new_lines)} new)"
            else:
                status_msg = f"[{effective_mode.upper()}] Pending: {len(self.pending_lines)} lines"
                # 타임아웃 남은 시간 표시
                if (self.pending_lines and 
                    self.chunk_pending_timeout > 0 and 
                    self.pending_start_time):
                    elapsed = time.time() - self.pending_start_time
                    remaining = max(0, self.chunk_pending_timeout - elapsed)
                    if timeout_triggered:
                        status_msg += " [TIMEOUT TRIGGERED]"
                    else:
                        status_msg += f" [Timeout: {int(remaining)}s]"
                elif timeout_triggered:
                    status_msg += " [TIMEOUT]"
                
            print(f"STATUS: {status_msg}")
        
        # 필요한 경우 샘플링 적용
        if should_sample and len(self.pending_lines) > self.chunk_size:
            discarded_count = len(self.pending_lines) - self.chunk_size
            self.pending_lines = self.pending_lines[-self.chunk_size:]
            if discarded_count > 0:
                print(f"SAMPLING: Discarded {discarded_count} older lines, keeping latest {self.chunk_size}")
                logger.info(f"Sampling applied - discarded {discarded_count} older lines, keeping latest {self.chunk_size}")
        
        # 완전한 청크들 반환 (정상적인 경우)
        while len(self.pending_lines) >= self.chunk_size:
            chunk = self.pending_lines[:self.chunk_size]
            self.pending_lines = self.pending_lines[self.chunk_size:]
            print(f"CHUNK READY: {len(chunk)} lines | Remaining: {len(self.pending_lines)}")
            logger.info(f"Yielding chunk with {len(chunk)} lines, {len(self.pending_lines)} lines remaining")
            logger.debug(f"Chunk content preview: {chunk[:3]}..." if len(chunk) > 3 else f"Chunk content: {chunk}")
            
            # pending_start_time 리셋
            if not self.pending_lines:
                self.pending_start_time = None
                logger.debug("Cleared pending timer - all lines processed")
            else:
                self.pending_start_time = time.time()  # 남은 라인들에 대해 새로운 타이머 시작
                logger.debug(f"Reset pending timer for {len(self.pending_lines)} remaining lines")
                
            yield chunk
        
        # 타임아웃으로 인한 강제 처리
        if timeout_triggered and self.pending_lines:
            chunk = self.pending_lines[:]
            self.pending_lines = []
            self.pending_start_time = None
            print(f"TIMEOUT CHUNK: {len(chunk)} lines (forced processing)")
            logger.info(f"Yielding timeout chunk with {len(chunk)} lines")
            logger.warning(f"Forced processing due to pending timeout - processed {len(chunk)} lines after {self.chunk_pending_timeout} seconds")
            logger.debug(f"Timeout chunk content preview: {chunk[:3]}..." if len(chunk) > 3 else f"Timeout chunk content: {chunk}")
            yield chunk
    
    def mark_chunk_processed(self, processed_lines: List[str]):
        """
        청크가 처리되었음을 표시 (실시간 모드에서는 특별한 처리 불필요)
        
        Args:
            processed_lines: 처리된 라인들
        """
        # 실시간 모드에서는 별도의 position 업데이트가 불필요
        # 파일 크기는 새 라인을 읽을 때마다 자동으로 업데이트됨
        logger.debug(f"Marked {len(processed_lines)} lines as processed")
        pass
    
    def save_state_on_exit(self):
        """종료시 상태 저장 (실시간 모드에서는 불필요)"""
        print("💾 Realtime mode - no state to save")
        logger.info("Realtime mode shutdown - no state to save")
        # 실시간 모드에서는 항상 파일 끝에서 시작하므로 상태 저장 불필요

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
    logger.info(f"Creating realtime monitor for log_type: {log_type}")
    logger.debug(f"Parameters - chunk_size: {chunk_size}, remote_mode: {remote_mode}, remote_log_path: {remote_log_path}")
    
    # Get configuration
    config = get_analysis_config(
        log_type=log_type,
        chunk_size=chunk_size,
        analysis_mode="realtime",
        remote_mode=remote_mode,
        ssh_config=ssh_config,
        remote_log_path=remote_log_path
    )
    
    monitor = RealtimeLogMonitor(log_type, config)
    logger.info(f"Realtime monitor created successfully for {log_type}")
    return monitor

