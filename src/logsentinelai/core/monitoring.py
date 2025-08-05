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
        self.only_sampling_mode = self.realtime_config["only_sampling_mode"]
        self.sampling_threshold = self.realtime_config["sampling_threshold"]
        
        # Buffer management
        self.line_buffer = []
        self.pending_lines = []
        
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
    
    def _initialize_file_state(self):
        """파일 상태 초기화 - 현재 파일 끝에서 시작"""
        try:
            if self.access_mode == "ssh":
                if self.ssh_monitor:
                    self.current_file_size = self.ssh_monitor.get_file_size()
                    self.current_inode = self.ssh_monitor.get_file_inode()
                    print(f"📍 Starting from end of remote file (size: {self.current_file_size})")
            else:
                if os.path.exists(self.log_path):
                    file_stat = os.stat(self.log_path)
                    self.current_file_size = file_stat.st_size
                    self.current_inode = file_stat.st_ino
                    print(f"📍 Starting from end of local file (size: {self.current_file_size})")
                else:
                    print(f"WARNING: Log file does not exist: {self.log_path}")
                    self.current_file_size = 0
                    self.current_inode = None
        except Exception as e:
            print(f"WARNING: Error accessing log file: {e}")
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
        print(f"Starting Mode:    NEW LOGS ONLY (realtime)")
        print("=" * 80)
    
    def _read_new_lines(self) -> List[str]:
        """새로운 로그 라인들을 읽어옴 (현재 파일 크기에서 증가분만)"""
        if self.access_mode == "ssh":
            return self._read_remote_new_lines()
        else:
            return self._read_local_new_lines()
    
    def _read_local_new_lines(self) -> List[str]:
        """로컬 파일에서 새로운 로그 라인들을 읽어옴"""
        try:
            if not os.path.exists(self.log_path):
                print(f"WARNING: Log file does not exist: {self.log_path}")
                return []
            
            # 현재 파일 상태 확인
            file_stat = os.stat(self.log_path)
            new_size = file_stat.st_size
            new_inode = file_stat.st_ino
            
            # 파일 회전이나 새 파일 감지
            if self.current_inode and new_inode != self.current_inode:
                print(f"NOTICE: Log rotation detected - starting fresh")
                self.current_file_size = new_size  # 새 파일 끝에서 시작
                self.current_inode = new_inode
                self.line_buffer = []
                return []
            
            # 파일이 줄어든 경우 (truncated)
            if new_size < self.current_file_size:
                print(f"NOTICE: File truncated - starting fresh")
                self.current_file_size = new_size
                self.current_inode = new_inode
                self.line_buffer = []
                return []
            
            # 새로운 내용이 없는 경우
            if new_size <= self.current_file_size:
                return []
            
            # 새로운 내용 읽기
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.current_file_size)
                new_content = f.read()
                
                if not new_content:
                    return []
                
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
                return complete_lines
                
        except IOError as e:
            print(f"WARNING: Error reading local log file: {e}")
            return []
    
    def _read_remote_new_lines(self) -> List[str]:
        """SSH로 원격 파일에서 새로운 로그 라인들을 읽어옴"""
        try:
            if not self.ssh_monitor:
                print(f"WARNING: SSH monitor not initialized")
                return []
            
            new_size = self.ssh_monitor.get_file_size()
            new_inode = self.ssh_monitor.get_file_inode()
            
            # 파일 회전이나 새 파일 감지
            if self.current_inode and new_inode and new_inode != self.current_inode:
                print(f"NOTICE: Remote log rotation detected - starting fresh")
                self.current_file_size = new_size  # 새 파일 끝에서 시작
                self.current_inode = new_inode
                return []
            
            # 파일이 줄어든 경우 (truncated)
            if new_size < self.current_file_size:
                print(f"NOTICE: Remote file truncated - starting fresh")
                self.current_file_size = new_size
                self.current_inode = new_inode
                return []
            
            # 새로운 내용이 없는 경우
            if new_size <= self.current_file_size:
                return []
            
            # 새로운 라인들 읽기
            new_lines = self.ssh_monitor.read_from_position(self.current_file_size)
            
            if new_lines:
                # 파일 위치 업데이트
                self.current_file_size = new_size
                self.current_inode = new_inode
            
            return new_lines
            
        except Exception as e:
            print(f"WARNING: Error reading remote log file: {e}")
            return []
    
    def get_new_log_chunks(self) -> Generator[List[str], None, None]:
        """
        새로운 로그 청크를 반환하는 제너레이터
        
        Yields:
            List[str]: 새로운 로그 라인들의 청크
        """
        # 새로운 라인 읽기
        new_lines = self._read_new_lines()
        
        if not new_lines and not self.pending_lines:
            return
        
        # 배치당 라인 수 제한
        max_lines = self.realtime_config["max_lines_per_batch"]
        if len(new_lines) > max_lines:
            print(f"WARNING: Too many new lines ({len(new_lines)}), limiting to {max_lines}")
            new_lines = new_lines[:max_lines]
        
        # 대기 중인 버퍼에 추가
        self.pending_lines.extend(new_lines)
        
        # 처리 모드 결정 및 자동 샘플링 로직 적용
        should_sample = False
        
        if self.only_sampling_mode:
            should_sample = True
            effective_mode = "sampling"
        elif len(self.pending_lines) > self.sampling_threshold:
            print(f"AUTO-SWITCH: Pending lines ({len(self.pending_lines)}) exceed threshold ({self.sampling_threshold})")
            print("SWITCHING TO SAMPLING MODE")
            should_sample = True
            effective_mode = "sampling"
        else:
            effective_mode = "full"
        
        # 상태 업데이트
        if len(new_lines) > 0 or self.pending_lines:
            if len(new_lines) > 0:
                status_msg = f"[{effective_mode.upper()}] Pending: {len(self.pending_lines)} lines (+{len(new_lines)} new)"
            else:
                status_msg = f"[{effective_mode.upper()}] Pending: {len(self.pending_lines)} lines"
            print(f"STATUS: {status_msg}")
        
        # 필요한 경우 샘플링 적용
        if should_sample and len(self.pending_lines) > self.chunk_size:
            discarded_count = len(self.pending_lines) - self.chunk_size
            self.pending_lines = self.pending_lines[-self.chunk_size:]
            if discarded_count > 0:
                print(f"SAMPLING: Discarded {discarded_count} older lines, keeping latest {self.chunk_size}")
        
        # 완전한 청크들 반환
        while len(self.pending_lines) >= self.chunk_size:
            chunk = self.pending_lines[:self.chunk_size]
            self.pending_lines = self.pending_lines[self.chunk_size:]
            print(f"CHUNK READY: {len(chunk)} lines | Remaining: {len(self.pending_lines)}")
            yield chunk
    
    def mark_chunk_processed(self, processed_lines: List[str]):
        """
        청크가 처리되었음을 표시 (실시간 모드에서는 특별한 처리 불필요)
        
        Args:
            processed_lines: 처리된 라인들
        """
        # 실시간 모드에서는 별도의 position 업데이트가 불필요
        # 파일 크기는 새 라인을 읽을 때마다 자동으로 업데이트됨
        pass
    
    def save_state_on_exit(self):
        """종료시 상태 저장 (실시간 모드에서는 불필요)"""
        print("💾 Realtime mode - no state to save")
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
