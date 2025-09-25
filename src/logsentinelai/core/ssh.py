"""
SSH remote log monitoring module
Handles remote log file access via SSH connections
"""
import os
from typing import Dict, Any, List, Optional

class RemoteSSHLogMonitor:
    """SSH-based remote log file monitoring"""
    
    def __init__(self, ssh_config: Dict[str, Any], remote_log_path: str):
        """
        Initialize SSH remote log monitor
        
        Args:
            ssh_config: SSH connection configuration
            remote_log_path: Remote log file path
        """
        self.ssh_host = ssh_config["host"]
        self.ssh_port = ssh_config["port"]
        self.ssh_user = ssh_config["user"]
        self.ssh_key_path = ssh_config["key_path"]
        self.ssh_password = ssh_config["password"]
        self.ssh_timeout = ssh_config["timeout"]
        self.remote_log_path = remote_log_path
        
        self._validate_ssh_config()
        
        print(f"SSH Target:       {self.ssh_user}@{self.ssh_host}:{self.ssh_port}")
        print(f"Remote Log:       {self.remote_log_path}")
        print(f"Auth Method:      {'SSH Key' if self.ssh_key_path else 'Password'}")
        
    def _validate_ssh_config(self):
        """SSH 설정 유효성 검사"""
        if not self.ssh_host:
            raise ValueError("REMOTE_SSH_HOST is required for SSH mode")
        if not self.ssh_user:
            raise ValueError("REMOTE_SSH_USER is required for SSH mode")
        if not self.ssh_key_path and not self.ssh_password:
            raise ValueError("Either REMOTE_SSH_KEY_PATH or REMOTE_SSH_PASSWORD is required")
        
        if self.ssh_key_path and not os.path.exists(self.ssh_key_path):
            raise FileNotFoundError(f"SSH key file not found: {self.ssh_key_path}")
    
    def _create_ssh_connection(self):
        """SSH 연결 생성"""
        try:
            import paramiko
        except ImportError:
            raise ImportError("paramiko library is required for SSH functionality. Install with: pip install paramiko")
        
        ssh = paramiko.SSHClient()
        # ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) ### 보안상 위험할 수 있으므로 사용하지 않음
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        
        try:
            if self.ssh_key_path:
                ssh.connect(
                    hostname=self.ssh_host,
                    port=self.ssh_port,
                    username=self.ssh_user,
                    key_filename=self.ssh_key_path,
                    timeout=self.ssh_timeout
                )
            else:
                ssh.connect(
                    hostname=self.ssh_host,
                    port=self.ssh_port,
                    username=self.ssh_user,
                    password=self.ssh_password,
                    timeout=self.ssh_timeout
                )
            
            return ssh
            
        except Exception as e:
            ssh.close()
            raise ConnectionError(f"Failed to connect to SSH server: {e}")
    
    def get_file_size(self) -> int:
        """원격 파일 크기 확인"""
        ssh = self._create_ssh_connection()
        try:
            command = f"stat -c %s '{self.remote_log_path}' 2>/dev/null || echo 0"
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()
            
            size_str = stdout.read().decode('utf-8').strip()
            return int(size_str) if size_str.isdigit() else 0
            
        except Exception as e:
            print(f"WARNING: Failed to get remote file size: {e}")
            return 0
        finally:
            ssh.close()
    
    def get_file_inode(self) -> Optional[int]:
        """원격 파일 inode 확인 (로그 로테이션 감지용)"""
        ssh = self._create_ssh_connection()
        try:
            command = f"stat -c %i '{self.remote_log_path}' 2>/dev/null || echo 0"
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()
            
            inode_str = stdout.read().decode('utf-8').strip()
            return int(inode_str) if inode_str.isdigit() and inode_str != "0" else None
            
        except Exception as e:
            print(f"WARNING: Failed to get remote file inode: {e}")
            return None
        finally:
            ssh.close()
    
    def read_from_position(self, position: int) -> List[str]:
        """특정 위치부터 원격 파일 읽기"""
        ssh = self._create_ssh_connection()
        try:
            # 먼저 현재 파일 크기 확인
            size_command = f"stat -c %s '{self.remote_log_path}' 2>/dev/null || echo 0"
            stdin, stdout, stderr = ssh.exec_command(size_command)
            stdout.channel.recv_exit_status()
            current_size = int(stdout.read().decode('utf-8').strip() or '0')
            
            # 요청한 위치가 파일 끝이거나 그 이후인 경우
            if position >= current_size:
                return []
            
            # 실제로 읽을 바이트 수 계산
            bytes_to_read = current_size - position
            if bytes_to_read <= 0:
                return []
            
            # dd 명령으로 정확한 바이트 수만큼 읽기 (tail보다 정확함)
            command = f"dd if='{self.remote_log_path}' bs=1 skip={position} count={bytes_to_read} 2>/dev/null || echo ''"
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()
            
            content = stdout.read().decode('utf-8', errors='ignore')
            
            # 내용이 실제로 없는 경우
            if not content:
                return []
            
            # 라인 분할 및 빈 라인 제거
            lines = content.split('\n')
            
            # 마지막이 개행으로 끝나는 경우 빈 라인 제거
            if lines and not lines[-1]:
                lines = lines[:-1]
            
            # 빈 라인과 공백만 있는 라인 필터링
            filtered_lines = [line.strip() for line in lines if line.strip()]
            
            return filtered_lines
            
        except Exception as e:
            print(f"WARNING: Failed to read remote file: {e}")
            return []
        finally:
            ssh.close()
    
    def test_connection(self) -> bool:
        """SSH 연결 테스트"""
        try:
            ssh = self._create_ssh_connection()
            stdin, stdout, stderr = ssh.exec_command("echo 'SSH connection test'")
            stdout.channel.recv_exit_status()
            
            result = stdout.read().decode('utf-8').strip()
            ssh.close()
            
            return result == "SSH connection test"
            
        except Exception as e:
            print(f"SSH connection test failed: {e}")
            return False
