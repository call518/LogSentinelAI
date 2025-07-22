# LogSentinelAI - 사용법 예시

## 개요

LogSentinelAI는 이제 로컬 파일과 원격 SSH 서버의 로그 파일을 모두 지원합니다. 각 스크립트를 실행할 때마다 개별적으로 대상을 지정할 수 있어, 여러 서버를 대상으로 유연하게 사용할 수 있습니다.

## 지원되는 모드

### 1. 로컬 파일 모드 (기본값)
- 로컬 시스템의 파일을 직접 분석
- 기존 방식과 동일하게 작동

### 2. SSH 원격 모드  
- SSH를 통해 원격 서버의 로그 파일에 접근
- 실시간 모니터링 및 배치 분석 모두 지원

## 로컬 파일 사용법

### 배치 분석 (기본 설정 파일 사용)
```bash
# config 파일의 기본 경로 사용
python analysis-linux-system-log.py --mode batch

# config 파일의 기본 경로 사용하되 청크 크기 변경
python analysis-linux-system-log.py --mode batch --chunk-size 20
```

### 배치 분석 (사용자 지정 파일)
```bash
# 특정 로그 파일 지정
python analysis-linux-system-log.py --mode batch --log-path /var/log/messages

# 특정 로그 파일 + 청크 크기 변경
python analysis-linux-system-log.py --mode batch --log-path /var/log/messages --chunk-size 15
```

### 실시간 모니터링 (로컬)
```bash
# 기본 설정으로 실시간 모니터링
python analysis-linux-system-log.py --mode realtime

# 샘플링 모드로 실시간 모니터링
python analysis-linux-system-log.py --mode realtime --processing-mode sampling

# 자동 샘플링 임계값 변경
python analysis-linux-system-log.py --mode realtime --sampling-threshold 200
```

## SSH 원격 파일 사용법

### SSH 키 인증 사용
```bash
# 배치 분석 (SSH 키 인증)
python analysis-linux-system-log.py \
  --mode batch \
  --access-mode ssh \
  --ssh-host 192.168.1.100 \
  --ssh-user admin \
  --ssh-key ~/.ssh/id_rsa \
  --remote-log-path /var/log/messages

# 실시간 모니터링 (SSH 키 인증)  
python analysis-linux-system-log.py \
  --mode realtime \
  --access-mode ssh \
  --ssh-host 192.168.1.100 \
  --ssh-user admin \
  --ssh-key ~/.ssh/id_rsa \
  --remote-log-path /var/log/messages
```

### SSH 패스워드 인증 사용
```bash
# 배치 분석 (패스워드 인증)
python analysis-linux-system-log.py \
  --mode batch \
  --access-mode ssh \
  --ssh-host server.example.com \
  --ssh-user loguser \
  --ssh-password "your_password" \
  --remote-log-path /var/log/syslog

# 비표준 SSH 포트 사용
python analysis-linux-system-log.py \
  --mode batch \
  --access-mode ssh \
  --ssh-host server.example.com \
  --ssh-port 2222 \
  --ssh-user loguser \
  --ssh-key ~/.ssh/custom_key \
  --remote-log-path /var/log/messages
```

## 다양한 로그 타입별 예시

### Apache Access 로그 (원격)
```bash
python analysis-httpd-access-log.py \
  --mode batch \
  --access-mode ssh \
  --ssh-host web-server.example.com \
  --ssh-user apache \
  --ssh-key ~/.ssh/apache_key \
  --remote-log-path /var/log/apache2/access.log \
  --chunk-size 50
```

### TCPDump 패킷 로그 (원격 실시간)
```bash
python analysis-tcpdump-packet.py \
  --mode realtime \
  --access-mode ssh \
  --ssh-host firewall.example.com \
  --ssh-user admin \
  --ssh-key ~/.ssh/firewall_key \
  --remote-log-path /var/log/tcpdump.log \
  --processing-mode sampling \
  --chunk-size 10
```

### Apache Error 로그 (원격)
```bash
python analysis-httpd-apache-log.py \
  --mode batch \
  --access-mode ssh \
  --ssh-host web-server2.example.com \
  --ssh-user root \
  --ssh-password "secure_password" \
  --remote-log-path /var/log/apache2/error.log
```

## 여러 서버 동시 모니터링

각 터미널에서 개별 스크립트 실행:

### 터미널 1: 웹서버 액세스 로그
```bash
python analysis-httpd-access-log.py \
  --mode realtime \
  --access-mode ssh \
  --ssh-host web1.company.com \
  --ssh-user webuser \
  --ssh-key ~/.ssh/web1_key \
  --remote-log-path /var/log/apache2/access.log
```

### 터미널 2: 데이터베이스 서버 시스템 로그  
```bash
python analysis-linux-system-log.py \
  --mode realtime \
  --access-mode ssh \
  --ssh-host db1.company.com \
  --ssh-user dbadmin \
  --ssh-key ~/.ssh/db1_key \
  --remote-log-path /var/log/messages
```

### 터미널 3: 방화벽 패킷 로그
```bash
python analysis-tcpdump-packet.py \
  --mode realtime \
  --access-mode ssh \
  --ssh-host firewall.company.com \
  --ssh-user security \
  --ssh-key ~/.ssh/firewall_key \
  --remote-log-path /var/log/tcpdump.log
```

## 설정 파일 우선순위

1. **CLI 인자** (최고 우선순위)
2. **config 파일의 환경변수**  
3. **기본값** (최저 우선순위)

## 주의사항

### SSH 키 권한 설정
```bash
# SSH 키 파일 권한 설정
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
```

### 원격 서버 로그 파일 권한
```bash
# 원격 서버에서 로그 파일 읽기 권한 확인
ls -la /var/log/messages
# 필요시 권한 조정 (관리자 권한 필요)
sudo chmod 644 /var/log/messages
```

### SSH 연결 테스트
```bash
# 실제 스크립트 실행 전에 SSH 연결 테스트
ssh -i ~/.ssh/id_rsa user@server.example.com "tail -n 5 /var/log/messages"
```

## 문제 해결

### SSH 연결 실패
- SSH 키 파일 경로 및 권한 확인
- 원격 서버의 SSH 서비스 상태 확인
- 방화벽 및 포트 설정 확인

### 로그 파일 접근 권한 오류
- 원격 사용자의 로그 파일 읽기 권한 확인
- sudo 권한이 필요한 경우 사용자 계정 권한 확인

### 실시간 모니터링 성능 이슈
- `--sampling-threshold` 값 조정
- `--chunk-size` 값 최적화
- `REALTIME_POLLING_INTERVAL` 설정값 조정
