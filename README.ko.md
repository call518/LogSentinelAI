[![PyPI에 태그로 배포](https://github.com/call518/LogSentinelAI/actions/workflows/pypi-publish.yml/badge.svg)](https://github.com/call518/LogSentinelAI/actions/workflows/pypi-publish.yml)

# LogSentinelAI — 보안 이벤트 및 이상 탐지를 위한 선언적 추출 기반 LLM 로그 분석 도구

LogSentinelAI는 **Declarative Extraction (선언적 추출)** 방식으로 LLM을 활용하여 Apache, Linux 등 다양한 로그에서 보안 이벤트, 이상 징후, 오류를 분석하고, 이를 Elasticsearch/Kibana로 시각화 가능한 구조화 데이터로 변환합니다. 원하는 결과 구조를 Pydantic 클래스로 선언하기만 하면, AI가 자동으로 로그를 분석하여 해당 스키마에 맞는 JSON을 반환합니다. 복잡한 파싱 작업은 필요하지 않습니다.

## 시스템 아키텍처

![System Architecture](img/system-architecture.png)

## 🚀 주요 특징

> ⚡️ **Declarative Extraction (선언적 추출)**
>
> 각 분석기 스크립트에서 원하는 분석 결과 구조(Pydantic class)만 선언하면, LLM이 해당 구조에 맞춰 자동으로 로그를 분석하고 JSON으로 결과를 반환합니다. 복잡한 파싱/후처리 없이 원하는 필드만 선언하면 AI가 알아서 결과를 채워줍니다. 이 방식은 개발자가 "무엇을 뽑을지"만 선언적으로 정의하면, "어떻게 뽑을지"는 LLM이 자동으로 처리하는 최신 패러다임입니다.
```python
# 예시: HTTP Access 로그 분석기에서 원하는 결과 구조만 선언하면,
from pydantic import BaseModel

class MyAccessLogResult(BaseModel):
    ip: str
    url: str
    is_attack: bool

# 위처럼 결과 구조(Pydantic class)만 정의하면,
# LLM이 자동으로 각 로그를 분석해서 아래와 같은 JSON을 반환합니다:
# {
#   "ip": "192.168.0.1",
#   "url": "/admin.php",
#   "is_attack": true
# }
```

### AI 기반 분석
- **Declarative Extraction 지원**: 원하는 결과 구조(Pydantic class)만 선언하면 LLM이 자동 분석
- **LLM 제공자**: OpenAI API, Ollama, vLLM
- **지원 로그 유형**: HTTP Access, Apache Error, Linux System
- **위협 탐지**: SQL Injection, XSS, Brute Force, 네트워크 이상 탐지
- **출력**: Pydantic 검증이 적용된 구조화 JSON
- **Pydantic 클래스만 정의하면 LLM이 자동으로 해당 구조에 맞춰 분석 결과를 생성**
- **적응형 민감도**: LLM 모델 및 로그 유형별 프롬프트에 따라 탐지 민감도 자동 조정

### 처리 모드
- **배치**: 과거 로그 일괄 분석
- **실시간**: 샘플링 기반 라이브 모니터링
- **접근 방식**: 로컬 파일, SSH 원격

### 데이터 부가정보
- **GeoIP**: MaxMind GeoLite2 City 조회(좌표 포함, Kibana geo_point 지원)
- **통계**: IP 카운트, 응답 코드, 각종 메트릭
- **다국어 지원**: 결과 언어 설정 가능(기본: 한국어)

### 엔터프라이즈 통합
- **저장소**: Elasticsearch(ILM 정책 지원)
- **시각화**: Kibana 대시보드
- **배포**: Docker 컨테이너

## 대시보드 예시

![Kibana Dashboard](img/ex-dashboard.png)

## 📋 JSON 출력 예시

![JSON Output](img/ex-json.png)

## 📁 프로젝트 구조 및 주요 파이썬 스크립트

### 핵심 파이썬 구성요소

```
src/logsentinelai/
├── __init__.py                    # 패키지 초기화
├── cli.py                         # 메인 CLI 진입점 및 명령 라우팅
├── py.typed                       # mypy 타입 힌트 마커
│
├── analyzers/                     # 로그 유형별 분석기
│   ├── __init__.py                # 분석기 패키지 초기화
│   ├── httpd_access.py            # HTTP access 로그 분석기(Apache/Nginx)
│   ├── httpd_apache.py            # Apache error 로그 분석기
│   └── linux_system.py            # Linux system 로그 분석기(syslog/messages)
│
├── core/                          # 핵심 분석 엔진(모듈화)
│   ├── __init__.py                # Core 패키지 초기화 및 통합 import
│   ├── commons.py                 # 배치/실시간 분석 공통 함수, 처리 흐름 정의
│   ├── config.py                  # 환경변수 기반 설정 관리
│   ├── llm.py                     # LLM 모델 초기화 및 상호작용
│   ├── elasticsearch.py           # Elasticsearch 연동 및 데이터 전송
│   ├── geoip.py                   # GeoIP 조회 및 IP 부가정보
│   ├── ssh.py                     # SSH 원격 로그 접근
│   ├── monitoring.py              # 실시간 로그 모니터링 및 처리
│   ├── utils.py                   # 로그 처리 유틸리티 및 헬퍼
│   └── prompts.py                 # 로그 유형별 LLM 프롬프트 템플릿
│
└── utils/                         # 유틸리티 함수
    ├── __init__.py                # Utils 패키지 초기화
    └── geoip_downloader.py        # MaxMind GeoIP DB 다운로더
```

### CLI 명령 매핑

```bash
# CLI 명령은 분석기 스크립트에 매핑됨:
logsentinelai-httpd-access   → analyzers/httpd_access.py
logsentinelai-apache-error   → analyzers/httpd_apache.py  
logsentinelai-linux-system   → analyzers/linux_system.py
logsentinelai-geoip-download → utils/geoip_downloader.py
```

### 📑 샘플 로그 미리보기

#### HTTP Access 로그
```
54.36.149.41 - - [22/Jan/2019:03:56:14 +0330] "GET /filter/27|13%20%D9%85%DA%AF%D8%A7%D9%BE%DB%8C%DA%A9%D8%B3%D9%84,27|%DA%A9%D9%85%D8%AA%D8%B1%20%D8%A7%D8%B2%205%20%D9%85%DA%AF%D8%A7%D9%BE%DB%8C%DA%A9%D8%B3%D9%84,p53 HTTP/1.1" 200 30577 "-" "Mozilla/5.0 (compatible; AhrefsBot/6.1; +http://ahrefs.com/robot/)" "-"
31.56.96.51 - - [22/Jan/2019:03:56:16 +0330] "GET /image/60844/productModel/200x200 HTTP/1.1" 200 5667 "https://www.zanbil.ir/m/filter/b113" "Mozilla/5.0 (Linux; Android 6.0; ALE-L21 Build/HuaweiALE-L21) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.158 Mobile Safari/537.36" "-"
31.56.96.51 - - [22/Jan/2019:03:56:16 +0330] "GET /image/61474/productModel/200x200 HTTP/1.1" 200 5379 "https://www.zanbil.ir/m/filter/b113" "Mozilla/5.0 (Linux; Android 6.0; ALE-L21 Build/HuaweiALE-L21) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.158 Mobile Safari/537.36" "-"
40.77.167.129 - - [22/Jan/2019:03:56:17 +0330] "GET /image/14925/productModel/100x100 HTTP/1.1" 200 1696 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "-"
91.99.72.15 - - [22/Jan/2019:03:56:17 +0330] "GET /product/31893/62100/%D8%B3%D8%B4%D9%88%D8%A7%D8%B1-%D8%AE%D8%A7%D9%86%DA%AF%DB%8C-%D9%BE%D8%B1%D9%86%D8%B3%D9%84%DB%8C-%D9%85%D8%AF%D9%84-PR257AT HTTP/1.1" 200 41483 "-" "Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0)Gecko/16.0 Firefox/16.0" "-"
40.77.167.129 - - [22/Jan/2019:03:56:17 +0330] "GET /image/23488/productModel/150x150 HTTP/1.1" 200 2654 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "-"
40.77.167.129 - - [22/Jan/2019:03:56:18 +0330] "GET /image/45437/productModel/150x150 HTTP/1.1" 200 3688 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "-"
40.77.167.129 - - [22/Jan/2019:03:56:18 +0330] "GET /image/576/article/100x100 HTTP/1.1" 200 14776 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "-"
66.249.66.194 - - [22/Jan/2019:03:56:18 +0330] "GET /filter/b41,b665,c150%7C%D8%A8%D8%AE%D8%A7%D8%B1%D9%BE%D8%B2,p56 HTTP/1.1" 200 34277 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "-"
40.77.167.129 - - [22/Jan/2019:03:56:18 +0330] "GET /image/57710/productModel/100x100 HTTP/1.1" 200 1695 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" "-"
```

#### Apache Error 로그
```
[Thu Jun 09 06:07:04 2005] [notice] LDAP: Built with OpenLDAP LDAP SDK
[Thu Jun 09 06:07:04 2005] [notice] LDAP: SSL support unavailable
[Thu Jun 09 06:07:04 2005] [notice] suEXEC mechanism enabled (wrapper: /usr/sbin/suexec)
[Thu Jun 09 06:07:05 2005] [notice] Digest: generating secret for digest authentication ...
[Thu Jun 09 06:07:05 2005] [notice] Digest: done
[Thu Jun 09 06:07:05 2005] [notice] LDAP: Built with OpenLDAP LDAP SDK
[Thu Jun 09 06:07:05 2005] [notice] LDAP: SSL support unavailable
[Thu Jun 09 06:07:05 2005] [error] env.createBean2(): Factory error creating channel.jni:jni ( channel.jni, jni)
[Thu Jun 09 06:07:05 2005] [error] config.update(): Can't create channel.jni:jni
[Thu Jun 09 06:07:05 2005] [error] env.createBean2(): Factory error creating vm: ( vm, )
```

#### Linux System 로그
```
Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 
Jun 14 15:16:02 combo sshd(pam_unix)[19937]: check pass; user unknown
Jun 14 15:16:02 combo sshd(pam_unix)[19937]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 
Jun 15 02:04:59 combo sshd(pam_unix)[20882]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
Jun 15 02:04:59 combo sshd(pam_unix)[20884]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
Jun 15 02:04:59 combo sshd(pam_unix)[20883]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
Jun 15 02:04:59 combo sshd(pam_unix)[20885]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
Jun 15 02:04:59 combo sshd(pam_unix)[20886]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
Jun 15 02:04:59 combo sshd(pam_unix)[20892]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
Jun 15 02:04:59 combo sshd(pam_unix)[20893]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
```

## 설치 가이드

LogSentinelAI의 설치, 환경설정, CLI 사용법, Elasticsearch/Kibana 연동 등 모든 실전 가이드는 아래 설치 문서를 참고해 주세요.

**[설치 및 사용 가이드 바로가기: INSTALL.ko.md](./INSTALL.ko.md)**

> ⚡️ 추가 문의는 GitHub Issue/Discussion을 이용해 주세요!

## 감사의 말씀

LogSentinelAI에 영감과 지침, 그리고 기반 기술을 제공해주신 다음 프로젝트 및 커뮤니티에 진심으로 감사드립니다.

### 핵심 기술 및 프레임워크
- **[Outlines](https://dottxt-ai.github.io/outlines/latest/)** - 신뢰성 높은 AI 분석을 가능하게 하는 구조화 LLM 출력 생성 프레임워크
- **[dottxt-ai Demos](https://github.com/dottxt-ai/demos/tree/main/logs)** - 훌륭한 로그 분석 예제와 구현 패턴
- **[Docker ELK Stack](https://github.com/deviantony/docker-elk)** - 완전한 Elasticsearch, Logstash, Kibana Docker 구성

### LLM 인프라 및 배포
- **[vLLM](https://github.com/vllm-project/vllm)** - GPU 가속 로컬 배포를 위한 고성능 LLM 추론 엔진
- **[Ollama](https://ollama.com/)** - 간편한 로컬 LLM 배포 및 관리 플랫폼

### 오픈소스 커뮤니티
AI 기반 로그 분석을 실용적으로 만들 수 있도록 기여해주신 오픈소스 커뮤니티와 수많은 프로젝트에 깊이 감사드립니다.