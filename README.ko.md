[![PyPI에 태그로 배포](https://github.com/call518/LogSentinelAI/actions/workflows/pypi-publish.yml/badge.svg)](https://github.com/call518/LogSentinelAI/actions/workflows/pypi-publish.yml)

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/call518/LogSentinelAI)

# LogSentinelAI — 보안 이벤트, 시스템 오류, 이상 탐지를 위한 선언적 LLM 기반 로그 분석기

LogSentinelAI는 **Declarative Extraction (선언적 추출)** 방식으로 LLM을 활용하여 Apache, Linux 등 다양한 로그에서 보안 이벤트, 이상 징후, 오류를 분석하고, 이를 Elasticsearch/Kibana로 시각화 가능한 구조화 데이터로 변환합니다. 원하는 결과 구조를 Pydantic 클래스로 선언하기만 하면, AI가 자동으로 로그를 분석하여 해당 스키마에 맞는 JSON을 반환합니다. 복잡한 파싱 작업은 필요하지 않습니다.

## 주요 특징

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

## 시스템 아키텍처

![System Architecture](img/system-architecture.png)

- **Log Sources (로그 소스)**: 로컬 파일, 원격 SSH, HTTP 접근 로그, Apache 에러 로그, 시스템 로그, TCPDump 등 다양한 로그 소스로부터 데이터를 수집합니다.
- **LogSentinelAI Core (핵심 처리 모듈)**: 사용자 정의 스키마(Pydantic 모델)를 기반으로 로그 구조를 선언적으로 정의하면, LLM을 통해 해당 데이터를 자동으로 추출 및 구조화합니다. 추출된 결과는 Pydantic을 통해 유효성 검사를 거칩니다.
- **LLM Provider (LLM 공급자)**: OpenAI, vLLM, Ollama 등 다양한 외부 또는 로컬 LLM과 연동하여, 선언된 구조에 따라 로그를 해석하고 JSON 형태로 변환합니다.
- **Elasticsearch**: 구조화된 JSON, 원시 로그, 메타데이터를 Elasticsearch에 인덱싱하여 검색 및 상관 분석이 가능하도록 합니다.
- **Kibana**: Elasticsearch에 저장된 결과를 기반으로, 보안 이벤트 및 운영 현황에 대한 시각화와 대시보드를 제공합니다.

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

## JSON 출력 예시

![JSON Output](img/ex-json.png)

### CLI 명령 매핑

```bash
# CLI 명령은 분석기 스크립트에 매핑됨:
logsentinelai-httpd-access   → analyzers/httpd_access.py
logsentinelai-httpd-server   → analyzers/httpd_server.py  
logsentinelai-linux-system   → analyzers/linux_system.py
logsentinelai-geoip-download → utils/geoip_downloader.py
```

### 샘플 로그 미리보기

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

#### Apache Server 로그
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

### 공개 샘플 로그 추천

여러 로그 타입/포맷에 대해 더 폭넓게 테스트하려면 아래 공개 샘플 로그 저장소를 활용해 보세요.

- GitHub: https://github.com/SoftManiaTech/sample_log_files

LogSentinelAI와 함께 사용하는 방법:
- 저장소를 클론한 뒤, 분석 대상에 맞는 샘플 파일을 선택합니다
- 해당 파일 경로를 각 분석기 CLI에 `--log-path`로 전달합니다
- 일부 포맷은 현재 제공 분석기 스키마/프롬프트를 보강해야 할 수 있습니다

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