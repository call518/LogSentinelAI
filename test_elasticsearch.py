#!/usr/bin/env python3
"""
Elasticsearch 연결 및 기능 테스트 스크립트
"""

from commons import (
    get_elasticsearch_client, 
    create_elasticsearch_index_if_not_exists,
    format_and_send_to_elasticsearch,
    generate_log_hash,
    verify_log_hash,
    extract_log_content_from_logid_line
)

def test_hash_functions():
    """해시 기반 LOGID 함수들 테스트"""
    print("=== 해시 기반 LOGID 함수 테스트 ===")
    
    # 테스트 로그 라인
    test_log = "192.168.1.1 - - [22/Jan/2019:03:56:14 +0330] \"GET /test HTTP/1.1\" 200 1234"
    
    # 해시 생성 테스트
    logid = generate_log_hash(test_log)
    print(f"원본 로그: {test_log}")
    print(f"생성된 LOGID: {logid}")
    
    # LOGID 라인 생성
    logid_line = f"{logid} {test_log}"
    
    # 분리 테스트
    extracted_logid, extracted_content = extract_log_content_from_logid_line(logid_line)
    print(f"추출된 LOGID: {extracted_logid}")
    print(f"추출된 내용: {extracted_content}")
    
    # 검증 테스트
    is_valid = verify_log_hash(extracted_logid, extracted_content)
    print(f"해시 검증 결과: {'✅ 성공' if is_valid else '❌ 실패'}")
    
    # 동일한 로그는 동일한 해시 생성하는지 테스트
    logid2 = generate_log_hash(test_log)
    print(f"동일 로그 재해시: {logid2}")
    print(f"해시 일관성: {'✅ 성공' if logid == logid2 else '❌ 실패'}")
    
    return is_valid

def test_elasticsearch_connection():
    """Elasticsearch 연결 테스트"""
    print("=== Elasticsearch 연결 테스트 ===")
    client = get_elasticsearch_client()
    if client:
        print("✅ 연결 성공!")
        return True
    else:
        print("❌ 연결 실패!")
        return False

def test_index_creation():
    """인덱스 생성 테스트"""
    print("\n=== Elasticsearch 인덱스 생성 테스트 ===")
    success = create_elasticsearch_index_if_not_exists()
    if success:
        print("✅ 인덱스 생성/확인 성공!")
        return True
    else:
        print("❌ 인덱스 생성/확인 실패!")
        return False

def test_data_send():
    """테스트 데이터 전송"""
    print("\n=== 테스트 데이터 전송 ===")
    
    test_data = {
        "summary": "테스트 로그 분석 결과",
        "observations": ["테스트 관찰 사항 1", "테스트 관찰 사항 2"],
        "planning": ["테스트 계획 1", "테스트 계획 2"],
        "events": [],
        "highest_severity": "LOW",
        "requires_immediate_attention": False,
        "test_timestamp": "2025-07-15T08:00:00Z"
    }
    
    # 테스트 청크 생성 (해시 매핑 테스트용)
    test_chunk = [
        "LOGID-D5E8FBC59FED12345678901234567890 192.168.1.1 - - [22/Jan/2019:03:56:14 +0330] \"GET /test1 HTTP/1.1\" 200 1234",
        "LOGID-A1B2C3D4E5F612345678901234567890 192.168.1.2 - - [22/Jan/2019:03:56:15 +0330] \"GET /test2 HTTP/1.1\" 200 5678"
    ]
    
    success = format_and_send_to_elasticsearch(test_data, "test_log_type", 999, test_chunk)
    if success:
        print("✅ 테스트 데이터 전송 성공!")
        return True
    else:
        print("❌ 테스트 데이터 전송 실패!")
        return False

if __name__ == "__main__":
    print("🔍 Elasticsearch 및 해시 기반 LOGID 기능 테스트를 시작합니다...")
    
    # 0. 해시 함수 테스트
    if not test_hash_functions():
        print("\n❌ 해시 함수 테스트 실패!")
        exit(1)
    
    # 1. 연결 테스트
    if not test_elasticsearch_connection():
        print("\n❌ Elasticsearch가 실행되지 않았거나 설정이 잘못되었습니다.")
        print("다음을 확인해주세요:")
        print("- Elasticsearch가 http://localhost:9200에서 실행되고 있는지")
        print("- 사용자명/비밀번호가 elastic/changeme 인지")
        exit(1)
    
    # 2. 인덱스 생성 테스트
    test_index_creation()
    
    # 3. 데이터 전송 테스트
    test_data_send()
    
    print("\n🎉 모든 테스트 완료!")
