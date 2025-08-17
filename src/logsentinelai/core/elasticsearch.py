"""
Elasticsearch integration module
Handles connection, indexing, and data transmission to Elasticsearch
"""
import datetime
import json
from typing import Dict, Any, Optional
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, RequestError
from rich import print_json

from .config import ELASTICSEARCH_HOST, ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD, ELASTICSEARCH_INDEX
from .commons import setup_logger, LOG_LEVEL
from ..utils.general import get_host_metadata
import logging

logger = setup_logger("logsentinelai.elasticsearch", LOG_LEVEL)

def get_elasticsearch_client() -> Optional[Elasticsearch]:
    """
    Create an Elasticsearch client and test the connection.
    
    Returns:
        Elasticsearch: Connected client object or None (on connection failure)
    """
    try:
        client = Elasticsearch(
            [ELASTICSEARCH_HOST],
            basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD),
            verify_certs=False,
            ssl_show_warn=False
        )
        if client.ping():
            logger.info(f"Elasticsearch connection successful: {ELASTICSEARCH_HOST}")
            return client
        else:
            logger.error(f"Elasticsearch ping failed: {ELASTICSEARCH_HOST}")
            return None
    except ConnectionError as e:
        logger.error(f"Elasticsearch connection error: {e}")
        return None
    except Exception as e:
        logger.error(f"Elasticsearch client creation error: {e}")
        return None

def send_to_elasticsearch_raw(data: Dict[str, Any], log_type: str, chunk_id: Optional[int] = None) -> bool:
    """
    Send analysis results to Elasticsearch.
    
    Args:
        data: Analysis data to send (JSON format)
        log_type: Log type ("httpd_access", "httpd_server", "linux_system")
        chunk_id: Chunk number (optional)
    
    Returns:
        bool: Whether transmission was successful
    """
    
    logger.debug(f"send_to_elasticsearch_raw called with log_type={log_type}, chunk_id={chunk_id}")
    print(f"[ES][DEBUG] send_to_elasticsearch_raw called with log_type={log_type}, chunk_id={chunk_id}")
    
    try:
        # Generate document identification ID
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        doc_id = f"{log_type}_{timestamp}"
        if chunk_id is not None:
            doc_id += f"_chunk_{chunk_id}"

        # Add metadata
        host_metadata = get_host_metadata()
        enriched_data = {
            **data,
            "@timestamp": datetime.datetime.utcnow().isoformat(),
            "@log_type": log_type,
            "@document_id": doc_id,
            **host_metadata
        }

        # --- Telegram Alert: CRITICAL events OR processing failure ---
        print(f"[TELEGRAM][DEBUG] Checking events for CRITICAL severity and processing result...")
        try:
            from .telegram_alert import send_telegram_alert
            events = enriched_data.get("events")
            processing_result = enriched_data.get("@processing_result", "unknown")
            
            print(f"[TELEGRAM][DEBUG] Found {len(events) if events else 0} events, processing_result: {processing_result}")
            
            # 알림 조건 체크: CRITICAL 이벤트 OR 처리 실패
            has_critical = events and any(str(e.get("severity", "")).upper() == "CRITICAL" for e in events)
            has_failure = processing_result != "success"
            
            if has_critical or has_failure:
                # 알림 타입에 따른 로깅 및 메시지 준비
                if has_critical and has_failure:
                    alert_type = "CRITICAL EVENTS + PROCESSING FAILURE"
                    logger.info(f"[TELEGRAM] CRITICAL events AND processing failure detected in chunk {chunk_id}")
                elif has_critical:
                    alert_type = "CRITICAL EVENTS"
                    logger.info(f"[TELEGRAM] CRITICAL event(s) detected in chunk {chunk_id}")
                else:  # has_failure
                    alert_type = "PROCESSING FAILURE"
                    logger.info(f"[TELEGRAM] Processing failure detected in chunk {chunk_id}")
                
                print(f"[TELEGRAM][DEBUG] Alert type: {alert_type}")
                
                # 청크 전체 정보를 가독성 좋게 포맷팅 (1번만)
                msg_lines = []
                msg_lines.append(f"🚨 [{alert_type}] 🚨")
                msg_lines.append(f"   • Log Type: {log_type}")
                msg_lines.append(f"   • Document ID: {enriched_data.get('@document_id', 'N/A')}")
                msg_lines.append(f"   • Timestamp: {enriched_data.get('@timestamp', 'N/A')}")
                msg_lines.append(f"   • Analysis Time: {enriched_data.get('@chunk_analysis_elapsed_time', 'N/A')}s")
                msg_lines.append(f"   • Host: {enriched_data.get('@host', {}).get('hostname', 'N/A')}")
                msg_lines.append("")
                
                # 처리 실패인 경우 에러 정보 표시
                if has_failure:
                    error_type = enriched_data.get("@error_type", "unknown_error")
                    error_message = enriched_data.get("@error_message", "No error message")
                    msg_lines.append("❌ Processing Failure:")
                    msg_lines.append(f"   • Error Type: {error_type}")
                    msg_lines.append(f"   • Error Message: {error_message}")
                    msg_lines.append("")
                    
                    # 실패 시에도 전체 메타데이터 표시
                    msg_lines.append("🔍 Complete Processing Metadata:")
                    msg_lines.append(f"   • Chunk ID: {enriched_data.get('@chunk_id', 'N/A')}")
                    msg_lines.append(f"   • Log Count: {enriched_data.get('@log_count', 'N/A')}")
                    msg_lines.append(f"   • Processing Mode: {enriched_data.get('@processing_mode', 'N/A')}")
                    msg_lines.append(f"   • LLM Provider: {enriched_data.get('@llm_provider', 'N/A')}")
                    msg_lines.append(f"   • LLM Model: {enriched_data.get('@llm_model', 'N/A')}")
                    msg_lines.append(f"   • Log Path: {enriched_data.get('@log_path', 'N/A')}")
                    msg_lines.append(f"   • Analysis Start: {enriched_data.get('@chunk_analysis_start_utc', 'N/A')}")
                    msg_lines.append(f"   • Analysis End: {enriched_data.get('@chunk_analysis_end_utc', 'N/A')}")
                    msg_lines.append("")
                
                # 요약 (성공한 경우에만)
                if not has_failure:
                    summary = enriched_data.get("summary", "No summary")
                    msg_lines.append(f"📋 Summary: {summary}")
                    msg_lines.append("")
                
                # CRITICAL 이벤트들만 표시 (이벤트가 있는 경우에만)
                if has_critical and events:
                    critical_events = [e for e in events if str(e.get("severity", "")).upper() == "CRITICAL"]
                    msg_lines.append(f"🔴 Critical Events ({len(critical_events)}):")
                    
                    # 최대 3개까지만 표시
                    displayed_events = critical_events[:3]
                    for i, evt in enumerate(displayed_events, 1):
                        msg_lines.append(f"{i}. {evt.get('event_type', 'Unknown')}")
                        msg_lines.append(f"   • {evt.get('description', 'No description')}")
                        if evt.get('recommended_actions'):
                            actions = evt.get('recommended_actions')[:3]  # 액션은 3개까지만
                            for action in actions:
                                msg_lines.append(f"   ➤ {action}")
                        msg_lines.append("")  # CRITICAL 이벤트 간 구분을 위한 빈 줄
                    
                    # 3개 초과 시 생략 안내 메시지
                    if len(critical_events) > 3:
                        omitted_count = len(critical_events) - 3
                        msg_lines.append(f"   ... and {omitted_count} more CRITICAL event(s) omitted (check ES/Kibana for full details)")
                        msg_lines.append("")
                    msg_lines.append("")
                    
                    # 전체 이벤트 요약 (모든 severity 포함)
                    all_severities = {}
                    for evt in events:
                        sev = evt.get('severity', 'UNKNOWN')
                        all_severities[sev] = all_severities.get(sev, 0) + 1
                    
                    msg_lines.append(f"📊 All Events Summary ({len(events)} total):")
                    for sev, count in sorted(all_severities.items()):
                        msg_lines.append(f"   • {sev}: {count}")
                    msg_lines.append("")
                    
                    # 통계
                    stats = enriched_data.get("statistics", {})
                    if stats:
                        msg_lines.append("📊 Statistics:")
                        for key, value in list(stats.items())[:3]:  # 최대 3개 통계
                            msg_lines.append(f"   • {key}: {value}")
                        msg_lines.append("")
                    
                    # ES/Kibana 조회를 위한 메타데이터 정보 (@ 필드들)
                    msg_lines.append("🔍 ES/Kibana Metadata:")
                    msg_lines.append(f"   • Index: {ELASTICSEARCH_INDEX}")
                    for key, value in enriched_data.items():
                        if key.startswith("@"):
                            # @host 같은 dict는 특별 처리
                            if isinstance(value, dict):
                                msg_lines.append(f"   • {key}: {json.dumps(value, separators=(',', ':'))}")
                            # 리스트는 간단하게 표시
                            elif isinstance(value, list):
                                msg_lines.append(f"   • {key}: {json.dumps(value, separators=(',', ':'))}")
                            else:
                                msg_lines.append(f"   • {key}: {value}")
                    
                    msg = "\n".join(msg_lines)
                    
                    # 텔레그램 메시지 길이 제한 (4096자) 체크
                    if len(msg) > 4000:
                        msg = msg[:3990] + "\n...(truncated)"
                    try:
                        send_telegram_alert(msg)
                        if has_critical and has_failure:
                            logger.info(f"[TELEGRAM] Alert sent successfully: {alert_type} for chunk {chunk_id}")
                        elif has_critical:
                            critical_events = [e for e in events if str(e.get("severity", "")).upper() == "CRITICAL"]
                            logger.info(f"[TELEGRAM] Alert sent successfully: {alert_type} for chunk {chunk_id} ({len(critical_events)} events)")
                        else:
                            logger.info(f"[TELEGRAM] Alert sent successfully: {alert_type} for chunk {chunk_id}")
                        print(f"[TELEGRAM][DEBUG] ✅ Alert sent: {alert_type}")
                    except Exception as e:
                        logger.error(f"[TELEGRAM] Failed to send alert for chunk {chunk_id}: {e}")
                        print(f"[TELEGRAM][ERROR] ❌ Failed to send alert: {e}")
                else:
                    logger.debug(f"[TELEGRAM] No alert conditions met for chunk {chunk_id} (no CRITICAL events and processing_result={processing_result})")
                    print(f"[TELEGRAM][DEBUG] No alert conditions met (no CRITICAL events, processing_result={processing_result})")
        except ImportError:
            print("[TELEGRAM][ERROR] telegram_alert import failed!")
            pass
        # --- END Telegram Alert ---

        # Print final ES input data (콘솔)
        print("\n✅ [Final ES Input JSON]")
        print("-" * 30)
        print_json(json.dumps(enriched_data, ensure_ascii=False, indent=2))
        print()
        
        # DEBUG 레벨에서 ES 전송 직전 최종 JSON 로깅 (더 상세한 정보 포함)
        logger.debug(f"ES transmission for chunk {chunk_id} - Document ID: {doc_id}")
        logger.debug(f"Final ES JSON data (chunk {chunk_id}):\n{json.dumps(enriched_data, ensure_ascii=False, indent=2)}")

        # Get Elasticsearch client
        client = get_elasticsearch_client()
        if not client:
            logger.error(f"Elasticsearch client not available.")
            return False

        # Index document in Elasticsearch
        response = client.index(
            index=ELASTICSEARCH_INDEX,
            id=doc_id,
            document=enriched_data
        )

        # Check response status (콘솔)
        print(f"✅ Sending data to Elasticsearch index '{ELASTICSEARCH_INDEX}' with ID '{doc_id}'")
        if response.get('result') in ['created', 'updated']:
            print(f"✅ Elasticsearch transmission successful: {doc_id}")
            logger.info(f"Elasticsearch transmission successful: {doc_id}")
            return True
        else:
            print(f"❌ Elasticsearch transmission failed: {response}")
            logger.error(f"Elasticsearch transmission failed: {response}")
            return False

    except RequestError as e:
        print(f"❌ Elasticsearch request error: {e}")
        logger.error(f"Elasticsearch request error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error occurred during Elasticsearch transmission: {e}")
        logger.exception(f"Error occurred during Elasticsearch transmission: {e}")
        return False
