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
from .utils import get_host_metadata
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
