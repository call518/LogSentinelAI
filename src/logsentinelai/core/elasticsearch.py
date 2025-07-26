"""
Elasticsearch integration module
Handles connection, indexing, and data transmission to Elasticsearch
"""
import datetime
from typing import Dict, Any, Optional
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, RequestError
from .config import ELASTICSEARCH_HOST, ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD, ELASTICSEARCH_INDEX

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
            print(f"✅ Elasticsearch connection successful: {ELASTICSEARCH_HOST}")
            return client
        else:
            print(f"❌ Elasticsearch ping failed: {ELASTICSEARCH_HOST}")
            return None
            
    except ConnectionError as e:
        print(f"❌ Elasticsearch connection error: {e}")
        return None
    except Exception as e:
        print(f"❌ Elasticsearch client creation error: {e}")
        return None

def send_to_elasticsearch_raw(data: Dict[str, Any], log_type: str, chunk_id: Optional[int] = None) -> bool:
    """
    Send analysis results to Elasticsearch.
    
    Args:
        data: Analysis data to send (JSON format)
        log_type: Log type ("httpd_access", "httpd_apache_error", "linux_system")
        chunk_id: Chunk number (optional)
    
    Returns:
        bool: Whether transmission was successful
    """
    client = get_elasticsearch_client()
    if not client:
        return False
    
    try:
        # Generate document identification ID
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        doc_id = f"{log_type}_{timestamp}"
        if chunk_id is not None:
            doc_id += f"_chunk_{chunk_id}"
        
        # Add metadata
        enriched_data = {
            **data,
            "@timestamp": datetime.datetime.utcnow().isoformat(),
            "@log_type": log_type,
            "@document_id": doc_id
        }
        
        # Index document in Elasticsearch
        response = client.index(
            index=ELASTICSEARCH_INDEX,
            id=doc_id,
            document=enriched_data
        )
        
        if response.get('result') in ['created', 'updated']:
            print(f"✅ Elasticsearch transmission successful: {doc_id}")
            return True
        else:
            print(f"❌ Elasticsearch transmission failed: {response}")
            return False
    
    except RequestError as e:
        print(f"❌ Elasticsearch request error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error occurred during Elasticsearch transmission: {e}")
        return False
