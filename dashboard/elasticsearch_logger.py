"""
Elasticsearch Integration for DDoS Detection
Stores events for long-term analysis and Kibana visualization
"""

from elasticsearch import Elasticsearch, helpers
from typing import Dict, List, Optional
from datetime import datetime
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ElasticsearchLogger:
    """
    Log DDoS detection events to Elasticsearch
    Enables Kibana dashboards and long-term analysis
    """
    
    def __init__(
        self,
        hosts: List[str] = ["localhost:9200"],
        index_prefix: str = "ddos-detection",
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_ssl: bool = False
    ):
        """
        Args:
            hosts: List of Elasticsearch hosts
            index_prefix: Index name prefix (will append -YYYY.MM.DD)
            username: Optional username for authentication
            password: Optional password for authentication
            use_ssl: Use SSL/TLS connection
        """
        self.index_prefix = index_prefix
        
        # Connect to Elasticsearch
        try:
            if username and password:
                self.es = Elasticsearch(
                    hosts,
                    http_auth=(username, password),
                    use_ssl=use_ssl,
                    verify_certs=use_ssl
                )
            else:
                self.es = Elasticsearch(hosts)
            
            # Test connection
            if self.es.ping():
                logger.info(f"✓ Connected to Elasticsearch: {hosts}")
                self._create_index_template()
            else:
                logger.error("✗ Failed to connect to Elasticsearch")
        
        except Exception as e:
            logger.error(f"Elasticsearch connection error: {e}")
            self.es = None
    
    def _create_index_template(self):
        """Create index template for DDoS events"""
        template = {
            "index_patterns": [f"{self.index_prefix}-*"],
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1,
                "index": {
                    "refresh_interval": "5s"
                }
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "is_attack": {"type": "boolean"},
                    "confidence_score": {"type": "float"},
                    "prediction_class": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    
                    # Network details
                    "src_ip": {"type": "ip"},
                    "dst_ip": {"type": "ip"},
                    "src_port": {"type": "integer"},
                    "dst_port": {"type": "integer"},
                    "protocol": {"type": "keyword"},
                    
                    # Flow metrics
                    "flow_duration": {"type": "long"},
                    "total_fwd_packets": {"type": "integer"},
                    "total_bwd_packets": {"type": "integer"},
                    "total_packets": {"type": "integer"},
                    "flow_bytes_per_sec": {"type": "float"},
                    "flow_packets_per_sec": {"type": "float"},
                    
                    # Ensemble votes
                    "ensemble_votes": {
                        "properties": {
                            "random_forest": {"type": "integer"},
                            "kmeans": {"type": "integer"},
                            "signature": {"type": "integer"},
                            "total_votes": {"type": "integer"}
                        }
                    },
                    
                    # Geographic (if available)
                    "geo": {
                        "properties": {
                            "src_country": {"type": "keyword"},
                            "src_city": {"type": "keyword"},
                            "src_location": {"type": "geo_point"},
                            "dst_country": {"type": "keyword"},
                            "dst_city": {"type": "keyword"},
                            "dst_location": {"type": "geo_point"}
                        }
                    },
                    
                    # System metadata
                    "detector_id": {"type": "keyword"},
                    "version": {"type": "keyword"}
                }
            }
        }
        
        try:
            self.es.indices.put_template(
                name=f"{self.index_prefix}-template",
                body=template
            )
            logger.info("✓ Index template created")
        except Exception as e:
            logger.error(f"Failed to create template: {e}")
    
    def _get_index_name(self) -> str:
        """Get current index name with date"""
        return f"{self.index_prefix}-{datetime.now().strftime('%Y.%m.%d')}"
    
    def log_event(self, event: Dict):
        """
        Log single detection event
        
        Args:
            event: Detection event dictionary
        """
        if not self.es:
            logger.warning("Elasticsearch not connected")
            return
        
        try:
            # Prepare document
            doc = self._prepare_document(event)
            
            # Index document
            self.es.index(
                index=self._get_index_name(),
                body=doc
            )
            
            logger.debug(f"Event logged: {doc.get('timestamp')}")
        
        except Exception as e:
            logger.error(f"Failed to log event: {e}")
    
    def log_events_bulk(self, events: List[Dict]):
        """
        Log multiple events in bulk (more efficient)
        
        Args:
            events: List of detection events
        """
        if not self.es or not events:
            return
        
        try:
            # Prepare bulk actions
            actions = [
                {
                    "_index": self._get_index_name(),
                    "_source": self._prepare_document(event)
                }
                for event in events
            ]
            
            # Bulk index
            success, failed = helpers.bulk(self.es, actions, raise_on_error=False)
            logger.info(f"Bulk logged: {success} success, {len(failed)} failed")
        
        except Exception as e:
            logger.error(f"Bulk logging failed: {e}")
    
    def _prepare_document(self, event: Dict) -> Dict:
        """Prepare event for Elasticsearch"""
        doc = {
            'timestamp': event.get('timestamp', datetime.now().isoformat()),
            'is_attack': event.get('is_attack', False),
            'confidence_score': event.get('confidence_score', 0.0),
            'prediction_class': event.get('prediction_class', 'BENIGN'),
            'severity': event.get('severity', 'low'),
            
            # Network
            'src_ip': event.get('src_ip', '0.0.0.0'),
            'dst_ip': event.get('dst_ip', '0.0.0.0'),
            'src_port': event.get('src_port', 0),
            'dst_port': event.get('dst_port', 0),
            'protocol': event.get('protocol', 'TCP'),
            
            # Flow metrics
            'flow_duration': event.get('flow_duration', 0),
            'total_fwd_packets': event.get('total_fwd_packets', 0),
            'total_bwd_packets': event.get('total_bwd_packets', 0),
            'total_packets': event.get('total_packets', 0),
            'flow_bytes_per_sec': event.get('flow_bytes_per_sec', 0.0),
            'flow_packets_per_sec': event.get('flow_packets_per_sec', 0.0),
            
            # Ensemble
            'ensemble_votes': event.get('ensemble_votes', {}),
            
            # Metadata
            'detector_id': event.get('detector_id', 'default'),
            'version': event.get('version', '1.0')
        }
        
        return doc
    
    def query_attacks(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        min_confidence: float = 0.0,
        size: int = 100
    ) -> List[Dict]:
        """
        Query attack events with filters
        
        Args:
            start_time: Start time for query
            end_time: End time for query
            src_ip: Filter by source IP
            dst_ip: Filter by destination IP
            min_confidence: Minimum confidence score
            size: Maximum results to return
        
        Returns:
            List of matching events
        """
        if not self.es:
            return []
        
        # Build query
        must_conditions = [
            {"term": {"is_attack": True}},
            {"range": {"confidence_score": {"gte": min_confidence}}}
        ]
        
        if start_time or end_time:
            time_range = {}
            if start_time:
                time_range["gte"] = start_time.isoformat()
            if end_time:
                time_range["lte"] = end_time.isoformat()
            must_conditions.append({"range": {"timestamp": time_range}})
        
        if src_ip:
            must_conditions.append({"term": {"src_ip": src_ip}})
        
        if dst_ip:
            must_conditions.append({"term": {"dst_ip": dst_ip}})
        
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "sort": [{"timestamp": "desc"}],
            "size": size
        }
        
        try:
            result = self.es.search(
                index=f"{self.index_prefix}-*",
                body=query
            )
            
            return [hit["_source"] for hit in result["hits"]["hits"]]
        
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return []
    
    def get_attack_stats(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict:
        """
        Get attack statistics
        
        Returns:
            Dictionary with attack statistics
        """
        if not self.es:
            return {}
        
        time_filter = []
        if start_time or end_time:
            time_range = {}
            if start_time:
                time_range["gte"] = start_time.isoformat()
            if end_time:
                time_range["lte"] = end_time.isoformat()
            time_filter = [{"range": {"timestamp": time_range}}]
        
        query = {
            "query": {
                "bool": {
                    "filter": time_filter
                }
            },
            "aggs": {
                "total_events": {"value_count": {"field": "timestamp"}},
                "attack_count": {
                    "filter": {"term": {"is_attack": True}}
                },
                "top_sources": {
                    "filter": {"term": {"is_attack": True}},
                    "aggs": {
                        "ips": {
                            "terms": {"field": "src_ip", "size": 10}
                        }
                    }
                },
                "protocols": {
                    "filter": {"term": {"is_attack": True}},
                    "aggs": {
                        "types": {
                            "terms": {"field": "protocol"}
                        }
                    }
                },
                "avg_confidence": {
                    "filter": {"term": {"is_attack": True}},
                    "aggs": {
                        "score": {"avg": {"field": "confidence_score"}}
                    }
                }
            },
            "size": 0
        }
        
        try:
            result = self.es.search(
                index=f"{self.index_prefix}-*",
                body=query
            )
            
            aggs = result["aggregations"]
            
            return {
                "total_events": aggs["total_events"]["value"],
                "attack_count": aggs["attack_count"]["doc_count"],
                "top_sources": [
                    {"ip": bucket["key"], "count": bucket["doc_count"]}
                    for bucket in aggs["top_sources"]["ips"]["buckets"]
                ],
                "protocols": [
                    {"protocol": bucket["key"], "count": bucket["doc_count"]}
                    for bucket in aggs["protocols"]["types"]["buckets"]
                ],
                "avg_confidence": aggs["avg_confidence"]["score"]["value"]
            }
        
        except Exception as e:
            logger.error(f"Stats query failed: {e}")
            return {}
    
    def close(self):
        """Close Elasticsearch connection"""
        if self.es:
            self.es.close()
            logger.info("Elasticsearch connection closed")


# Example usage
if __name__ == "__main__":
    # Initialize logger
    es_logger = ElasticsearchLogger(
        hosts=["localhost:9200"],
        index_prefix="ddos-detection"
    )
    
    # Sample event
    event = {
        'timestamp': datetime.now().isoformat(),
        'is_attack': True,
        'confidence_score': 0.95,
        'prediction_class': 'DDoS',
        'severity': 'high',
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'protocol': 'TCP',
        'flow_duration': 5000,
        'total_packets': 1500,
        'flow_bytes_per_sec': 2000000,
        'ensemble_votes': {
            'random_forest': 1,
            'kmeans': 1,
            'signature': 1,
            'total_votes': 3
        }
    }
    
    # Log event
    es_logger.log_event(event)
    
    # Query attacks
    attacks = es_logger.query_attacks(min_confidence=0.8, size=10)
    print(f"Found {len(attacks)} attacks")
    
    # Get statistics
    stats = es_logger.get_attack_stats()
    print(f"Attack statistics: {json.dumps(stats, indent=2)}")
    
    # Close
    es_logger.close()
