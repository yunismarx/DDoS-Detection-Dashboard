"""
Kafka Producer for DDoS Detection
Streams packet features to Kafka topics for distributed processing
"""

import json
import logging
from typing import Dict, Optional
from datetime import datetime
from kafka import KafkaProducer
from kafka.errors import KafkaError
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DDosKafkaProducer:
    """
    Kafka producer for streaming network features
    """
    
    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        topic_features: str = "ids.features",
        topic_alerts: str = "ids.alerts",
        compression_type: str = "gzip"
    ):
        """
        Args:
            bootstrap_servers: Kafka broker addresses
            topic_features: Topic for feature vectors
            topic_alerts: Topic for detected attacks
            compression_type: Compression algorithm (gzip, snappy, lz4)
        """
        self.bootstrap_servers = bootstrap_servers
        self.topic_features = topic_features
        self.topic_alerts = topic_alerts
        
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                compression_type=compression_type,
                acks='all',  # Wait for all replicas
                retries=3,
                max_in_flight_requests_per_connection=1  # Ensure ordering
            )
            logger.info(f"✓ Kafka producer connected to {bootstrap_servers}")
        except Exception as e:
            logger.error(f"Failed to create Kafka producer: {e}")
            sys.exit(1)
    
    def send_features(self, flow_key: str, features: Dict[str, float], metadata: Optional[Dict] = None):
        """
        Send feature vector to Kafka
        
        Args:
            flow_key: Unique flow identifier
            features: Feature dictionary
            metadata: Additional metadata (src_ip, dst_ip, etc.)
        """
        try:
            message = {
                'flow_key': flow_key,
                'features': features,
                'timestamp': datetime.utcnow().isoformat(),
                'metadata': metadata or {}
            }
            
            future = self.producer.send(
                self.topic_features,
                key=flow_key.encode('utf-8'),
                value=message
            )
            
            # Non-blocking - add callback
            future.add_callback(self._on_send_success)
            future.add_errback(self._on_send_error)
            
        except Exception as e:
            logger.error(f"Error sending features: {e}")
    
    def send_alert(self, flow_key: str, detection_result: Dict, severity: str = "high"):
        """
        Send attack alert to Kafka
        
        Args:
            flow_key: Flow identifier
            detection_result: Detection result from model
            severity: Alert severity (low, medium, high, critical)
        """
        try:
            alert = {
                'flow_key': flow_key,
                'detection_result': detection_result,
                'severity': severity,
                'timestamp': datetime.utcnow().isoformat(),
                'alert_id': f"alert_{datetime.utcnow().timestamp()}"
            }
            
            future = self.producer.send(
                self.topic_alerts,
                key=flow_key.encode('utf-8'),
                value=alert
            )
            
            future.add_callback(lambda _: logger.info(f"Alert sent: {alert['alert_id']}"))
            future.add_errback(self._on_send_error)
            
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
    
    def _on_send_success(self, record_metadata):
        """Callback for successful send"""
        logger.debug(
            f"Message sent: topic={record_metadata.topic}, "
            f"partition={record_metadata.partition}, "
            f"offset={record_metadata.offset}"
        )
    
    def _on_send_error(self, exc):
        """Callback for send error"""
        logger.error(f"Failed to send message: {exc}")
    
    def flush(self):
        """Flush pending messages"""
        self.producer.flush()
    
    def close(self):
        """Close producer"""
        logger.info("Closing Kafka producer...")
        self.producer.close()


class KafkaFeatureStreamer:
    """
    Stream network features to Kafka in real-time
    Integrates with packet capture
    """
    
    def __init__(
        self,
        kafka_producer: DDosKafkaProducer,
        interface: str = "eth0",
        batch_size: int = 10
    ):
        """
        Args:
            kafka_producer: Kafka producer instance
            interface: Network interface
            batch_size: Batch size for flow processing
        """
        self.producer = kafka_producer
        self.interface = interface
        self.batch_size = batch_size
        self.running = False
        
        try:
            from extractor.feature_extractor import FlowFeatureExtractor, PacketParser
            self.extractor = FlowFeatureExtractor(window_size=100, timeout=60.0)
            self.parser = PacketParser()
        except ImportError:
            logger.error("Feature extractor not found")
            sys.exit(1)
        
        self.stats = {
            'packets_captured': 0,
            'features_sent': 0
        }
    
    def packet_handler(self, packet):
        """Process captured packet"""
        try:
            packet_info = self.parser.parse_scapy_packet(packet)
            
            if packet_info is None:
                return
            
            self.stats['packets_captured'] += 1
            
            # Update flow
            flow_key = self.extractor.update_flow(packet_info)
            
            # Extract and send features periodically
            if self.stats['packets_captured'] % self.batch_size == 0:
                self._send_flow_features()
        
        except Exception as e:
            logger.error(f"Error handling packet: {e}")
    
    def _send_flow_features(self):
        """Extract features and send to Kafka"""
        flow_features = self.extractor.get_all_flow_features()
        
        for flow_key, features in flow_features:
            # Extract metadata from flow key
            parts = flow_key.split('-')
            src, dst = parts[0].split(':'), parts[1].split(':')
            
            metadata = {
                'src_ip': src[0] if len(src) > 0 else '',
                'src_port': src[1] if len(src) > 1 else '',
                'dst_ip': dst[0] if len(dst) > 0 else '',
                'dst_port': dst[1] if len(dst) > 1 else '',
                'protocol': parts[2] if len(parts) > 2 else ''
            }
            
            self.producer.send_features(flow_key, features, metadata)
            self.stats['features_sent'] += 1
    
    def start_streaming(self):
        """Start streaming features to Kafka"""
        try:
            from scapy.all import sniff
            
            logger.info(f"Starting Kafka feature streaming on {self.interface}")
            logger.info(f"Kafka topics: {self.producer.topic_features}, {self.producer.topic_alerts}")
            
            self.running = True
            
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                stop_filter=lambda x: not self.running
            )
        
        except PermissionError:
            logger.error("Permission denied. Run with sudo/admin privileges")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Streaming error: {e}")
            sys.exit(1)
    
    def stop_streaming(self):
        """Stop streaming"""
        logger.info("Stopping Kafka streaming...")
        self.running = False
        self._send_flow_features()  # Send remaining
        self.producer.flush()
        self.producer.close()
        
        logger.info(f"Stats: {self.stats}")


def main():
    """Main entry point"""
    import argparse
    import signal
    
    parser = argparse.ArgumentParser(description="Kafka Feature Streaming for DDoS Detection")
    parser.add_argument('--bootstrap-servers', default='localhost:9092')
    parser.add_argument('--topic-features', default='ids.features')
    parser.add_argument('--topic-alerts', default='ids.alerts')
    parser.add_argument('--interface', default='eth0')
    parser.add_argument('--batch-size', type=int, default=10)
    
    args = parser.parse_args()
    
    # Create producer
    producer = DDosKafkaProducer(
        bootstrap_servers=args.bootstrap_servers,
        topic_features=args.topic_features,
        topic_alerts=args.topic_alerts
    )
    
    # Create streamer
    streamer = KafkaFeatureStreamer(
        kafka_producer=producer,
        interface=args.interface,
        batch_size=args.batch_size
    )
    
    # Setup signal handler
    def signal_handler(signum, frame):
        streamer.stop_streaming()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start streaming
    try:
        streamer.start_streaming()
    except KeyboardInterrupt:
        streamer.stop_streaming()


if __name__ == "__main__":
    main()
