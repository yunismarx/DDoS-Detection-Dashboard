"""
Kafka Consumer for DDoS Detection
Consumes feature vectors from Kafka and performs real-time detection
"""

import json
import logging
import os
import sys
import signal
from typing import Dict, Optional
from kafka import KafkaConsumer
from kafka.errors import KafkaError
import requests

# Add project root to path to allow imports from service
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# Import shared logic
try:
    from service.detector_service import ModelLoader, DDosDetector, DetectionResult
except ImportError:
    # If running as script
    pass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DDosKafkaConsumer:
    """
    Kafka consumer for processing network features (HTTP Mode)
    Consumes from feature topic and uses Detector Service API
    """
    
    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        topic_features: str = "ids.features",
        group_id: str = "ids-detector-group",
        detection_url: str = "http://localhost:8000/detect"
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topic_features = topic_features
        self.group_id = group_id
        self.detection_url = detection_url
        self.running = False
        
        self.stats = {
            'messages_processed': 0,
            'attacks_detected': 0,
            'errors': 0
        }
        
        try:
            self.consumer = KafkaConsumer(
                topic_features,
                bootstrap_servers=bootstrap_servers,
                group_id=group_id,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                auto_offset_reset='latest',
                enable_auto_commit=True,
                max_poll_records=100
            )
            logger.info(f"✓ Kafka consumer connected: {bootstrap_servers}")
        except Exception as e:
            logger.error(f"Failed to create Kafka consumer: {e}")
            sys.exit(1)
    
    def process_message(self, message):
        try:
            data = message.value
            flow_key = data.get('flow_key')
            features = data.get('features')
            metadata = data.get('metadata', {})
            
            if not features:
                return
            
            # Send to detection service
            response = requests.post(
                self.detection_url,
                json={
                    "features": features,
                    "src_ip": metadata.get('src_ip', 'unknown'),
                    "dst_ip": metadata.get('dst_ip', 'unknown'),
                    "protocol": metadata.get('protocol', 'UNKNOWN')
                },
                timeout=2.0
            )
            
            if response.status_code == 200:
                result = response.json()
                self.stats['messages_processed'] += 1
                
                if result.get('is_attack'):
                    self.stats['attacks_detected'] += 1
                    logger.warning(
                        f"🚨 Attack: {flow_key} | Stage: {result.get('stage_detected')} | Conf: {result.get('confidence_score'):.2f}"
                    )

        except Exception as e:
            logger.error(f"Error processing message: {e}")
            self.stats['errors'] += 1
    
    def start_consuming(self):
        logger.info(f"Starting Consumer (HTTP Mode) -> {self.detection_url}")
        self.running = True
        try:
            for message in self.consumer:
                if not self.running: break
                self.process_message(message)
        except Exception as e:
            logger.error(f"Consumer error: {e}")
        finally:
            self.consumer.close()


class LocalDetectorConsumer:
    """
    Kafka consumer with Local Detection (Cascading Logic)
    Reuses DDosDetector class from service module to ensure consistency.
    """
    
    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        topic_features: str = "ids.features",
        group_id: str = "ids-local-detector",
        model_dir: str = "."
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topic_features = topic_features
        self.group_id = group_id
        self.model_dir = model_dir
        self.running = False
        
        self.stats = {
            'messages_processed': 0,
            'attacks_detected': 0
        }
        
        # Load Detector locally
        try:
            # Add service to path again just in case (already done at top)
            if BASE_DIR not in sys.path: sys.path.append(BASE_DIR)
            
            from service.detector_service import ModelLoader, DDosDetector
            
            loader = ModelLoader(model_dir)
            loader.load_all()
            self.detector = DDosDetector(loader)
            logger.info("✓ Local Detector (Cascading) initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Local Detector: {e}")
            sys.exit(1)
        
        # Create consumer
        try:
            self.consumer = KafkaConsumer(
                topic_features,
                bootstrap_servers=bootstrap_servers,
                group_id=group_id,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                auto_offset_reset='latest',
                enable_auto_commit=True,
                max_poll_records=500
            )
        except Exception as e:
            logger.error(f"Kafka connection failed: {e}")
            sys.exit(1)

    def start_consuming(self):
        logger.info("Starting Consumer (Local Cascading Mode)")
        self.running = True
        
        try:
            for message in self.consumer:
                if not self.running: break
                
                data = message.value
                features = data.get('features')
                flow_key = data.get('flow_key', 'unknown')
                
                if features:
                    # Use shared detector
                    result = self.detector.detect(features)
                    
                    self.stats['messages_processed'] += 1
                    
                    if result.is_attack:
                        self.stats['attacks_detected'] += 1
                        logger.warning(
                            f"🚨 Attack Detected (Local): {flow_key} | "
                            f"Stage: {result.stage_detected} | "
                            f"Conf: {result.confidence_score:.2f}"
                        )
                        
                        # Here we could produce to 'ids.alerts' topic if needed
                
                if self.stats['messages_processed'] % 1000 == 0:
                    logger.info(f"Processed: {self.stats['messages_processed']} | Attack Ratio: {self.stats['attacks_detected']/self.stats['messages_processed']:.1%}")

        except Exception as e:
            logger.error(f"Processing error: {e}")
        finally:
            self.consumer.close()

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Kafka Consumer for DDoS Detection")
    parser.add_argument('--mode', choices=['http', 'local'], default='http',
                       help='Detection mode: http (call service) or local (local model)')
    parser.add_argument('--bootstrap-servers', default='localhost:9092')
    parser.add_argument('--topic', default='ids.features')
    parser.add_argument('--group-id', default='ids-detector-group')
    parser.add_argument('--detection-url', default='http://localhost:8000/detect')
    parser.add_argument('--model-dir', default=os.path.join(BASE_DIR, 'models'))
    
    args = parser.parse_args()
    
    if args.mode == 'http':
        consumer = DDosKafkaConsumer(
            bootstrap_servers=args.bootstrap_servers,
            topic_features=args.topic,
            group_id=args.group_id,
            detection_url=args.detection_url
        )
    else:
        consumer = LocalDetectorConsumer(
            bootstrap_servers=args.bootstrap_servers,
            topic_features=args.topic,
            group_id=args.group_id,
            model_dir=args.model_dir
        )
    
    try:
        consumer.start_consuming()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
