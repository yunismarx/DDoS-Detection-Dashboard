"""
Real-time Packet Capture for DDoS Detection
Captures network packets and sends to detection service
"""

import asyncio
import logging
import signal
import sys
from typing import Optional, Callable
from datetime import datetime
import requests
import json
import os


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Real-time packet capture and processing
    Requires root/admin privileges for live capture
    """
    
    def __init__(
        self,
        interface: str = "eth0",
        detection_url: str = "http://localhost:8000/detect",
        batch_size: int = 10,
        capture_filter: Optional[str] = None
    ):
        """
        Args:
            interface: Network interface to capture from
            detection_url: URL of detection service
            batch_size: Number of flows to batch before sending
            capture_filter: BPF filter for packet capture (e.g., "tcp port 80")
        """
        self.interface = interface
        self.detection_url = detection_url
        self.batch_size = batch_size
        self.capture_filter = capture_filter or "ip"
        self.running = False
        self.stats = {
            'packets_captured': 0,
            'flows_analyzed': 0,
            'attacks_detected': 0,
            'errors': 0
        }
        
        # Import feature extractor
        try:
            from extractor.feature_extractor import FlowFeatureExtractor, PacketParser
            self.extractor = FlowFeatureExtractor(window_size=100, timeout=60.0)
            self.parser = PacketParser()
        except ImportError:
            logger.error("Feature extractor module not found")
            sys.exit(1)
    
    def packet_handler(self, packet):
        """
        Process captured packet
        
        Args:
            packet: Scapy packet object
        """
        try:
            # Parse packet
            packet_info = self.parser.parse_scapy_packet(packet)
            
            if packet_info is None:
                return
            
            self.stats['packets_captured'] += 1
            
            # Update flow
            flow_key = self.extractor.update_flow(packet_info)
            
            # Extract features periodically
            if self.stats['packets_captured'] % self.batch_size == 0:
                self.process_flows()
            
            # Log progress
            if self.stats['packets_captured'] % 100 == 0:
                logger.info(
                    f"Captured: {self.stats['packets_captured']} packets, "
                    f"Analyzed: {self.stats['flows_analyzed']} flows, "
                    f"Attacks: {self.stats['attacks_detected']}"
                )
        
        except Exception as e:
            logger.error(f"Error handling packet: {e}")
            self.stats['errors'] += 1
    
    def process_flows(self):
        """
        Extract features from flows and send to detection service
        """
        try:
            # Get features for all active flows
            flow_features = self.extractor.get_all_flow_features()
            
            if not flow_features:
                return
            
            # Send to detection service
            for flow_key, features in flow_features:
                self.send_to_detector(flow_key, features)
                self.stats['flows_analyzed'] += 1
        
        except Exception as e:
            logger.error(f"Error processing flows: {e}")
            self.stats['errors'] += 1
    
    def send_to_detector(self, flow_key: str, features: dict):
        """
        Send features to detection service
        
        Args:
            flow_key: Unique flow identifier
            features: Feature dictionary
        """
        try:
            response = requests.post(
                self.detection_url,
                json={"features": features},
                timeout=2.0
            )
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('is_attack'):
                    self.stats['attacks_detected'] += 1
                    logger.warning(
                        f"🚨 ATTACK DETECTED - Flow: {flow_key[:50]}... "
                        f"Confidence: {result.get('confidence_score', 0):.2f} "
                        f"Class: {result.get('prediction_class')}"
                    )
                    
                    # Log detailed info for attacks
                    logger.info(f"Attack details: {json.dumps(result.get('ensemble_votes'), indent=2)}")
            
            else:
                logger.error(f"Detection service error: {response.status_code}")
        
        except requests.exceptions.Timeout:
            logger.warning("Detection service timeout")
        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to detection service")
        except Exception as e:
            logger.error(f"Error sending to detector: {e}")
    
    def start_capture(self):
        """
        Start packet capture
        Requires root privileges
        """
        try:
            from scapy.all import sniff
            
            logger.info(f"Starting packet capture on interface: {self.interface}")
            logger.info(f"Filter: {self.capture_filter}")
            logger.info(f"Detection service: {self.detection_url}")
            logger.info("Press Ctrl+C to stop")
            
            self.running = True
            
            # Start capture
            sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=self.packet_handler,
                store=False,
                stop_filter=lambda x: not self.running
            )
        
        except PermissionError:
            logger.error("Permission denied. Please run with sudo/admin privileges")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Capture error: {e}")
            sys.exit(1)
    
    def stop_capture(self):
        """Stop packet capture"""
        logger.info("Stopping capture...")
        self.running = False
        
        # Process remaining flows
        self.process_flows()
        
        # Print final stats
        logger.info("\n" + "="*60)
        logger.info("Final Statistics:")
        logger.info("="*60)
        for key, value in self.stats.items():
            logger.info(f"{key}: {value}")
        logger.info("="*60)


class FileCapture:
    """
    Capture from PCAP file for testing
    """
    
    def __init__(
        self,
        pcap_file: str,
        detection_url: str = "http://localhost:8000/detect",
        batch_size: int = 10
    ):
        """
        Args:
            pcap_file: Path to PCAP file
            detection_url: URL of detection service
            batch_size: Number of flows to batch
        """
        self.pcap_file = pcap_file
        self.detection_url = detection_url
        self.batch_size = batch_size
        self.stats = {
            'packets_processed': 0,
            'flows_analyzed': 0,
            'attacks_detected': 0
        }
        
        try:
            from extractor.feature_extractor import FlowFeatureExtractor, PacketParser
            self.extractor = FlowFeatureExtractor(window_size=100, timeout=60.0)
            self.parser = PacketParser()
        except ImportError:
            logger.error("Feature extractor module not found")
            sys.exit(1)
    
    def process_pcap(self):
        """
        Process PCAP file
        """
        try:
            from scapy.all import rdpcap
            
            logger.info(f"Reading PCAP file: {self.pcap_file}")
            packets = rdpcap(self.pcap_file)
            logger.info(f"Loaded {len(packets)} packets")
            
            for i, packet in enumerate(packets):
                packet_info = self.parser.parse_scapy_packet(packet)
                
                if packet_info:
                    self.extractor.update_flow(packet_info)
                    self.stats['packets_processed'] += 1
                
                # Process flows periodically
                if (i + 1) % self.batch_size == 0:
                    self._process_flows()
            
            # Process remaining flows
            self._process_flows()
            
            # Print stats
            logger.info("\n" + "="*60)
            logger.info("Processing Complete")
            logger.info("="*60)
            for key, value in self.stats.items():
                logger.info(f"{key}: {value}")
        
        except Exception as e:
            logger.error(f"Error processing PCAP: {e}")
    
    def _process_flows(self):
        """Process all flows and send to detector"""
        flow_features = self.extractor.get_all_flow_features()
        
        for flow_key, features in flow_features:
            try:
                response = requests.post(
                    self.detection_url,
                    json={"features": features},
                    timeout=2.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    self.stats['flows_analyzed'] += 1
                    
                    if result.get('is_attack'):
                        self.stats['attacks_detected'] += 1
                        logger.warning(
                            f"🚨 ATTACK - Flow: {flow_key[:40]}... "
                            f"Conf: {result.get('confidence_score', 0):.2f}"
                        )
            
            except Exception as e:
                logger.error(f"Detection error: {e}")


def signal_handler(signum, frame):
    """Handle interrupt signal"""
    logger.info("\nReceived interrupt signal")
    sys.exit(0)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Real-time DDoS Detection Packet Capture")
    parser.add_argument(
        '--mode',
        choices=['live', 'file'],
        default='live',
        help='Capture mode: live or from file'
    )
    parser.add_argument(
        '--interface',
        default='eth0',
        help='Network interface for live capture'
    )
    parser.add_argument(
        '--pcap-file',
        help='PCAP file path for file mode'
    )
    parser.add_argument(
        '--detection-url',
        default='http://localhost:8000/detect',
        help='Detection service URL'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=10,
        help='Batch size for flow processing'
    )
    parser.add_argument(
        '--filter',
        default='ip',
        help='BPF capture filter (e.g., "tcp port 80")'
    )
    
    args = parser.parse_args()
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    if args.mode == 'live':
        capture = PacketCapture(
            interface=args.interface,
            detection_url=args.detection_url,
            batch_size=args.batch_size,
            capture_filter=args.filter
        )
        
        try:
            capture.start_capture()
        except KeyboardInterrupt:
            capture.stop_capture()
    
    elif args.mode == 'file':
        if not args.pcap_file:
            logger.error("PCAP file required for file mode")
            sys.exit(1)
        
        if not os.path.exists(args.pcap_file):
            logger.error(f"PCAP file not found: {args.pcap_file}")
            sys.exit(1)
        
        capture = FileCapture(
            pcap_file=args.pcap_file,
            detection_url=args.detection_url,
            batch_size=args.batch_size
        )
        
        capture.process_pcap()


if __name__ == "__main__":
    main()
