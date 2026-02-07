"""
Feature Extractor for Real-time Network Traffic
Converts raw packets into feature vectors compatible with trained model
"""

import numpy as np
import pandas as pd
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FlowFeatureExtractor:
    """
    Extract features from network flows for DDoS detection
    Maintains sliding window of packets and computes statistical features
    """
    
    def __init__(self, window_size: int = 100, timeout: float = 60.0):
        """
        Args:
            window_size: Number of packets in sliding window
            timeout: Flow timeout in seconds
        """
        self.window_size = window_size
        self.timeout = timeout
        self.flows = defaultdict(lambda: {
            'packets': deque(maxlen=window_size),
            'start_time': None,
            'last_seen': None,
            'fwd_packets': [],
            'bwd_packets': [],
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'flags': defaultdict(int),
            'iat_fwd': [],  # Inter-arrival time forward
            'iat_bwd': [],  # Inter-arrival time backward
        })
        
    def get_flow_key(self, packet_info: Dict) -> str:
        """Generate unique flow identifier"""
        src_ip = packet_info.get('src_ip', '0.0.0.0')
        dst_ip = packet_info.get('dst_ip', '0.0.0.0')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol = packet_info.get('protocol', 'TCP')
        
        # Create bidirectional flow key
        if src_ip < dst_ip:
            key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            direction = 'fwd'
        else:
            key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            direction = 'bwd'
            
        return key, direction
    
    def clean_stale_flows(self):
        """Remove flows that have timed out"""
        current_time = datetime.now()
        stale_flows = []
        
        for flow_key, flow_data in self.flows.items():
            if flow_data['last_seen']:
                age = (current_time - flow_data['last_seen']).total_seconds()
                if age > self.timeout:
                    stale_flows.append(flow_key)
        
        for flow_key in stale_flows:
            del self.flows[flow_key]
            
        if stale_flows:
            logger.debug(f"Cleaned {len(stale_flows)} stale flows")
    
    def update_flow(self, packet_info: Dict) -> str:
        """
        Update flow with new packet
        
        Args:
            packet_info: Dictionary containing packet information:
                - timestamp: packet timestamp
                - src_ip, dst_ip: IP addresses
                - src_port, dst_port: port numbers
                - length: packet length
                - protocol: TCP/UDP/ICMP
                - flags: TCP flags (if TCP)
        
        Returns:
            flow_key: Unique flow identifier
        """
        flow_key, direction = self.get_flow_key(packet_info)
        flow = self.flows[flow_key]
        
        timestamp = packet_info.get('timestamp', datetime.now())
        length = packet_info.get('length', 0)
        
        # Initialize flow if new
        if flow['start_time'] is None:
            flow['start_time'] = timestamp
        
        # Calculate inter-arrival time
        if flow['last_seen']:
            iat = (timestamp - flow['last_seen']).total_seconds() * 1000000  # microseconds
            if direction == 'fwd':
                flow['iat_fwd'].append(iat)
            else:
                flow['iat_bwd'].append(iat)
        
        flow['last_seen'] = timestamp
        
        # Add packet to flow
        flow['packets'].append({
            'timestamp': timestamp,
            'length': length,
            'direction': direction,
            'flags': packet_info.get('flags', {})
        })
        
        # Update direction-specific counters
        if direction == 'fwd':
            flow['fwd_packets'].append(length)
            flow['fwd_bytes'] += length
        else:
            flow['bwd_packets'].append(length)
            flow['bwd_bytes'] += length
        
        # Update TCP flags
        if packet_info.get('protocol') == 'TCP':
            flags = packet_info.get('flags', {})
            for flag, value in flags.items():
                if value:
                    flow['flags'][flag] += 1
        
        return flow_key
    
    def extract_features(self, flow_key: str) -> Dict[str, float]:
        """
        Extract all features for a flow
        
        Returns dictionary with feature names matching training data
        """
        if flow_key not in self.flows:
            return {}
        
        flow = self.flows[flow_key]
        packets = list(flow['packets'])
        
        if not packets:
            return {}
        
        # Calculate flow duration (microseconds)
        duration = 0
        if flow['start_time'] and flow['last_seen']:
            duration = (flow['last_seen'] - flow['start_time']).total_seconds() * 1000000
        
        # Packet counts
        total_fwd = len(flow['fwd_packets'])
        total_bwd = len(flow['bwd_packets'])
        total_packets = total_fwd + total_bwd
        
        # Byte counts
        fwd_bytes = flow['fwd_bytes']
        bwd_bytes = flow['bwd_bytes']
        total_bytes = fwd_bytes + bwd_bytes
        
        # Packet lengths
        fwd_lengths = flow['fwd_packets'] if flow['fwd_packets'] else [0]
        bwd_lengths = flow['bwd_packets'] if flow['bwd_packets'] else [0]
        all_lengths = fwd_lengths + bwd_lengths
        
        # Inter-arrival times
        iat_fwd = flow['iat_fwd'] if flow['iat_fwd'] else [0]
        iat_bwd = flow['iat_bwd'] if flow['iat_bwd'] else [0]
        all_iat = iat_fwd + iat_bwd
        
        # Calculate rates (avoid division by zero)
        duration_sec = max(duration / 1000000, 0.000001)
        flow_bytes_per_s = total_bytes / duration_sec
        flow_packets_per_s = total_packets / duration_sec
        
        # Build feature dictionary
        features = {
            # Flow basics
            'Flow Duration': duration,
            'Total Fwd Packets': total_fwd,
            'Total Backward Packets': total_bwd,
            
            # Packet lengths
            'Total Length of Fwd Packets': sum(fwd_lengths),
            'Total Length of Bwd Packets': sum(bwd_lengths),
            'Fwd Packet Length Max': max(fwd_lengths),
            'Fwd Packet Length Min': min(fwd_lengths),
            'Fwd Packet Length Mean': np.mean(fwd_lengths),
            'Fwd Packet Length Std': np.std(fwd_lengths),
            'Bwd Packet Length Max': max(bwd_lengths),
            'Bwd Packet Length Min': min(bwd_lengths),
            'Bwd Packet Length Mean': np.mean(bwd_lengths),
            'Bwd Packet Length Std': np.std(bwd_lengths),
            
            # Flow rates
            'Flow Bytes/s': flow_bytes_per_s,
            'Flow Packets/s': flow_packets_per_s,
            'Flow IAT Mean': np.mean(all_iat),
            'Flow IAT Std': np.std(all_iat),
            'Flow IAT Max': max(all_iat),
            'Flow IAT Min': min(all_iat),
            
            # Forward IAT
            'Fwd IAT Total': sum(iat_fwd),
            'Fwd IAT Mean': np.mean(iat_fwd),
            'Fwd IAT Std': np.std(iat_fwd),
            'Fwd IAT Max': max(iat_fwd),
            'Fwd IAT Min': min(iat_fwd),
            
            # Backward IAT
            'Bwd IAT Total': sum(iat_bwd),
            'Bwd IAT Mean': np.mean(iat_bwd),
            'Bwd IAT Std': np.std(iat_bwd),
            'Bwd IAT Max': max(iat_bwd),
            'Bwd IAT Min': min(iat_bwd),
            
            # TCP Flags
            'FIN Flag Count': flow['flags'].get('FIN', 0),
            'SYN Flag Count': flow['flags'].get('SYN', 0),
            'RST Flag Count': flow['flags'].get('RST', 0),
            'PSH Flag Count': flow['flags'].get('PSH', 0),
            'ACK Flag Count': flow['flags'].get('ACK', 0),
            'URG Flag Count': flow['flags'].get('URG', 0),
            'CWE Flag Count': flow['flags'].get('CWE', 0),
            'ECE Flag Count': flow['flags'].get('ECE', 0),
            
            # Packet size stats
            'Min Packet Length': min(all_lengths),
            'Max Packet Length': max(all_lengths),
            'Packet Length Mean': np.mean(all_lengths),
            'Packet Length Std': np.std(all_lengths),
            'Packet Length Variance': np.var(all_lengths),
            
            # Advanced features
            'Down/Up Ratio': bwd_bytes / max(fwd_bytes, 1),
            'Average Packet Size': total_bytes / max(total_packets, 1),
            'Avg Fwd Segment Size': sum(fwd_lengths) / max(total_fwd, 1),
            'Avg Bwd Segment Size': sum(bwd_lengths) / max(total_bwd, 1),
            
            # Bulk features (simplified)
            'Fwd Avg Bytes/Bulk': sum(fwd_lengths) / max(len(fwd_lengths), 1),
            'Fwd Avg Packets/Bulk': len(fwd_lengths),
            'Fwd Avg Bulk Rate': len(fwd_lengths) / duration_sec,
            'Bwd Avg Bytes/Bulk': sum(bwd_lengths) / max(len(bwd_lengths), 1),
            'Bwd Avg Packets/Bulk': len(bwd_lengths),
            'Bwd Avg Bulk Rate': len(bwd_lengths) / duration_sec,
            
            # Subflow features (simplified for single flow)
            'Subflow Fwd Packets': total_fwd,
            'Subflow Fwd Bytes': fwd_bytes,
            'Subflow Bwd Packets': total_bwd,
            'Subflow Bwd Bytes': bwd_bytes,
            
            # Init window features (first 10 packets)
            'Init_Win_bytes_forward': sum(fwd_lengths[:10]) if len(fwd_lengths) >= 10 else sum(fwd_lengths),
            'Init_Win_bytes_backward': sum(bwd_lengths[:10]) if len(bwd_lengths) >= 10 else sum(bwd_lengths),
            
            # Active/Idle time (simplified)
            'Active Mean': duration / max(total_packets, 1),
            'Active Std': 0,  # Simplified
            'Active Max': duration,
            'Active Min': 0,
            'Idle Mean': 0,  # Simplified
            'Idle Std': 0,
            'Idle Max': 0,
            'Idle Min': 0,
        }
        
        return features
    
    def get_all_flow_features(self) -> List[Tuple[str, Dict[str, float]]]:
        """
        Extract features for all active flows
        
        Returns:
            List of (flow_key, features) tuples
        """
        self.clean_stale_flows()
        
        results = []
        for flow_key in list(self.flows.keys()):
            features = self.extract_features(flow_key)
            if features:
                results.append((flow_key, features))
        
        return results


class PacketParser:
    """
    Parse raw packet data into structured format
    Compatible with scapy and pyshark
    """
    
    @staticmethod
    def parse_scapy_packet(packet) -> Optional[Dict]:
        """
        Parse scapy packet into standard format
        
        Args:
            packet: Scapy packet object
        
        Returns:
            Dictionary with packet information
        """
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            
            packet_info = {
                'timestamp': datetime.now(),
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'length': len(packet),
                'protocol': None,
                'src_port': 0,
                'dst_port': 0,
                'flags': {}
            }
            
            # TCP
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = tcp.sport
                packet_info['dst_port'] = tcp.dport
                packet_info['flags'] = {
                    'FIN': bool(tcp.flags & 0x01),
                    'SYN': bool(tcp.flags & 0x02),
                    'RST': bool(tcp.flags & 0x04),
                    'PSH': bool(tcp.flags & 0x08),
                    'ACK': bool(tcp.flags & 0x10),
                    'URG': bool(tcp.flags & 0x20),
                    'ECE': bool(tcp.flags & 0x40),
                    'CWE': bool(tcp.flags & 0x80),
                }
            
            # UDP
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = udp.sport
                packet_info['dst_port'] = udp.dport
            
            # ICMP
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
            
            return packet_info
            
        except Exception as e:
            logger.error(f"Error parsing scapy packet: {e}")
            return None
    
    @staticmethod
    def parse_pyshark_packet(packet) -> Optional[Dict]:
        """
        Parse pyshark packet into standard format
        
        Args:
            packet: Pyshark packet object
        
        Returns:
            Dictionary with packet information
        """
        try:
            if not hasattr(packet, 'ip'):
                return None
            
            packet_info = {
                'timestamp': datetime.fromtimestamp(float(packet.sniff_timestamp)),
                'src_ip': packet.ip.src,
                'dst_ip': packet.ip.dst,
                'length': int(packet.length),
                'protocol': packet.transport_layer,
                'src_port': 0,
                'dst_port': 0,
                'flags': {}
            }
            
            # TCP
            if hasattr(packet, 'tcp'):
                packet_info['src_port'] = int(packet.tcp.srcport)
                packet_info['dst_port'] = int(packet.tcp.dstport)
                flags = int(packet.tcp.flags, 16)
                packet_info['flags'] = {
                    'FIN': bool(flags & 0x01),
                    'SYN': bool(flags & 0x02),
                    'RST': bool(flags & 0x04),
                    'PSH': bool(flags & 0x08),
                    'ACK': bool(flags & 0x10),
                    'URG': bool(flags & 0x20),
                    'ECE': bool(flags & 0x40),
                    'CWE': bool(flags & 0x80),
                }
            
            # UDP
            elif hasattr(packet, 'udp'):
                packet_info['src_port'] = int(packet.udp.srcport)
                packet_info['dst_port'] = int(packet.udp.dstport)
            
            return packet_info
            
        except Exception as e:
            logger.error(f"Error parsing pyshark packet: {e}")
            return None


if __name__ == "__main__":
    # Example usage
    extractor = FlowFeatureExtractor(window_size=50)
    
    # Simulate some packets
    test_packets = [
        {
            'timestamp': datetime.now(),
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'src_port': 54321,
            'dst_port': 80,
            'length': 1500,
            'protocol': 'TCP',
            'flags': {'SYN': True, 'ACK': False}
        }
    ]
    
    for packet_info in test_packets:
        flow_key = extractor.update_flow(packet_info)
        features = extractor.extract_features(flow_key)
        print(f"Flow: {flow_key}")
        print(f"Features extracted: {len(features)}")
        print(f"Sample features: {list(features.items())[:5]}")
