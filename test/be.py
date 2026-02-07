import json
import random
import time
from datetime import datetime
from urllib import request, error
import argparse

# Update the path if API is on a different port or path
API_URL = "http://localhost:8000/detect"


# ================== Helper Tools ==================

def random_ip(private=True):
    if private:
        return f"192.168.{random.randint(0, 254)}.{random.randint(1, 254)}"
    else:
        return f"{random.randint(20, 220)}.{random.randint(0, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}"


# ============== Build Features per Scenario ==============

def build_features(scenario: str) -> dict:


    if scenario == "benign":
        # Very normal traffic: Regular browsing
        # Based on real sample: Duration=3, Win=33, PktMean=6
        
        fwd_packets = random.randint(1, 10)
        bwd_packets = random.randint(0, 10)
        duration = random.randint(1, 2000) # Short flows
        
        # Small packet sizes (ACK/Handshake)
        fwd_mean = random.uniform(5, 100)
        bwd_mean = random.uniform(0, 100)

        return {
            "Flow Duration": duration,
            "Total Fwd Packets": fwd_packets,
            "Total Backward Packets": bwd_packets,
            "Total Length of Fwd Packets": int(fwd_packets * fwd_mean),
            "Total Length of Bwd Packets": int(bwd_packets * bwd_mean),
            "Fwd Packet Length Max": int(fwd_mean * 1.5),
            "Fwd Packet Length Min": int(fwd_mean * 0.5),
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": random.uniform(0, 20),
            "Flow Bytes/s": random.uniform(10, 5000),
            "Flow Packets/s": random.uniform(1, 1000),
            "ACK Flag Count": random.randint(0, 5),
            "SYN Flag Count": random.randint(0, 2),
            "FIN Flag Count": random.randint(0, 2),
            "RST Flag Count": 0,
            "Bwd Packets/s": random.uniform(0, 50),
            "Bwd Packet Length Mean": bwd_mean,
            "Down/Up Ratio": random.uniform(0, 1),
            "Idle Mean": 0,
            # Missing AE Features - Critical for correct classification
            "Init_Win_bytes_forward": random.choice([33, 8192, 29200, 65535]),
            "Fwd IAT Max": random.randint(0, duration), 
        }

    if scenario == "ddos":
        # DDoS / Flood – Very high traffic
        # to ensure detection as Signature or AutoencoderAnomaly
        fwd_packets = random.randint(3000, 20_000)
        bwd_packets = random.randint(100, 2000)
        duration = random.randint(100, 1000) # Short duration and many packets = Bursty
        fwd_mean = random.uniform(300, 800)
        bwd_mean = random.uniform(300, 800)

        return {
            "Flow Duration": duration,
            "Total Fwd Packets": fwd_packets,
            "Total Backward Packets": bwd_packets,
            "Total Length of Fwd Packets": int(fwd_packets * fwd_mean),
            "Total Length of Bwd Packets": int(bwd_packets * bwd_mean),
            "Fwd Packet Length Max": int(fwd_mean * random.uniform(1.2, 1.8)),
            "Fwd Packet Length Min": int(fwd_mean * random.uniform(0.5, 0.8)),
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": random.uniform(80, 200),
            "Flow Bytes/s": random.uniform(500_000, 5_000_000),
            "Flow Packets/s": random.uniform(10_000, 120_000),
            "ACK Flag Count": random.randint(100, 1000),
            "SYN Flag Count": random.randint(1000, 5000),
            "FIN Flag Count": random.randint(0, 100),
            "RST Flag Count": random.randint(0, 50),
            "Bwd Packets/s": random.uniform(1000, 10_000),
            "Bwd Packet Length Mean": bwd_mean,
            "Down/Up Ratio": random.uniform(0.2, 0.8),
            "Idle Mean": random.uniform(0, 800),
            # Missing AE Features
            "Init_Win_bytes_forward": random.randint(100, 1000), # Abnormal window
            "Fwd IAT Max": random.randint(1, 50), # Very fast IAT
        }

    if scenario == "port_scan":
        # Port Scan – High connection count, few bytes, limited response
        fwd_packets = random.randint(300, 2_000)
        bwd_packets = random.randint(0, 100)
        duration = random.randint(500, 5_000)
        fwd_mean = random.uniform(40, 120)
        bwd_mean = random.uniform(0, 80)

        return {
            "Flow Duration": duration,
            "Total Fwd Packets": fwd_packets,
            "Total Backward Packets": bwd_packets,
            "Total Length of Fwd Packets": int(fwd_packets * fwd_mean),
            "Total Length of Bwd Packets": int(bwd_packets * bwd_mean) if bwd_packets > 0 else 0,
            "Fwd Packet Length Max": int(fwd_mean * 1.5),
            "Fwd Packet Length Min": int(fwd_mean * 0.5),
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": random.uniform(10, 40),
            "Flow Bytes/s": random.uniform(1_000, 15_000),
            "Flow Packets/s": random.uniform(1_000, 6_000),
            "ACK Flag Count": random.randint(0, 50),
            "SYN Flag Count": random.randint(200, 1500),
            "FIN Flag Count": random.randint(0, 10),
            "RST Flag Count": random.randint(100, 800),
            "Bwd Packets/s": random.uniform(0, 100),
            "Bwd Packet Length Mean": bwd_mean,
            "Down/Up Ratio": random.uniform(0, 0.5),
            "Idle Mean": random.uniform(500, 5_000),
            # Missing AE Features
            "Init_Win_bytes_forward": random.randint(0, 500),
            "Fwd IAT Max": random.randint(10, 200),
        }

    if scenario == "bruteforce":
        # Brute Force – Repeated login attempts
        fwd_packets = random.randint(500, 3_000)
        bwd_packets = random.randint(500, 3_000)
        duration = random.randint(3_000, 20_000)
        fwd_mean = random.uniform(200, 600)
        bwd_mean = random.uniform(200, 600)

        return {
            "Flow Duration": duration,
            "Total Fwd Packets": fwd_packets,
            "Total Backward Packets": bwd_packets,
            "Total Length of Fwd Packets": int(fwd_packets * fwd_mean),
            "Total Length of Bwd Packets": int(bwd_packets * bwd_mean),
            "Fwd Packet Length Max": int(fwd_mean * random.uniform(1.5, 2.0)),
            "Fwd Packet Length Min": int(fwd_mean * random.uniform(0.4, 0.6)),
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": random.uniform(60, 150),
            "Flow Bytes/s": random.uniform(20_000, 150_000),
            "Flow Packets/s": random.uniform(800, 5_000),
            "ACK Flag Count": random.randint(300, 2000),
            "SYN Flag Count": random.randint(400, 2500),
            "FIN Flag Count": random.randint(50, 300),
            "RST Flag Count": random.randint(50, 500),
            "Bwd Packets/s": random.uniform(500, 4_000),
            "Bwd Packet Length Mean": bwd_mean,
            "Down/Up Ratio": random.uniform(0.9, 1.2),
            "Idle Mean": random.uniform(500, 5_000),
        }

    if scenario == "slowloris":
        # Slowloris / Slow DoS – Very long flow, few bytes, few packets
        fwd_packets = random.randint(1, 5)
        bwd_packets = random.randint(1, 5)
        duration = random.randint(3000_000, 10_000_000)
        fwd_mean = random.uniform(4000, 9000)
        bwd_mean = random.uniform(4000, 9000)

        return {
            "Flow Duration": duration,
            "Total Fwd Packets": fwd_packets,
            "Total Backward Packets": bwd_packets,
            "Total Length of Fwd Packets": int(fwd_packets * fwd_mean),
            "Total Length of Bwd Packets": int(bwd_packets * bwd_mean),
            "Fwd Packet Length Max": int(fwd_mean * 1.2),
            "Fwd Packet Length Min": int(fwd_mean * 0.8),
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": random.uniform(500, 1500),
            "Flow Bytes/s": random.uniform(1, 50),
            "Flow Packets/s": random.uniform(0.5, 5),
            "ACK Flag Count": random.randint(1, 3),
            "SYN Flag Count": random.randint(1, 2),
            "FIN Flag Count": random.randint(0, 1),
            "RST Flag Count": random.randint(0, 1),
            "Bwd Packets/s": random.uniform(0.5, 5),
            "Bwd Packet Length Mean": bwd_mean,
            "Down/Up Ratio": random.uniform(0.8, 1.2),
            "Idle Mean": random.uniform(0, 2_000),
            # Missing AE Features 
            "Init_Win_bytes_forward": random.randint(100, 2000),
            "Fwd IAT Max": random.randint(1000, 5000), 
        }

    if scenario == "stealth_ddos":
        # Stealth DDoS - Crafted to EVADE Signature Rules but trigger ML
        # Signatures limits:
        # Pkts <= 100, Duration >= 50, Mean >= 18, InitWin != 0
        
        fwd_packets = random.randint(80, 99) # Close to 100 but under
        duration = random.randint(60, 200)   # Over 50
        fwd_mean = random.uniform(200, 1000) # Big packets
        
        # EXTREME Statistical Features to scream "ATTACK" to ML
        return {
            "Flow Duration": duration,
            "Total Fwd Packets": fwd_packets,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": int(fwd_packets * fwd_mean),
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Max": int(fwd_mean * 1.5),
            "Fwd Packet Length Min": int(fwd_mean * 0.5),
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": random.uniform(100, 300),
            
            # Massive rates
            "Flow Bytes/s": random.uniform(50_000_000, 100_000_000), 
            "Flow Packets/s": random.uniform(500_000, 1_000_000),
            
            "ACK Flag Count": 0,
            "SYN Flag Count": fwd_packets, # Pure SYN Flood
            "FIN Flag Count": 0,
            "RST Flag Count": 0,
            "Bwd Packets/s": 0,
            "Bwd Packet Length Mean": 0,
            "Down/Up Ratio": 0,
            "Idle Mean": 0,
            "Init_Win_bytes_forward": 500, # Suspiciously low but not 0
            "Fwd IAT Max": 1, # Instantaneous
        }

    if scenario == "real_ddos_simulation":
        # Taken from actual Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv sample
        return {
            "Source Port": 63048.0,
            "Destination Port": 80.0,
            "Protocol": 6.0,
            "Flow Duration": 81868052.0,
            "Total Fwd Packets": 8.0,
            "Total Backward Packets": 4.0,
            "Total Length of Fwd Packets": 56.0,
            "Total Length of Bwd Packets": 11601.0,       
            "Fwd Packet Length Max": 20.0,
            "Fwd Packet Length Min": 0.0,
            "Fwd Packet Length Mean": 7.0,
            "Fwd Packet Length Std": 5.656854249,
            "Bwd Packet Length Max": 10220.0,
            "Bwd Packet Length Min": 0.0,
            "Bwd Packet Length Mean": 2900.25,
            "Bwd Packet Length Std": 4922.508194,
            "Flow Bytes/s": 142.3876557,
            "Flow Packets/s": 0.146577324,
            "Flow IAT Mean": 7442550.182,
            "Flow IAT Std": 22700000.0,
            "Flow IAT Max": 75700000.0,
            "Flow IAT Min": 1.0,
            "Fwd IAT Total": 81800000.0,
            "Fwd IAT Mean": 11700000.0,
            "Fwd IAT Std": 28300000.0,
            "Fwd IAT Max": 75700000.0,
            "Fwd IAT Min": 1.0,
            "Bwd IAT Total": 67266.0,
            "Bwd IAT Mean": 22422.0,
            "Bwd IAT Std": 19764.30631,
            "Bwd IAT Max": 37490.0,
            "Bwd IAT Min": 44.0,
            "Fwd Packets/s": 0.097718216,
            "Bwd Packets/s": 0.048859108,
            "Packet Length Mean": 897.1538462,
            "Packet Length Variance": 7989683.974,        
            "FIN Flag Count": 0.0,
            "SYN Flag Count": 0.0,
            "RST Flag Count": 0.0,
            "ACK Flag Count": 1.0,
            "URG Flag Count": 0.0,
            "Down/Up Ratio": 0.0,
            "Init_Win_bytes_forward": 256.0,
            "Init_Win_bytes_backward": 229.0,
            "act_data_pkt_fwd": 6.0,
            "Active Mean": 982.0,
            "Active Std": 0.0,
            "Active Max": 982.0,
            "Active Min": 982.0,
            "Idle Mean": 40900000.0,
            "Idle Std": 49200000.0,
            "Idle Max": 75700000.0,
            "Idle Min": 6079854.0
        }

    # On error, return benign
    return build_features("benign")


def build_payload(scenario: str) -> dict:
    return {
        "src_ip": random_ip(True),
        "dst_ip": random_ip(False),
        "protocol": random.choice(["TCP", "UDP", "HTTP", "HTTPS"]),
        "features": build_features(scenario),
    }


# ================== Send Flow ==================

def send_flow(scenario: str, index: int):
    payload = build_payload(scenario)
    data_bytes = json.dumps(payload).encode("utf-8")

    print("=" * 70)
    print(f"[{datetime.now()}] Sending {scenario} flow #{index}")
    print(f"-> src={payload['src_ip']} dst={payload['dst_ip']} proto={payload['protocol']}")

    req = request.Request(
        API_URL,
        data=data_bytes,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        resp = request.urlopen(req, timeout=5)
        body = resp.read().decode("utf-8", errors="ignore")
        status = resp.getcode()
    except error.HTTPError as e:
        print(f"[ERROR] HTTP Error {e.code}")
        err_body = e.read().decode("utf-8", errors="ignore")
        print("Server response:")
        print(err_body)
        return
    except Exception as e:
        print(f"[ERROR] Connection error: {e}")
        return

    print(f"[OK] Status: {status}")
    print("Raw response:")
    print(body)

    # Attempt to parse JSON
    try:
        result = json.loads(body)
    except Exception:
        print("[WARN] Response is not JSON")
        return

    # Flexible name reading for Cascading Pipeline
    is_attack = result.get("is_attack")
    label = result.get("prediction_class") or result.get("label")
    conf = result.get("confidence_score") if result.get("confidence_score") is not None else result.get("confidence")
    stage = result.get("stage_detected", "Unknown")
    
    # Detailed scores
    dnn_prob = result.get("dnn_probability")
    xgb_conf = result.get("xgb_confidence")

    print(f"-> Result: {label} | Stage: {stage} | Conf: {conf}")
    
    if is_attack:
        print(f"[ATTACK] 🚨 Blocked by {stage}")
        if stage == "Deep Neural Network" and dnn_prob:
            print(f"         DNN Probability: {dnn_prob:.4f}")
        elif stage == "XGBoost" and xgb_conf:
             print(f"         XGB Confidence: {xgb_conf:.4f}")
    else:
        print(f"[BENIGN] ✅ Traffic Clean (Stage: {stage})")


# ================== Main ==================

def main():
    parser = argparse.ArgumentParser(
        description="Multi-scenario traffic tester for IDS / detection API"
    )
    parser.add_argument(
        "--scenario",
        "-s",
        type=str,
        default="all",
        help="benign | ddos | port_scan | bruteforce | slowloris | all",
    )
    parser.add_argument(
        "--repeat",
        "-r",
        type=int,
        default=3,
        help="Number of flows per scenario",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.5,
        help="Seconds to wait between flows",
    )
    args = parser.parse_args()

    available = ["benign", "ddos", "port_scan", "bruteforce", "slowloris", "stealth_ddos", "real_ddos_simulation"]

    if args.scenario == "all":
        scenarios = available
    else:
        if args.scenario not in available:
            print(f"[WARN] Unknown scenario: {args.scenario}")
            print("Available options:", ", ".join(available + ["all"]))
            return
        scenarios = [args.scenario]



    print(f"Testing API={API_URL}")
    print(f"Scenarios: {scenarios} | repeat={args.repeat} | sleep={args.sleep}s\n")

    for s in scenarios:
        for i in range(1, args.repeat + 1):
            send_flow(s, i)
            time.sleep(args.sleep)

    print("\n[DONE] Finished attack scenarios testing.")


if __name__ == "__main__":
    main()
