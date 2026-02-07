"""
Script to send REAL attack samples from the training dataset to the detector API
This will make RF and XGB detect attacks correctly
"""
import json
import time
from datetime import datetime
from urllib import request, error
import argparse
import pandas as pd
import random

API_URL = "http://localhost:8000/detect"


def random_ip(private=True):
    if private:
        return f"192.168.{random.randint(0, 254)}.{random.randint(1, 254)}"
    else:
        return f"{random.randint(20, 220)}.{random.randint(0, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}"


def load_real_samples():
    """Load real attack and benign samples from training dataset"""
    df = pd.read_csv('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')
    df.columns = df.columns.str.strip()

    attacks = df[df['Label'] == 'DDoS']
    if attacks.empty:
         # Fallback if label is lowercase or different
         attacks = df[df['Label'] != 'BENIGN']
         
    benign = df[df['Label'] == 'BENIGN']

    print(f"Loaded {len(attacks)} attack samples and {len(benign)} benign samples from dataset")

    return attacks, benign


def get_real_features(scenario: str, attacks_df, benign_df) -> dict:
    """Get real features from dataset based on scenario"""

    if scenario == "benign":
        # Pick a random benign sample
        sample = benign_df.sample(1).iloc[0]
    else:
        # Pick a random attack sample
        sample = attacks_df.sample(1).iloc[0]

    # Drop the Label column and metadata
    drop_cols = ['Label', 'Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
    # Filter only columns that exist
    features = sample.drop([c for c in drop_cols if c in sample.index]).to_dict()

    return features


def send_flow(scenario: str, index: int, attacks_df, benign_df):
    # Get real features from dataset
    features = get_real_features(scenario, attacks_df, benign_df)

    payload = {
        "src_ip": random_ip(True),
        "dst_ip": random_ip(False),
        "protocol": random.choice(["TCP", "UDP", "HTTP", "HTTPS"]),
        "features": features
    }

    data_bytes = json.dumps(payload).encode("utf-8")

    print("=" * 70)
    print(f"[{datetime.now()}] Sending REAL {scenario} sample #{index}")
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

    try:
        result = json.loads(body)
    except Exception:
        print("[WARN] Response is not JSON")
        return

    is_attack = result.get("is_attack")
    label = result.get("label") or result.get("prediction_class")
    conf = result.get("confidence") or result.get("confidence_score")
    votes = result.get("ensemble_votes", {})

    stage = result.get("stage_detected", "Unknown")
    
    print(f"-> Result: {label} | Stage: {stage} | Conf: {conf:.4f}")
    if is_attack:
        print(f"[ATTACK] 🚨 Blocked by {stage}")
    else:
        print(f"[BENIGN] ✅ Traffic Clean (Stage: {stage})")


def main():
    parser = argparse.ArgumentParser(
        description="Send REAL attack samples from dataset to IDS API"
    )
    parser.add_argument(
        "--scenario",
        "-s",
        type=str,
        default="attack",
        help="attack | benign | mixed",
    )
    parser.add_argument(
        "--repeat",
        "-r",
        type=int,
        default=5,
        help="Number of samples to send",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.5,
        help="Sleep between requests (seconds)",
    )
    args = parser.parse_args()

    # Load real samples from dataset
    print("Loading real samples from training dataset...")
    attacks_df, benign_df = load_real_samples()
    print()

    print(f"Testing API={API_URL}")
    print(f"Scenario: {args.scenario} | repeat={args.repeat} | sleep={args.sleep}s\n")

    if args.scenario == "mixed":
        scenarios = ["attack", "benign"]
        for i in range(1, args.repeat + 1):
            scenario = random.choice(scenarios)
            send_flow(scenario, i, attacks_df, benign_df)
            time.sleep(args.sleep)
    else:
        for i in range(1, args.repeat + 1):
            send_flow(args.scenario, i, attacks_df, benign_df)
            time.sleep(args.sleep)

    print("\n[DONE] Finished testing with real samples.")


if __name__ == "__main__":
    main()
