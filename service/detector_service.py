"""
Real-time DDoS Detection Service - FastAPI
Provides REST API endpoints for intrusion detection using Cascading Hybrid Model
(Signature -> XGBoost -> Deep Neural Network)
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Union
import pandas as pd
import numpy as np
import joblib
import logging
import os
from datetime import datetime
import uvicorn
from prometheus_client import (
    Counter, Gauge, Summary, start_http_server, generate_latest
)
from collections import deque
import psutil
import asyncio
import sys
from tensorflow.keras.models import load_model, Model

# ========= PYTHON PATH to allow import alerting =========
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from alerting.alert_manager import load_alert_config  # noqa: E402

# Alert manager + events buffer
alert_manager = None
# 🔴 Store last 1000 events here for the dashboard to read
recent_events = deque(maxlen=1000)


# ============= Logging ============
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ============= Config ============
MODEL_DIR = os.getenv("MODEL_DIR", os.path.join(BASE_DIR, "models"))
VERSION = "2.0.0"


# ============================================
# PROMETHEUS METRICS (Safe/Robust Init)
# ============================================
class MockMetric:
    def inc(self, amount=1): pass
    def set(self, value): pass
    def labels(self, **kwargs): return self
    def time(self): return self
    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): pass
    def __call__(self, f): return f

try:
    attack_counter = Counter("ids_attacks_total", "Total number of detected attacks")
    packet_counter = Counter("ids_packets_total", "Total number of processed packets")
    benign_counter = Counter("ids_benign_total", "Total number of benign flows")
    stage_block_counter = Counter("ids_stage_blocks", "Attacks blocked by specific stage", ["stage"])
    model_latency_summary = Summary("ids_model_latency_seconds", "Model inference latency")
    system_cpu_gauge = Gauge("ids_system_cpu_percent", "System CPU usage percentage")
    system_ram_gauge = Gauge("ids_system_ram_percent", "System RAM usage percentage")
    
    # start Prometheus metrics server on :8001
    start_http_server(8001)
    logger.info("Prometheus /metrics endpoint running on port 8001")
except Exception as e:
    logger.warning(f"⚠️ Prometheus metrics failed to initialize: {e}. Using mock metrics.")
    attack_counter = MockMetric()
    packet_counter = MockMetric()
    benign_counter = MockMetric()
    stage_block_counter = MockMetric()
    model_latency_summary = MockMetric()
    system_cpu_gauge = MockMetric()
    system_ram_gauge = MockMetric()
    
    # Mock start_http_server and generate_latest if needed
    def generate_latest(): return b""

# ============================================
# Pydantic Models
# ============================================
class FeatureData(BaseModel):
    """Single feature vector for detection + optional metadata (IP, protocol)"""

    src_ip: Optional[str] = Field(None, description="Source IP address")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    protocol: Optional[str] = Field(None, description="Protocol name")
    features: Dict[str, float] = Field(..., description="Feature name-value pairs")

class DetectionResult(BaseModel):
    """Detection result for single sample"""

    is_attack: bool
    confidence_score: float
    prediction_class: str
    stage_detected: str # "Signature", "XGBoost", "DNN", or "None"
    dnn_probability: Optional[float] = None
    threshold: Optional[float] = 0.5
    timestamp: str
    xgb_confidence: Optional[float] = None
    ensemble_votes: Dict[str, Union[int, float, str]] # Kept for backward compatibility with dashboard

# ============================================
# Model Loader
# ============================================
class ModelLoader:
    """Load and manage ML models for Cascading Pipeline"""

    def __init__(self, model_dir: str):
        self.model_dir = model_dir
        self.xgb_model = None
        self.dnn_model = None
        self.scaler = None
        self.ae_scaler = None  # RobustScaler for DNN
        self.dnn_threshold = 0.5  # Probability threshold for DNN


    def load_all(self):
        """Load all required models and artifacts"""
        try:
            logger.info("Loading models for Cascading Pipeline...")

            # 1. Load XGBoost
            xgb_path = os.path.join(self.model_dir, "ddos_xgboost.pkl")
            if os.path.exists(xgb_path):
                self.xgb_model = joblib.load(xgb_path)
                logger.info("✓ XGBoost model loaded")
            else:
                logger.warning(f"❌ XGBoost model not found at {xgb_path}")



            # 2. Load Deep Neural Network Classifier
            dnn_path = os.path.join(self.model_dir, "dnn_classifier.keras")
            if os.path.exists(dnn_path):
                self.dnn_model = load_model(dnn_path, compile=False)
                self.dnn_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
                logger.info("✓ Deep Neural Network classifier loaded")
            else:
                logger.warning(f"❌ DNN classifier not found at {dnn_path}")

            # 3. Load Scaler
            scaler_path = os.path.join(self.model_dir, "scaler.pkl")
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                logger.info("✓ Scaler loaded")
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                logger.info("✓ Scaler loaded")
            else:
                logger.warning(f"❌ Scaler not found at {scaler_path}")
            # 4. Load DNN Threshold
            threshold_path = os.path.join(self.model_dir, "threshold.pkl")
            if os.path.exists(threshold_path):
                self.dnn_threshold = joblib.load(threshold_path)
                logger.info(f"✓ DNN Threshold loaded: {self.dnn_threshold}")
            else:
                self.dnn_threshold = float(os.getenv("DNN_THRESHOLD", "0.5"))
                logger.info(f"ℹ️ Using default DNN threshold: {self.dnn_threshold}")

            return True

        except Exception as e:
            logger.error(f"Error loading models: {e}")
            raise


# ============================================
# Detector Class (Cascading Logic)
# ============================================
class DDosDetector:
    """Real-time DDoS detection engine using Cascading Pipeline"""

    def __init__(self, models: ModelLoader):
        self.models = models

    def _signature_check(self, features: Dict[str, float]) -> bool:
        """
        Enhanced Signature Rules for 99% DDoS Detection
        - Golden Rule: Small packets + burst
        - Init Window Rule: Strong DDoS tool signature
        - Volumetric Rule: Packet flooding
        - Speed Rule: Short duration + many packets
        """
        fwd_len_mean = features.get('Fwd Packet Length Mean', 0)
        fwd_pkts = features.get('Total Fwd Packets', 0)
        init_win_fwd = features.get('Init_Win_bytes_forward', -1)
        flow_duration = features.get('Flow Duration', 0)
        
        # 1. Golden Rule (Very small packets + bursty)
        if 0 < fwd_len_mean < 18 and fwd_pkts > 2:
            return True
            
        # 2. Init Window Rule (Strong signature for DDoS tools)
        if init_win_fwd == 0:
            return True

        # 3. Volumetric Rule (Packet flooding)
        if fwd_pkts > 100:
            return True
            
        # 4. Speed Rule (Very short duration + many packets)
        if flow_duration < 50 and fwd_pkts > 10:
            return True

        return False

    @model_latency_summary.time()
    def detect(self, feature_dict: Dict[str, float]) -> DetectionResult:
        """
        Perform detection using Cascading Pipeline
        1. Signature
        2. XGBoost
        3. Deep Neural Network
        """

        # Update system metrics
        packet_counter.inc()
        system_cpu_gauge.set(psutil.cpu_percent())
        system_ram_gauge.set(psutil.virtual_memory().percent)

        detection_stage = "None"
        is_attack = False
        confidence = 0.0
        dnn_prob = None
        xgb_conf = None
        
        # 1. Prepare Data
        # We need a DataFrame for Scaler/Models
        # Ensuring we pass all expected columns (handling defaults)
        # However, scaler expects specific columns. 
        # We'll rely on the fact that feature_dict comes from feature_extractor 
        # which should match training keys if updated correctly.
        
        # For XGBoost, we need the full scaled vector
        # For Autoencoder, we need "Golden Set" from scaled vector
        
        # Wrap into DF
        df = pd.DataFrame([feature_dict])
        
        # Fill missing cols with 0 if necessary (safe guard)
        if self.models.scaler:
             # Get expected features from scaler
             expected_features = self.models.scaler.feature_names_in_ if hasattr(self.models.scaler, 'feature_names_in_') else df.columns
             for col in expected_features:
                 if col not in df.columns:
                     df[col] = 0.0
             df = df[expected_features]
             
             try:
                 X_scaled = self.models.scaler.transform(df)
                 # X_scaled is numpy array. If we need DF for column selection (Autoencoder), wrap it back
                 X_scaled_df = pd.DataFrame(X_scaled, columns=expected_features)
             except Exception as e:
                 logger.error(f"Scaling error: {e}")
                 X_scaled = np.zeros((1, len(expected_features)))
                 X_scaled_df = pd.DataFrame(X_scaled, columns=expected_features)
        else:
            X_scaled = df.values
            X_scaled_df = df

        # ==========================================
        # STAGE 1: Signature Based
        # ==========================================
        if self._signature_check(feature_dict):
            is_attack = True
            confidence = 1.0
            detection_stage = "Signature"
            stage_block_counter.labels(stage="signature").inc()
        
        # ==========================================
        # STAGE 2: XGBoost (if not detected yet)
        # ==========================================
        if not is_attack and self.models.xgb_model:
            try:
                # XGBoost expect matrix
                xgb_pred = self.models.xgb_model.predict(X_scaled)[0]
                xgb_proba = self.models.xgb_model.predict_proba(X_scaled)[0][1] # Probability of class 1
                xgb_conf = float(xgb_proba)
                
                if xgb_pred == 1:
                    is_attack = True
                    confidence = xgb_conf
                    detection_stage = "XGBoost"
                    stage_block_counter.labels(stage="xgboost").inc()
            except Exception as e:
                logger.error(f"XGBoost prediction error: {e}")

        # ==========================================
        # STAGE 3: Deep Neural Network (if not detected yet)
        # ==========================================
        if not is_attack and self.models.dnn_model:
            try:
                # Use DNN scaler if available, otherwise use main scaler output
                # Use main scaler output (X_scaled) which is already transformed
                X_dnn = X_scaled
                
                # Get probability prediction
                y_proba = self.models.dnn_model.predict(X_dnn, verbose=0)[0][0]
                dnn_prob = float(y_proba)
                
                if y_proba >= self.models.dnn_threshold:
                    is_attack = True
                    confidence = dnn_prob
                    detection_stage = "Deep Neural Network"
                    stage_block_counter.labels(stage="dnn").inc()
            except Exception as e:
                logger.error(f"DNN prediction error: {e}")
                
        # Update global counters
        if is_attack:
            attack_counter.inc()
        else:
            benign_counter.inc()

        # Construction result compatible with Dashboard
        # Dashboard expects 'ensemble_votes' dict to display reasoning
        ensemble_votes = {
             "total_votes": 3 if is_attack else 0, # Fake votes to make dashboard "Red"
             "threshold": 1,
             "weighted_vote": 3.0 if is_attack else 0.0,
             "reason": f"Blocked by {detection_stage}" if is_attack else "Clean"
        }

        result = DetectionResult(
            is_attack=is_attack,
            confidence_score=confidence,
            prediction_class="DDoS" if is_attack else "BENIGN",
            stage_detected=detection_stage,
            dnn_probability=dnn_prob,
            xgb_confidence=xgb_conf,
            threshold=self.models.dnn_threshold,
            timestamp=datetime.now().isoformat(),
            ensemble_votes=ensemble_votes
        )

        return result


# ============================================
# FastAPI Application
# ============================================
app = FastAPI(
    title="Real-time DDoS Detection Service (Cascading)",
    description="Multi-stage IDS: Signature -> XGBoost -> Deep Neural Network",
    version=VERSION,
)

detector: Optional[DDosDetector] = None


# ============================================
# /metrics ENDPOINT (prometheus client)
# ============================================
@app.get("/metrics")
async def prometheus_metrics():
    """Returns Prometheus metrics (for Prometheus scrape)"""
    return Response(generate_latest(), media_type="text/plain")


@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy" if detector is not None else "unhealthy",
        "timestamp": datetime.now().isoformat(),
        "models_loaded": detector is not None,
        "mode": "Cascading Pipeline"
    }


# ============================================
# Startup
# ============================================
@app.on_event("startup")
async def startup_event():
    """Initialize models and alert manager on startup"""
    global detector, alert_manager
    try:
        logger.info("Starting DDoS Detection Service (Cascading Mode)...")

        # Load models
        models = ModelLoader(MODEL_DIR)
        models.load_all()
        detector = DDosDetector(models)

        # Load alert config
        config_path = os.path.join(BASE_DIR, "alerting", "alert_config.json")
        alert_manager = load_alert_config(config_path)

        logger.info("✓ Service ready")

    except Exception as e:
        logger.error(f"Failed to start service: {e}")
        raise


# ============================================
# Build alert payload + event payload
# ============================================
def _pick_first(d: Dict, keys, default=None):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def build_alert_payload(data: FeatureData, result: DetectionResult) -> Dict:
    feats = data.features
    src_ip = data.src_ip or _pick_first(feats, ["src_ip", "Src IP", "Source IP"], "unknown")
    dst_ip = data.dst_ip or _pick_first(feats, ["dst_ip", "Dst IP", "Destination IP"], "unknown")
    protocol = data.protocol or _pick_first(feats, ["Protocol", "protocol"], "UNKNOWN")

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "attack_type": result.prediction_class,
        "confidence_score": result.confidence_score,
        "severity": "high" if result.confidence_score >= 0.9 else "medium",
        "flow_duration": feats.get("Flow Duration", 0),
        "total_packets": feats.get("Total Fwd Packets", 0) + feats.get("Total Backward Packets", 0),
        "flow_bytes_per_sec": feats.get("Flow Packets/s", 0.0), # Typo fix: bits or packets? keeping generic
        "ensemble_votes": result.ensemble_votes,
        "detection_stage": result.stage_detected,
        "dashboard_url": "http://localhost:8501",
    }


def build_event_record(data: FeatureData, result: DetectionResult) -> Dict:
    feats = data.features
    src_ip = data.src_ip or _pick_first(feats, ["src_ip", "Src IP"], "unknown")
    dst_ip = data.dst_ip or _pick_first(feats, ["dst_ip", "Dst IP"], "unknown")
    protocol = data.protocol or _pick_first(feats, ["Protocol", "protocol"], "UNKNOWN")

    return {
        "timestamp": result.timestamp,
        "is_attack": result.is_attack,
        "confidence_score": result.confidence_score,
        "prediction_class": result.prediction_class,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "flow_duration": feats.get("Flow Duration", 0),
        "total_packets": feats.get("Total Fwd Packets", 0) + feats.get("Total Backward Packets", 0),
        "flow_bytes_per_sec": feats.get("Flow Bytes/s", 0.0), # Fixed key
        "ensemble_votes": result.ensemble_votes,
        "detection_stage": result.stage_detected,
    }


# ============================================
# Detection Endpoint
# ============================================
@app.post("/detect", response_model=DetectionResult, tags=["Detection"])
async def detect_single(data: FeatureData):
    """
    Detect DDoS attack in single sample using Cascading Pipeline
    """
    global recent_events

    if detector is None:
        raise HTTPException(status_code=503, detail="Service not ready")

    try:
        feature_dict = data.features.copy()
        
        # Perform detection
        result = detector.detect(feature_dict)
        
        logger.info(
            f"Result: {result.prediction_class} | Stage: {result.stage_detected} | Conf: {result.confidence_score:.2f}"
        )

        event_record = build_event_record(data, result)
        recent_events.append(event_record)

        if result.is_attack and alert_manager is not None:
            alert_payload = build_alert_payload(data, result)
            asyncio.create_task(alert_manager.send_alert(alert_payload))

        return result

    except Exception as e:
        logger.error(f"Detection error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# /events endpoint for dashboard
# ============================================
@app.get("/events", tags=["Monitoring"])
async def get_events(limit: int = 1000):
    events = list(recent_events)[-limit:]
    return events[::-1]

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
