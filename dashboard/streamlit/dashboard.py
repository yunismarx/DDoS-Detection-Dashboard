"""
Real-time DDoS Detection Dashboard - Streamlit
Live monitoring, visualization, and alerting interface
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import requests
from datetime import datetime, timedelta
import time
from collections import deque
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="DDoS Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Professional Custom CSS with Harmonious Design
st.markdown("""
<style>
    /* Main Background - Dark Professional */
    .stApp {
        background: linear-gradient(135deg, #1e3a8a 0%, #1e293b 100%);
    }

    /* Content Area */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border-radius: 16px;
        box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        margin: 1rem;
    }

    /* Headers Styling - Consistent Blue */
    h1 {
        color: #ffff;
        font-weight: 800;
        letter-spacing: -0.5px;
    }

    h2, h3 {
        color: #ffff;
        font-weight: 700;
    }

    /* Metric Cards */
    [data-testid="stMetricValue"] {
        font-size: 2rem;
        font-weight: 700;
        color: #ffff;
    }

    [data-testid="stMetricLabel"] {
        font-size: 1rem;
        font-weight: 600;
        color: #64748b;
    }

    [data-testid="stMetricDelta"] {
        font-size: 0.9rem;
        font-weight: 600;
    }

    /* Custom Metric Cards */
    .metric-card {
        background: rgba(30, 41, 59, 0.5);
        padding: 25px;
        border-radius: 12px;
        margin: 15px 0;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        border: 1px solid rgba(100, 116, 139, 0.2);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }

    .metric-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 20px rgba(59, 130, 246, 0.3);
        border-color: rgba(59, 130, 246, 0.4);
    }

    /* Attack Alert - Consistent Red */
    .attack-alert {
        background: #dc2626;
        color: white;
        padding: 18px 24px;
        border-radius: 10px;
        margin: 12px 0;
        font-weight: 600;
        box-shadow: 0 4px 12px rgba(220, 38, 38, 0.25);
        border-left: 4px solid #991b1b;
        animation: slideIn 0.4s ease;
        font-size: 0.95rem;
    }

    /* Benign Alert - Consistent Green */
    .benign-alert {
        background: #059669;
        color: white;
        padding: 18px 24px;
        border-radius: 10px;
        margin: 12px 0;
        font-weight: 600;
        box-shadow: 0 4px 12px rgba(5, 150, 105, 0.25);
        border-left: 4px solid #047857;
        animation: slideIn 0.4s ease;
        font-size: 0.95rem;
    }

    /* Warning Alert - Yellow (Deep Neural Network) */
    .warning-alert {
        background: #eab308; /* Yellow-500 */
        color: #fffbeb; /* Yellow-50 */
        padding: 18px 24px;
        border-radius: 10px;
        margin: 12px 0;
        font-weight: 600;
        box-shadow: 0 4px 12px rgba(234, 179, 8, 0.25);
        border-left: 4px solid #a16207; /* Yellow-700 */
        animation: slideIn 0.4s ease;
        font-size: 0.95rem;
    }

    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateX(-20px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }

    /* Tabs Styling - Consistent Blue Theme */
    .stTabs [data-baseweb="tab-list"] {
        gap: 12px;
        background: rgba(15, 23, 42, 0.6);
        padding: 8px;
        border-radius: 10px;
        border: 1px solid rgba(100, 116, 139, 0.2);
    }

    .stTabs [data-baseweb="tab"] {
        height: 48px;
        background: rgba(30, 41, 59, 0.5);
        border-radius: 8px;
        padding: 0 24px;
        font-weight: 600;
        color: #cbd5e1;
        border: 2px solid transparent;
        transition: all 0.3s ease;
    }

    .stTabs [data-baseweb="tab"]:hover {
        background: rgba(59, 130, 246, 0.2);
        color: #ffffff;
        border-color: #3b82f6;
    }

    .stTabs [aria-selected="true"] {
        background: #1e40af;
        color: white !important;
        box-shadow: 0 4px 12px rgba(30, 64, 175, 0.5);
    }

    /* Sidebar Styling - Dark Blue */
    [data-testid="stSidebar"] {
        background: #1e293b;
    }

    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3,
    [data-testid="stSidebar"] label {
        color: #e2e8f0 !important;
    }

    /* Buttons - Consistent Blue */
    .stButton > button {
        background: #1e40af;
        color: white;
        border: none;
        border-radius: 8px;
        padding: 12px 28px;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 4px 12px rgba(30, 64, 175, 0.25);
    }

    .stButton > button:hover {
        background: #1e3a8a;
        transform: translateY(-2px);
        box-shadow: 0 6px 16px rgba(30, 64, 175, 0.35);
    }

    /* Success/Error/Info Messages */
    .stSuccess {
        background: #d1fae5;
        color: #065f46;
        border-radius: 8px;
        border-left: 4px solid #059669;
    }

    .stError {
        background: #fee2e2;
        color: #991b1b;
        border-radius: 8px;
        border-left: 4px solid #dc2626;
    }

    .stInfo {
        background: #dbeafe;
        color: #1e3a8a;
        border-radius: 8px;
        border-left: 4px solid #ffff;
    }

    /* Dataframe Styling */
    .dataframe {
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        background: rgba(15, 23, 42, 0.5);
    }

    /* Plotly Charts */
    .js-plotly-plot {
        border-radius: 12px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        overflow: hidden;
        background: rgba(15, 23, 42, 0.5);
    }

    /* Sliders */
    .stSlider > div > div > div {
        background: transparent !important;
    }
    
    .stSlider [data-baseweb="slider"] {
        background: transparent !important;
    }
    
    .stSlider [data-baseweb="slider"] > div {
        background: transparent !important;
    }

    /* Text Inputs */
    .stTextInput > div > div > input {
        border-radius: 8px;
        border: 2px solid rgba(100, 116, 139, 0.3);
        background: rgba(15, 23, 42, 0.5);
        color: #ffffff;
        transition: border-color 0.3s ease;
    }

    .stTextInput > div > div > input:focus {
        border-color: #3b82f6;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        background: rgba(30, 41, 59, 0.7);
    }

    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 10px;
        height: 10px;
    }

    ::-webkit-scrollbar-track {
        background: rgba(15, 23, 42, 0.5);
        border-radius: 8px;
    }

    ::-webkit-scrollbar-thumb {
        background: #1e40af;
        border-radius: 8px;
    }

    ::-webkit-scrollbar-thumb:hover {
        background: #3b82f6;
    }

    /* st-et Element - Dark Theme */
    .st-et {
        background: rgba(15, 23, 42, 0.5) !important;
        color: #cbd5e1 !important;
    }
</style>
""", unsafe_allow_html=True)


class DDoSDashboard:
    """Real-time DDoS Detection Dashboard"""
    
    def __init__(self, api_url: str = "http://localhost:8000", max_history: int = 1000):
        """
        Args:
            api_url: Detection service URL
            max_history: Maximum events to keep in memory
        """
        self.api_url = api_url
        self.max_history = max_history
        

        # Initialize session state
        if 'events' not in st.session_state:
            st.session_state.events = deque(maxlen=max_history)
        if 'attack_history' not in st.session_state:
            st.session_state.attack_history = deque(maxlen=max_history)
        if 'stats' not in st.session_state:
            st.session_state.stats = {
                'total_detections': 0,
                'attacks_detected': 0,
                'benign_traffic': 0,
                'false_positives': 0,
                'last_attack_time': None
            }
        if 'auto_refresh' not in st.session_state:
            st.session_state.auto_refresh = True
        if 'refresh_interval' not in st.session_state:
            st.session_state.refresh_interval = 5
    
    # =======================
    # Backend communication
    # =======================
    def check_service_health(self):
        """Check if detection service is running"""
        try:
            response = requests.get(f"{self.api_url}/health", timeout=2)
            return response.status_code == 200
        except:
            return False
        

    def fetch_events_from_api(self, limit: int = 1000):
        """جلب آخر الأحداث من /events وتخزينها في session_state"""
        try:
            resp = requests.get(
                f"{self.api_url}/events",
                params={"limit": limit},
                timeout=2
            )
            if resp.status_code != 200:
                logger.warning(f"Failed to fetch events: {resp.status_code}")
                return

            raw_events = resp.json()
            events = []

            for e in raw_events:
                # تحويل timestamp من string إلى datetime
                try:
                    ts = datetime.fromisoformat(e.get("timestamp"))
                except Exception:
                    ts = datetime.now()

                events.append({
                    "timestamp": ts,
                    "is_attack": e.get("is_attack", False),
                    "confidence_score": e.get("confidence_score", 0.0),
                    "prediction_class": e.get("prediction_class", "BENIGN"),
                    "src_ip": e.get("src_ip", "unknown"),
                    "dst_ip": e.get("dst_ip", "unknown"),
                    "protocol": e.get("protocol", "UNKNOWN"),
                    "flow_duration": e.get("flow_duration", 0),
                    "total_packets": e.get("total_packets", 0),
                    "flow_bytes_per_sec": e.get("flow_bytes_per_sec", 0.0),
                    "ensemble_votes": e.get("ensemble_votes", {}),
                    "detection_stage": e.get("detection_stage", "Unknown"),
                })

            # نخزن الأحداث في session_state
            from collections import deque as _deque
            st.session_state.events = _deque(events, maxlen=self.max_history)

            # نحدّث الإحصائيات
            total = len(events)
            attacks = sum(1 for ev in events if ev["is_attack"])
            benign = total - attacks
            last_attack_time = None
            for ev in events:
                if ev["is_attack"]:
                    if last_attack_time is None or ev["timestamp"] > last_attack_time:
                        last_attack_time = ev["timestamp"]

            st.session_state.stats = {
                "total_detections": total,
                "attacks_detected": attacks,
                "benign_traffic": benign,
                "false_positives": st.session_state.stats.get("false_positives", 0)
                    if "stats" in st.session_state else 0,
                "last_attack_time": last_attack_time,
            }

        except Exception as ex:
            logger.warning(f"Error fetching events from API: {ex}")


    def get_service_metrics(self):
        """Get service metrics (Prometheus text)"""
        try:
            response = requests.get(f"{self.api_url}/metrics", timeout=2)
            if response.status_code == 200:
                return response.text   # نص وليس JSON
        except:
            pass
        return None

    
    # =======================
    # Local simulation
    # =======================
    def simulate_detection(self, is_attack: bool = False):
        """
        Send real detection request to API
        """
        # Generate sample data
        features = {
            "flow_duration": np.random.randint(100, 100000),
            "total_fwd_packets": np.random.randint(10, 2000),
            "total_bwd_packets": np.random.randint(10, 2000),
            "flow_bytes_per_sec": np.random.uniform(1000, 2000000),
            "flow_packets_per_sec": np.random.uniform(10, 5000),
            "fwd_packet_length_mean": np.random.uniform(50, 1500),
            "bwd_packet_length_mean": np.random.uniform(50, 1500),
            "flow_iat_mean": np.random.uniform(10, 10000),
            "fwd_iat_mean": np.random.uniform(10, 10000),
            "bwd_iat_mean": np.random.uniform(10, 10000),
            "active_mean": np.random.uniform(100, 5000),
            "idle_mean": np.random.uniform(100, 5000),
            "syn_flag_count": np.random.randint(0, 10),
            "rst_flag_count": np.random.randint(0, 5),
            "psh_flag_count": np.random.randint(0, 10),
            "ack_flag_count": np.random.randint(0, 100),
        }

        # Adjust features based on attack/benign
        if is_attack:
            features["flow_bytes_per_sec"] = np.random.uniform(1000000, 2000000)
            features["flow_packets_per_sec"] = np.random.uniform(3000, 5000)
            features["syn_flag_count"] = np.random.randint(50, 100)
        else:
            features["flow_bytes_per_sec"] = np.random.uniform(1000, 50000)
            features["flow_packets_per_sec"] = np.random.uniform(10, 200)
            features["syn_flag_count"] = np.random.randint(0, 5)

        # Prepare request data
        data = {
            "src_ip": f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            "dst_ip": f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            "protocol": np.random.choice(['TCP', 'UDP', 'ICMP']),
            "features": features
        }

        # Send to API
        try:
            response = requests.post(f"{self.api_url}/detect", json=data, timeout=5)
            if response.status_code == 200:
                result = response.json()
                # Convert API response to dashboard event format
                event = {
                    'timestamp': datetime.now(),
                    'is_attack': result['is_attack'],
                    'confidence_score': result['confidence_score'],
                    'prediction_class': result['prediction_class'],
                    'src_ip': data['src_ip'],
                    'dst_ip': data['dst_ip'],
                    'protocol': data['protocol'],
                    'flow_duration': features['flow_duration'],
                    'total_packets': features['total_fwd_packets'] + features['total_bwd_packets'],
                    'flow_bytes_per_sec': features['flow_bytes_per_sec'],
                    'ensemble_votes': result['ensemble_votes'],
                    'detection_stage': result.get('detection_stage', 'Unknown')
                }
                return event
            else:
                logger.error(f"API returned error: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Failed to call detection API: {e}")
            return None
    
    def add_event(self, event):
        """Add new detection event"""
        st.session_state.events.append(event)
        
        # Update statistics
        st.session_state.stats['total_detections'] += 1
        if event['is_attack']:
            st.session_state.stats['attacks_detected'] += 1
            st.session_state.stats['last_attack_time'] = event['timestamp']
            st.session_state.attack_history.append(event)
        else:
            st.session_state.stats['benign_traffic'] += 1
    
    # =======================
    # UI Renders
    # =======================
    def render_header(self):
        """Render dashboard header"""
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            st.title("🛡️ Real-time DDoS Detection Dashboard")
        
        with col2:
            # Service health indicator
            is_healthy = self.check_service_health()
            if is_healthy:
                st.success("🟢 Service Online")
            else:
                st.error("🔴 Service Offline")
        
        with col3:
            # Current time
            st.info(f"🕐 {datetime.now().strftime('%H:%M:%S')}")
    
    def render_metrics(self):
        """Render key metrics"""
        stats = st.session_state.stats
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric(
                "Total Detections",
                f"{stats['total_detections']:,}",
                delta=None
            )
        
        with col2:
            attack_rate = (stats['attacks_detected'] / max(stats['total_detections'], 1)) * 100
            st.metric(
                "Attacks Detected",
                f"{stats['attacks_detected']:,}",
                delta=f"{attack_rate:.1f}%"
            )
        
        with col3:
            st.metric(
                "Benign Traffic",
                f"{stats['benign_traffic']:,}",
                delta=None
            )
        
        with col4:
            if stats['last_attack_time']:
                time_since = datetime.now() - stats['last_attack_time']
                if time_since.seconds < 60:
                    last_attack = f"{time_since.seconds}s ago"
                elif time_since.seconds < 3600:
                    last_attack = f"{time_since.seconds // 60}m ago"
                else:
                    last_attack = f"{time_since.seconds // 3600}h ago"
            else:
                last_attack = "Never"
            
            st.metric("Last Attack", last_attack)
        
        with col5:
            # False positive rate (placeholder)
            fp_rate = (stats.get('false_positives', 0) / max(stats['attacks_detected'], 1)) * 100
            st.metric("False Positive Rate", f"{fp_rate:.1f}%")
    
    def render_live_alerts(self):
        """Render live alert feed"""
        st.subheader("🚨 Live Alert Feed")
 
        # API returns events with newest first, so take first 10
        all_events = list(st.session_state.events)
        recent_events = all_events[:10]  # Get first 10 (newest already at top)

        if not recent_events:
            st.info("No events detected yet. Waiting for traffic...")
            return

        for event in recent_events:
            if event['is_attack']:
                # Get threshold from event, default to 3 if not present
                threshold = event['ensemble_votes'].get('threshold', 0)
                reason = event['ensemble_votes'].get('reason', 'Attack')
                stage = event.get('detection_stage', reason) 

                if stage in ["Deep Neural Network", "DNN"] or "DNN" in str(stage) or "Deep Neural" in str(stage):
                     alert_html = f"""
                    <div class="warning-alert">
                        ⚠️ SUSPICIOUS ACTIVITY (DNN) | {event['timestamp'].strftime('%H:%M:%S')} |
                        {event['src_ip']} → {event['dst_ip']} |
                        {event['protocol']} |
                        Confidence: {event['confidence_score']:.2%} |
                        Reason: Deep Learning Detection
                    </div>
                    """
                else:
                    alert_html = f"""
                    <div class="attack-alert">
                        🚨 ATTACK DETECTED | {event['timestamp'].strftime('%H:%M:%S')} |
                        {event['src_ip']} → {event['dst_ip']} |
                        {event['protocol']} |
                        Confidence: {event['confidence_score']:.2%} |
                        Block Reason: {stage}
                    </div>
                    """
                st.markdown(alert_html, unsafe_allow_html=True)
            else:
                alert_html = f"""
                <div class="benign-alert">
                    ✓ BENIGN | {event['timestamp'].strftime('%H:%M:%S')} | 
                    {event['src_ip']} → {event['dst_ip']} | {event['protocol']}
                </div>
                """
                st.markdown(alert_html, unsafe_allow_html=True)
    
    def render_timeline_chart(self):
        """Render attack timeline"""
        st.subheader("📊 Detection Timeline")

        if len(st.session_state.events) < 2:
            st.info("Collecting data...")
            return

        # Create DataFrame from events
        df = pd.DataFrame(list(st.session_state.events))

        # Resample by minute
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.set_index('timestamp', inplace=True)

        # Count attacks and benign per minute
        attacks = df[df['is_attack']].resample('1min').size()
        benign = df[~df['is_attack']].resample('1min').size()

        # Create figure with professional styling
        fig = go.Figure()

        fig.add_trace(go.Scatter(
            x=attacks.index,
            y=attacks.values,
            mode='lines+markers',
            name='Attacks',
            line=dict(color='#dc2626', width=3, shape='spline'),
            marker=dict(size=10, color='#dc2626', line=dict(width=2, color='white')),
            fill='tozeroy',
            fillcolor='rgba(220, 38, 38, 0.1)'
        ))

        fig.add_trace(go.Scatter(
            x=benign.index,
            y=benign.values,
            mode='lines+markers',
            name='Benign',
            line=dict(color='#059669', width=3, shape='spline'),
            marker=dict(size=10, color='#059669', line=dict(width=2, color='white')),
            fill='tozeroy',
            fillcolor='rgba(5, 150, 105, 0.1)'
        ))

        fig.update_layout(
            title={
                'text': "Traffic Timeline (per minute)",
                'font': {'size': 20, 'color': '#ffffff', 'family': 'Arial Black'}
            },
            xaxis_title="Time",
            yaxis_title="Events",
            hovermode='x unified',
            height=450,
            plot_bgcolor='rgba(15, 23, 42, 0.5)',
            paper_bgcolor='rgba(30, 41, 59, 0.3)',
            font=dict(family='Arial', size=12, color='#cbd5e1'),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1,
                bgcolor='rgba(15, 23, 42, 0.8)',
                bordercolor='rgba(100, 116, 139, 0.3)',
                borderwidth=1
            ),
            xaxis=dict(showgrid=True, gridwidth=1, gridcolor='rgba(100, 116, 139, 0.1)', color='#cbd5e1'),
            yaxis=dict(showgrid=True, gridwidth=1, gridcolor='rgba(100, 116, 139, 0.1)', color='#cbd5e1')
        )

        st.plotly_chart(fig, width='stretch')
    
    def render_confidence_distribution(self):
        """Render confidence score distribution"""
        st.subheader("📈 Confidence Score Distribution")

        if len(st.session_state.events) < 10:
            st.info("Collecting data...")
            return

        df = pd.DataFrame(list(st.session_state.events))

        fig = px.histogram(
            df,
            x='confidence_score',
            color='prediction_class',
            nbins=20,
            title="Distribution of Confidence Scores",
            labels={'confidence_score': 'Confidence Score', 'count': 'Frequency'},
            color_discrete_map={'DDoS': '#dc2626', 'BENIGN': '#059669'},
            opacity=0.75
        )

        fig.update_layout(
            height=450,
            plot_bgcolor='rgba(15, 23, 42, 0.5)',
            paper_bgcolor='rgba(30, 41, 59, 0.3)',
            font=dict(family='Arial', size=12, color='#cbd5e1'),
            title={'font': {'size': 18, 'color': '#ffffff'}},
            xaxis=dict(showgrid=True, gridwidth=1, gridcolor='rgba(100, 116, 139, 0.1)', color='#cbd5e1'),
            yaxis=dict(showgrid=True, gridwidth=1, gridcolor='rgba(100, 116, 139, 0.1)', color='#cbd5e1')
        )

        st.plotly_chart(fig, width='stretch')

    def render_top_sources(self):
        """Render top attack sources"""
        st.subheader("🎯 Top Attack Sources")

        attack_events = [e for e in st.session_state.events if e['is_attack']]

        if not attack_events:
            st.info("No attacks detected yet")
            return

        # Count by source IP
        df = pd.DataFrame(attack_events)
        top_sources = df['src_ip'].value_counts().head(10)

        fig = px.bar(
            x=top_sources.values,
            y=top_sources.index,
            orientation='h',
            title="Top 10 Attack Sources",
            labels={'x': 'Number of Attacks', 'y': 'Source IP'},
            color=top_sources.values,
            color_continuous_scale=[[0, '#fca5a5'], [0.5, '#dc2626'], [1, '#991b1b']]
        )

        fig.update_layout(
            height=450,
            showlegend=False,
            plot_bgcolor='rgba(15, 23, 42, 0.5)',
            paper_bgcolor='rgba(30, 41, 59, 0.3)',
            font=dict(family='Arial', size=12, color='#cbd5e1'),
            title={'font': {'size': 18, 'color': '#ffffff'}},
            xaxis=dict(showgrid=True, gridwidth=1, gridcolor='rgba(100, 116, 139, 0.1)', color='#cbd5e1'),
            yaxis=dict(showgrid=False, color='#cbd5e1')
        )

        fig.update_traces(marker=dict(line=dict(width=2, color='rgba(30, 41, 59, 0.5)')))

        st.plotly_chart(fig, width='stretch')
    
    def render_protocol_distribution(self):
        """Render protocol distribution"""
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("🔌 Attack Protocols")

            attack_events = [e for e in st.session_state.events if e['is_attack']]

            if attack_events:
                df = pd.DataFrame(attack_events)
                protocol_counts = df['protocol'].value_counts()

                fig = px.pie(
                    values=protocol_counts.values,
                    names=protocol_counts.index,
                    title="Attack Distribution by Protocol",
                    color_discrete_sequence=['#dc2626', '#b91c1c', '#991b1b', '#7f1d1d'],
                    hole=0.4
                )

                fig.update_traces(
                    textposition='inside',
                    textinfo='percent+label',
                    marker=dict(line=dict(color='white', width=2))
                )

                fig.update_layout(
                    height=400,
                    plot_bgcolor='rgba(15, 23, 42, 0.5)',
                    paper_bgcolor='rgba(30, 41, 59, 0.3)',
                    font=dict(family='Arial', size=12, color='#cbd5e1'),
                    title={'font': {'size': 16, 'color': '#ffffff'}}
                )

                st.plotly_chart(fig, width='stretch')
            else:
                st.info("No attack data available")

        with col2:
            st.subheader("✓ Benign Protocols")

            benign_events = [e for e in st.session_state.events if not e['is_attack']]

            if benign_events:
                df = pd.DataFrame(benign_events)
                protocol_counts = df['protocol'].value_counts()

                fig = px.pie(
                    values=protocol_counts.values,
                    names=protocol_counts.index,
                    title="Benign Distribution by Protocol",
                    color_discrete_sequence=['#059669', '#047857', '#065f46', '#064e3b'],
                    hole=0.4
                )

                fig.update_traces(
                    textposition='inside',
                    textinfo='percent+label',
                    marker=dict(line=dict(color='white', width=2))
                )

                fig.update_layout(
                    height=400,
                    plot_bgcolor='rgba(15, 23, 42, 0.5)',
                    paper_bgcolor='rgba(30, 41, 59, 0.3)',
                    font=dict(family='Arial', size=12, color='#cbd5e1'),
                    title={'font': {'size': 16, 'color': '#ffffff'}}
                )

                st.plotly_chart(fig, width='stretch')
            else:
                st.info("No benign data available")
    
    def render_flow_characteristics(self):
        """Render flow characteristics"""
        st.subheader("🌊 Flow Characteristics")

        if len(st.session_state.events) < 10:
            st.info("Collecting data...")
            return

        df = pd.DataFrame(list(st.session_state.events))

        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=(
                'Bytes/sec Distribution',
                'Packet Count Distribution',
                'Flow Duration Distribution',
                'Confidence vs Bytes/sec'
            )
        )

        # Bytes/sec by class
        for class_name, color in [('DDoS', '#dc2626'), ('BENIGN', '#059669')]:
            class_df = df[df['prediction_class'] == class_name]
            if not class_df.empty:
                fig.add_trace(
                    go.Box(
                        y=class_df['flow_bytes_per_sec'],
                        name=class_name,
                        marker_color=color,
                        marker=dict(line=dict(width=2, color='white'))
                    ),
                    row=1, col=1
                )

        # Packet count
        for class_name, color in [('DDoS', '#dc2626'), ('BENIGN', '#059669')]:
            class_df = df[df['prediction_class'] == class_name]
            if not class_df.empty:
                fig.add_trace(
                    go.Box(
                        y=class_df['total_packets'],
                        name=class_name,
                        marker_color=color,
                        showlegend=False,
                        marker=dict(line=dict(width=2, color='white'))
                    ),
                    row=1, col=2
                )

        # Flow duration
        for class_name, color in [('DDoS', '#dc2626'), ('BENIGN', '#059669')]:
            class_df = df[df['prediction_class'] == class_name]
            if not class_df.empty:
                fig.add_trace(
                    go.Box(
                        y=class_df['flow_duration'],
                        name=class_name,
                        marker_color=color,
                        showlegend=False,
                        marker=dict(line=dict(width=2, color='white'))
                    ),
                    row=2, col=1
                )

        # Scatter: Confidence vs Bytes/sec
        fig.add_trace(
            go.Scatter(
                x=df['flow_bytes_per_sec'],
                y=df['confidence_score'],
                mode='markers',
                marker=dict(
                    color=df['is_attack'].map({True: '#dc2626', False: '#059669'}),
                    size=10,
                    line=dict(width=2, color='white')
                ),
                showlegend=False
            ),
            row=2, col=2
        )

        fig.update_layout(
            height=650,
            showlegend=True,
            plot_bgcolor='rgba(15, 23, 42, 0.5)',
            paper_bgcolor='rgba(30, 41, 59, 0.3)',
            font=dict(family='Arial', size=12, color='#cbd5e1')
        )

        fig.update_xaxes(showgrid=True, gridwidth=1, gridcolor='rgba(100, 116, 139, 0.1)', color='#cbd5e1')
        fig.update_yaxes(showgrid=True, gridwidth=1, gridcolor='rgba(100, 116, 139, 0.1)', color='#cbd5e1')

        st.plotly_chart(fig, width='stretch')
    
    def render_event_table(self):
        """Render detailed event table"""
        st.subheader("📋 Detailed Event Log")
        
        if not st.session_state.events:
            st.info("No events to display")
            return
        
        # Filter options
        col1, col2, col3 = st.columns(3)
        
        with col1:
            filter_class = st.selectbox("Filter by Class", ["All", "DDoS", "BENIGN"])
        
        with col2:
            filter_protocol = st.selectbox("Filter by Protocol", ["All", "TCP", "UDP", "ICMP"])
        
        with col3:
            show_last = st.slider("Show last N events", 10, 1000, 50)
        
        # Apply filters
        df = pd.DataFrame(list(st.session_state.events)[-show_last:])
        
        if filter_class != "All":
            df = df[df['prediction_class'] == filter_class]
        
        if filter_protocol != "All":
            df = df[df['protocol'] == filter_protocol]
        
        # Format DataFrame for display
        display_df = df[['timestamp', 'prediction_class', 'confidence_score', 
                        'src_ip', 'dst_ip', 'protocol', 'total_packets', 
                        'flow_bytes_per_sec']].copy()
        
        display_df['timestamp'] = pd.to_datetime(display_df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
        display_df['confidence_score'] = display_df['confidence_score'].apply(lambda x: f"{x:.2%}")
        display_df['flow_bytes_per_sec'] = display_df['flow_bytes_per_sec'].apply(lambda x: f"{x:,.0f}")
        
        st.dataframe(display_df, use_container_width=True, height=400)
    
    def render_sidebar(self):
        """Render sidebar controls"""
        with st.sidebar:
            st.header("⚙️ Dashboard Controls")
            
            # Service configuration
            st.subheader("Service Configuration")
            self.api_url = st.text_input("Detection Service URL", self.api_url)
            
            # Auto-refresh settings
            st.subheader("Auto-Refresh")
            st.session_state.auto_refresh = st.checkbox(
                "Enable Auto-Refresh",
                value=st.session_state.auto_refresh
            )
            
            st.session_state.refresh_interval = st.slider(
                "Refresh Interval (seconds)",
                1, 30, st.session_state.refresh_interval
            )
            # Export data
            st.subheader("📥 Export Data")
            if st.button("Export to CSV"):
                if st.session_state.events:
                    df = pd.DataFrame(list(st.session_state.events))
                    csv = df.to_csv(index=False)
                    st.download_button(
                        "Download CSV",
                        csv,
                        "ddos_events.csv",
                        "text/csv"
                    )
            
            # Service metrics
            st.subheader("🔧 Service Metrics")
            metrics = self.get_service_metrics()
            if metrics:
                st.code(metrics, language="text")
            else:
                st.warning("Service metrics unavailable")
    
    
    def run(self):
        """Run the dashboard"""

        # Render UI
        self.render_header()
        self.render_sidebar()

        # 🔵 جلب أحدث الأحداث من السيرفس في كل دورة
        self.fetch_events_from_api(limit=1000)
        
        # Main content tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "📊 Overview",
            "📈 Analytics",
            "🔍 Details",
            "⚙️ System"
        ])
        
        with tab1:
            self.render_metrics()
            st.markdown("---")
            self.render_live_alerts()
            st.markdown("---")
            self.render_timeline_chart()
        
        with tab2:
            col1, col2 = st.columns(2)
            with col1:
                self.render_confidence_distribution()
            with col2:
                self.render_top_sources()
            
            st.markdown("---")
            self.render_protocol_distribution()
            st.markdown("---")
            self.render_flow_characteristics()
        
        with tab3:
            self.render_event_table()
        
        with tab4:
            st.subheader("🖥️ System Information")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Events in Memory", len(st.session_state.events))
                st.metric("Max History", self.max_history)
            
            with col2:
                is_healthy = self.check_service_health()
                health_status = "🟢 Healthy" if is_healthy else "🔴 Unhealthy"
                st.metric("Service Status", health_status)
        
        # Auto-refresh
        if st.session_state.auto_refresh:
            time.sleep(st.session_state.refresh_interval)
            st.rerun()


def main():
    """Main entry point"""
    import os
    api_url = os.getenv("DETECTOR_SERVICE_URL", "http://localhost:8000")
    dashboard = DDoSDashboard(
        api_url=api_url,
        max_history=1000
    )
    dashboard.run()


if __name__ == "__main__":
    main()