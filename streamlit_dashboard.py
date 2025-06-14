import streamlit as st
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import requests
from confluent_kafka import Consumer, KafkaError
from streamlit_autorefresh import st_autorefresh
from pyvis.network import Network
import streamlit.components.v1 as components
import networkx as nx
import tempfile
import os
import re
from datetime import datetime

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

BRUTE_FORCE_THRESHOLD = 5

# --- Fixed Functions ---

def send_telegram_alert(data, source="Manual"):
    try:
        alert_message = (
            f"🚨 <b>New {source} Data Inserted</b>\n\n"
            f"<b>Source IP:</b> {data.get('src_ip', 'N/A')}\n"
            f"<b>Event:</b> {data.get('eventid', 'N/A')}\n"
            f"<b>Message:</b> {data.get('message', 'N/A')}\n"
            f"<b>Time:</b> {data.get('timestamp', 'N/A')}"
        )
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": alert_message,
            "parse_mode": "HTML"
        }
        requests.post(url, data=payload)
    except Exception as e:
        st.error(f"Failed to send Telegram alert: {e}")

@st.cache_resource
def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        port=DB_PORT,
        cursor_factory=RealDictCursor,
        sslmode='require'
    )

def detect_attack_type(row):
    """Fixed to always return tuple (attack_type, details)"""
    eventid = row.get('eventid', '').lower()
    input_cmd = str(row.get('input', '')).lower()
    message = str(row.get('message', '')).lower()
    
    attack_type = "Unknown Activity"
    details = message[:100] if message else "No details"
    
    if eventid == 'cowrie.login.failed':
        attack_type = "Brute Force Attack"
        details = f"Failed login attempt from {row.get('src_ip')}"
    elif eventid == 'cowrie.login.success':
        attack_type = "Successful Login"
    elif eventid == 'cowrie.command.input':
        if any(re.search(p, input_cmd) for p in WIPER_PATTERNS):
            attack_type = "Destructive Attack (Wiper)"
            details = f"Wiper command: {input_cmd[:50]}..."
        elif any(re.search(p, input_cmd) for p in MALWARE_PATTERNS):
            attack_type = "Malware Download Attempt"
            details = f"Download attempt: {input_cmd[:50]}..."
        elif any(re.search(p, input_cmd) for p in RECON_PATTERNS):
            attack_type = "Reconnaissance / Enumeration"
            details = f"Recon command: {input_cmd[:50]}..."
        else:
            attack_type = "Command Injection Attempt"
    elif eventid == 'cowrie.session.connect':
        attack_type = "Port Scanning / Connection Attempt"
        details = f"Connection to port {row.get('dst_port')}"
    
    return attack_type, details

def load_data():
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM hornet7_data ORDER BY timestamp DESC LIMIT 1000;")
        rows = cur.fetchall()
    df = pd.DataFrame(rows)
    
    # Fixed DataFrame assignment
    df[['attack_type', 'attack_details']] = df.apply(
        lambda x: pd.Series(detect_attack_type(x)), 
        axis=1
    )
    return df

# --- Enhanced Graph Modeling ---
def build_session_graph(row):
    G = nx.DiGraph()
    src_ip = row.get('src_ip')
    eventid = row.get('eventid')
    dst_port = row.get('dst_port')
    timestamp = row.get('timestamp')
    attack_type, details = detect_attack_type(row)

    # Node styling based on attack type
    node_colors = {
        "Brute Force Attack": "#FF6B6B",
        "Destructive Attack (Wiper)": "#FF0000",
        "Malware Download Attempt": "#FFA500",
        "Reconnaissance / Enumeration": "#ADD8E6",
        "Port Scanning / Connection Attempt": "#90EE90"
    }
    
    # Add nodes with enhanced information
    if src_ip:
        G.add_node(src_ip, 
                  label=f"Attacker\n{src_ip}",
                  color=node_colors.get(attack_type, "lightblue"),
                  title=f"First seen: {timestamp}",
                  shape="box")
    
    if eventid:
        G.add_node(eventid, 
                  label=f"Event\n{eventid}",
                  color="#F0F0F0",
                  title=details,
                  shape="ellipse")
    
    if dst_port:
        port_node = f"Port {dst_port}"
        G.add_node(port_node, 
                  label=port_node,
                  color="#D8BFD8",
                  shape="diamond")
    
    # Add edges with attack details
    if src_ip and eventid:
        G.add_edge(src_ip, eventid, 
                  title=f"Attack Type: {attack_type}\n{details}",
                  color=node_colors.get(attack_type, "grey"))
    
    if eventid and dst_port:
        G.add_edge(eventid, f"Port {dst_port}", 
                  title=f"Target port {dst_port}",
                  color="#888888")
    
    return G

# --- Original Dashboard Layout ---
st.set_page_config(page_title="GraphPot - Network Session Analysis", layout="wide")
st.title("🛡️ GraphPot - Network Session Analysis")

if st.button("🔄 Refresh"):
    st.rerun()

st.markdown("---")

df = load_data()

if not df.empty:
    # --- Summary Metrics ---
    st.subheader("📊 Attack Summary")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🔒 Brute Force", (df['attack_type'] == "Brute Force Attack").sum())
    col2.metric("🐍 Malware Download", (df['attack_type'] == "Malware Download Attempt").sum())
    col3.metric("🔥 Wiper Attack", (df['attack_type'] == "Destructive Attack (Wiper)").sum())
    col4.metric("🕵️ Reconnaissance", (df['attack_type'] == "Reconnaissance / Enumeration").sum())

    st.markdown("---")

    # Highlight Table
    def highlight_rows(row):
        if row['attack_type'] == 'Destructive Attack (Wiper)':
            return ['background-color: #FFB6B6'] * len(row)
        elif row['attack_type'] == 'Malware Download Attempt':
            return ['background-color: #FFF3CD'] * len(row)
        elif row['attack_type'] == 'Brute Force Attack':
            return ['background-color: #D1ECF1'] * len(row)
        elif row['attack_type'] == 'Reconnaissance / Enumeration':
            return ['background-color: #E2E3E5'] * len(row)
        else:
            return [''] * len(row)

    st.subheader("📋 Latest Captured Sessions")
    attack_filter = st.selectbox("🔍 Filter by Attack Type:", options=["All"] + sorted(df['attack_type'].unique()))

    if attack_filter != "All":
        df = df[df['attack_type'] == attack_filter]

    st.dataframe(df.style.apply(highlight_rows, axis=1), use_container_width=True)

    st.markdown("---")

    # Network Session Mapping
    st.subheader("🧠 Enhanced Attack Graph")
    selected_session = st.selectbox(
        "Select a Session ID to visualize:",
        options=df['session'].unique()
    )

    if selected_session:
        selected_row = df[df['session'] == selected_session].iloc[0]
        G = build_session_graph(selected_row)
        
        # Enhanced PyVis visualization
        net = Network(height="700px", width="100%", directed=True, notebook=False)
        net.barnes_hut(
            gravity=-1000,
            central_gravity=0.3,
            spring_length=200,
            spring_strength=0.05,
            damping=0.09,
            overlap=0.5
        )
        
        # Add nodes with custom properties
        for node, data in G.nodes(data=True):
            net.add_node(
                node, 
                label=data.get("label", node),
                color=data.get("color", "#97C2FC"),
                shape=data.get("shape", "dot"),
                title=data.get("title", ""),
                size=25 if "Attacker" in str(data.get("label", "")) else 20
            )
        
        # Add edges with custom properties
        for src, dst, data in G.edges(data=True):
            net.add_edge(
                src, dst,
                title=data.get("title", ""),
                color=data.get("color", "gray"),
                width=2,
                arrows="to"
            )
        
        # Generate and display the graph
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
            net.save_graph(tmp_file.name)
            components.html(open(tmp_file.name, 'r', encoding='utf-8').read(), height=750)
        os.unlink(tmp_file.name)

        # Session Overview
        attack_info = f"""
        📄 **Session Overview**  
        **Source IP:** {selected_row.get('src_ip', 'N/A')}  
        **Attack Type:** `{selected_row['attack_type']}`  
        **Target Port:** {selected_row.get('dst_port', 'N/A')}  
        **First Seen:** {selected_row.get('timestamp', 'N/A')}  
        **Details:** {selected_row.get('attack_details', 'N/A')}
        """
        
        if selected_row['attack_type'] == "Destructive Attack (Wiper)":
            st.error(attack_info)
        elif selected_row['attack_type'] == "Malware Download Attempt":
            st.warning(attack_info)
        elif selected_row['attack_type'] in ["Brute Force Attack", "Reconnaissance / Enumeration"]:
            st.info(attack_info)
        else:
            st.success(attack_info)

else:
    st.warning("⚠️ No data found.")

# Auto-refresh every 60 seconds
st_autorefresh(interval=60000, key="data_refresh")
