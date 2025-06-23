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
import time
from contextlib import contextmanager
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

# --- Fixed Connection Handling ---
@contextmanager
def get_connection():
    conn = None
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            port=DB_PORT,
            cursor_factory=RealDictCursor,
            sslmode='require',
            keepalives=1,
            keepalives_idle=30,
            application_name="graphpot_dash"
        )
        yield conn
    except Exception as e:
        st.error(f"Connection failed: {str(e)}")
        raise
    finally:
        if conn is not None:
            conn.close()

# --- Telegram Alert ---
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

# --- Fixed Data Functions ---
def load_data():
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM hornet7_data ORDER BY timestamp DESC LIMIT 1000;")
                rows = cur.fetchall()
                df = pd.DataFrame(rows)
                if not df.empty:
                    df['attack_type'] = df.apply(lambda row: detect_attack_type(
                        row.get('eventid', ''), 
                        row.get('input', ''), 
                        row.get('message', '')
                    ), axis=1)
                return df
    except Exception as e:
        st.error(f"Failed to load data: {str(e)}")
        return pd.DataFrame()

def insert_row(data):
    try:
        # Auto-fix empty strings to None
        for key, value in data.items():
            if value == '':
                data[key] = None

        # Remove auto-generated fields
        data.pop('id', None)
        data.pop('created_at', None)

        columns = ', '.join(data.keys())
        values_placeholder = ', '.join(['%s'] * len(data))
        
        with get_connection() as conn:
            with conn.cursor() as cur:
                sql = f"INSERT INTO hornet7_data ({columns}) VALUES ({values_placeholder})"
                cur.execute(sql, list(data.values()))
                conn.commit()
                st.success("Data inserted successfully!")
                send_telegram_alert(data, source="Manual")
                return True
    except Exception as e:
        st.error(f"Insert failed: {str(e)}")
        return False

def update_row(row_id, data):
    try:
        # Skip 'id' field
        if 'id' in data:
            data.pop('id')

        # Remove any empty strings
        data = {k: v for k, v in data.items() if v not in [None, ""]}

        # Auto-reassign attack_type if relevant fields changed
        if any(k in data for k in ['eventid', 'input', 'message']):
            eventid = data.get('eventid', '')
            input_cmd = data.get('input', '')
            message = data.get('message', '')
            data['attack_type'] = detect_attack_type(eventid, input_cmd, message)

        if not data:
            return True  # No update needed

        set_clause = ', '.join([f"{col} = %s" for col in data.keys()])
        values = list(data.values())
        values.append(row_id)

        with get_connection() as conn:
            with conn.cursor() as cur:
                sql = f"UPDATE hornet7_data SET {set_clause} WHERE id = %s"
                cur.execute(sql, values)
                conn.commit()
                st.success("Update successful!")
                
                # Send Telegram Alert
                send_telegram_alert({
                    "src_ip": data.get("src_ip", "N/A"),
                    "eventid": data.get("eventid", "N/A"),
                    "message": f"Session ID {row_id} has been updated.",
                    "timestamp": data.get("timestamp", datetime.now().isoformat())
                }, source="Update")
                return True
    except Exception as e:
        st.error(f"Update failed: {str(e)}")
        return False

def delete_row(session_id):
    try:
        # First verify existence
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM hornet7_data WHERE session = %s LIMIT 1", (session_id,))
                if not cur.fetchone():
                    st.error(f"Session {session_id} not found!")
                    return False

        # Send alert before deletion
        send_telegram_alert({
            "src_ip": "N/A",
            "eventid": "Session Deleted",
            "message": f"Session {session_id} marked for deletion",
            "timestamp": datetime.now().isoformat()
        }, source="Delete")

        # Execute deletion
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM hornet7_data WHERE session = %s", (session_id,))
                conn.commit()
                st.success(f"Session {session_id} deleted successfully")
                return True
    except Exception as e:
        st.error(f"Delete failed: {str(e)}")
        # Send failure alert
        send_telegram_alert({
            "src_ip": "N/A",
            "eventid": "Delete Failed",
            "message": f"Failed to delete session {session_id}: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }, source="Error")
        return False

# --- Original Helper Functions ---
def detect_attack_type(eventid, input_command, message):
    if not eventid:
        return "Unknown Activity"
    
    input_command = (input_command or "").lower()
    message = (message or "").lower()

    if eventid == "cowrie.login.failed":
        return "Brute Force Attack"
    elif eventid == "cowrie.login.success":
        return "Successful Login"
    elif eventid == "cowrie.command.input":
        if any(keyword in input_command for keyword in ["wget", "curl", ".sh", ".bin"]):
            return "Malware Download Attempt"
        elif any(keyword in input_command for keyword in ["rm -rf", "dd if=", ":(){ :|:& };:"]):
            return "Destructive Attack (Wiper)"
        elif any(keyword in input_command for keyword in ["cat /etc/passwd", "uname -a", "whoami", "busybox"]):
            return "Reconnaissance / Enumeration"
        else:
            return "Command Injection Attempt"
    elif eventid == "cowrie.session.connect":
        return "Port Scanning / Connection Attempt"
    else:
        return "Unknown Activity"

def build_session_graph(row):
    G = nx.DiGraph()
    src_ip = row.get('src_ip')
    eventid = row.get('eventid')
    dst_port = row.get('dst_port')

    if src_ip:
        G.add_node(src_ip, label=f"Source: {src_ip}", color="lightblue")
    if eventid:
        G.add_node(eventid, label=f"Event: {eventid}", color="orange")
    if dst_port:
        port_node = f"Port {dst_port}"
        G.add_node(port_node, label=port_node, color="lightgreen")

    if src_ip and eventid:
        G.add_edge(src_ip, eventid, title=f"{src_ip} triggered {eventid}")
    if eventid and dst_port:
        G.add_edge(eventid, f"Port {dst_port}", title=f"{eventid} targeted port {dst_port}")

    return G

def generate_description(row):
    return f"Session {row.get('session', 'N/A')} from {row.get('src_ip', 'Unknown IP')} attempted {row.get('eventid', 'unknown event')} on port {row.get('dst_port', 'unknown port')}."

# --- Streamlit UI ---
st.set_page_config(page_title="GraphPot - Network Session Analysis", layout="wide")
st.title("🛡️ GraphPot - Network Session Analysis")

# Refresh button
if st.button("🔄 Refresh"):
    st.rerun()

st.markdown("---")

# Load Data
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

    # Moving Marquee
    top_ips = df['src_ip'].value_counts().head(3).index.tolist()
    top_sessions = df['session'].value_counts().head(3).index.tolist()
    top_events = df['eventid'].value_counts().head(3).index.tolist()

    moving_text = f"Top IPs: {', '.join(top_ips)} | Top Sessions: {', '.join(top_sessions)} | Top Events: {', '.join(top_events)}"
    st.markdown(
        f'<marquee style="font-size: 18px; color: black; background-color: white; padding: 10px;">{moving_text}</marquee>',
        unsafe_allow_html=True
    )

    st.markdown("---")

    with st.expander("➕ Insert New Row"):
        new_data = {}
        for col in df.columns:
            if col not in ["attack_type", "id", "created_at"]:
                new_data[col] = st.text_input(f"{col}", key=f"insert_{col}")
        if st.button("Insert"):
            if insert_row(new_data):
                st.rerun()

    with st.expander("✏️ Update Sessions"):
        row_id_to_update = st.text_input("Row ID to update")
        if row_id_to_update:
            updated_data = {}
            for col in df.columns:
                if col not in ["attack_type", "id", "created_at"]:
                    updated_data[col] = st.text_input(f"{col} (new value)", key=f"update_{col}")
            if st.button("Update"):
                if update_row(row_id_to_update, updated_data):
                    st.rerun()

    with st.expander("❌ Delete by Session ID"):
        sid_del = st.text_input("Session ID to delete:")
        if st.button("Delete"):
            if delete_row(sid_del):
                st.rerun()

    st.markdown("---")

    # Network Session Mapping
    st.subheader("🧠 Network Session Mapping")

    selected_session = st.selectbox(
        "Select a Session ID to visualize:",
        options=df['session'].unique()
    )

    if selected_session:
        selected_row = df[df['session'] == selected_session].iloc[0]
        G = build_session_graph(selected_row)
        description = generate_description(selected_row)

        net = Network(height="600px", width="100%", directed=True, notebook=False)
        net.barnes_hut()

        for node, data in G.nodes(data=True):
            net.add_node(node, label=data.get("label", node), color=data.get("color", "grey"))

        for src, dst, edge_data in G.edges(data=True):
            title = edge_data.get("title", f"{src} -> {dst}")
            net.add_edge(src, dst, title=title, arrows="to")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
            net.save_graph(tmp_file.name)
            components.html(open(tmp_file.name, 'r', encoding='utf-8').read(), height=650)
        os.unlink(tmp_file.name)

        # Session Overview
        attack = detect_attack_type(selected_row.get('eventid', ''), selected_row.get('input', ''), selected_row.get('message', ''))
        session_info = f"📄 **Session Overview:** {description}\n\n🛡️ Detected Attack Type: `{attack}`"

        if attack == "Destructive Attack (Wiper)":
            st.error(session_info)
        elif attack == "Malware Download Attempt":
            st.warning(session_info)
        elif attack in ["Brute Force Attack", "Reconnaissance / Enumeration"]:
            st.info(session_info)
        else:
            st.success(session_info)

else:
    st.warning("⚠️ No data found.")
