import streamlit as st
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import time
import requests
from confluent_kafka import Consumer, KafkaError
from streamlit_autorefresh import st_autorefresh
from pyvis.network import Network
import streamlit.components.v1 as components
import networkx as nx
import tempfile
import os

# PostgreSQL config
DB_HOST = "localhost"
DB_NAME = "hornet7_db"
DB_USER = "postgres"
DB_PASS = "Serigala76!"  # Change this

# Kafka config
KAFKA_BROKER = "10.0.2.15:9092"
KAFKA_GROUP = "streamlit_consumer_group"
KAFKA_TOPIC = "cowrie_logs"

# Telegram Bot config
TELEGRAM_TOKEN = "8083560973:AAGoQstYrKVGVSIincqQ3r_MyGvurDVtNMo"
TELEGRAM_CHAT_ID = "623056896"

# Send simplified Telegram alert
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

# DB Connection
@st.cache_resource
def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        cursor_factory=RealDictCursor
    )

# Load PostgreSQL data
def load_data():
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM hornet7_data ORDER BY timestamp DESC LIMIT 1000;")
        rows = cur.fetchall()
        return pd.DataFrame(rows)

# Insert row
def insert_row(data):
    conn = get_connection()
    with conn.cursor() as cur:
        placeholders = ', '.join(['%s'] * len(data))
        columns = ', '.join(data.keys())
        sql = f"INSERT INTO hornet7_data ({columns}) VALUES ({placeholders})"
        cur.execute(sql, list(data.values()))
        conn.commit()
    # Send Telegram alert
    send_telegram_alert(data, source="Manual")

# Delete row by session
def delete_row(session_id):
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM hornet7_data WHERE session = %s", (session_id,))
        conn.commit()

# Update message field by session
def update_message(session_id, new_message):
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("UPDATE hornet7_data SET message = %s WHERE session = %s", (new_message, session_id))
        conn.commit()

# Kafka to PostgreSQL Ingest
def fetch_kafka_and_insert():
    consumer_config = {
        'bootstrap.servers': KAFKA_BROKER,
        'group.id': KAFKA_GROUP,
        'auto.offset.reset': 'latest'
    }
    consumer = Consumer(consumer_config)
    consumer.subscribe([KAFKA_TOPIC])

    conn = get_connection()
    with conn.cursor() as cur:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                break
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    st.error(f"Kafka error: {msg.error()}")
                continue
            try:
                log = json.loads(msg.value().decode("utf-8"))
                columns = ', '.join(log.keys())
                values = ', '.join(['%s'] * len(log))
                sql = f"INSERT INTO hornet7_data ({columns}) VALUES ({values}) ON CONFLICT DO NOTHING"
                cur.execute(sql, list(log.values()))
                conn.commit()
                # Send Telegram alert
                send_telegram_alert(log, source="Kafka")
            except Exception as e:
                st.error(f"Failed to insert Kafka message: {e}")
    consumer.close()

# Build Graph from a session
def build_attack_graph(row):
    G = nx.DiGraph()
    nodes = set()

    # Example: src_ip → eventid → dst_port
    if row.get('src_ip'):
        nodes.add(row['src_ip'])
    if row.get('eventid'):
        nodes.add(row['eventid'])
    if row.get('dst_port'):
        nodes.add(str(row['dst_port']))

    nodes = list(nodes)
    if len(nodes) > 1:
        for i in range(len(nodes) - 1):
            G.add_edge(nodes[i], nodes[i + 1])
    elif nodes:
        G.add_node(nodes[0]) # Add a single node if that's all we have

    return G

# Streamlit Dashboard UI
st.set_page_config(page_title="GraphPot Dashboard", layout="wide")
st.title("🛡️ GraphPot Dashboard (PostgreSQL)")

# Auto-refresh every 20 seconds
st_autorefresh(interval=20 * 1000, key="refresh")

# Load data
df = load_data()

if not df.empty:
    st.dataframe(df, use_container_width=True)

    top_ips = df['src_ip'].value_counts().head(3).index.tolist()
    top_sessions = df['session'].value_counts().head(3).index.tolist()
    top_events = df['eventid'].value_counts().head(3).index.tolist()

    moving_text = f"Top IPs: {', '.join(top_ips)} | Top Sessions: {', '.join(top_sessions)} | Top Events: {', '.join(top_events)}"
    st.markdown(
        f'<marquee style="font-size: 18px; color: black; background-color: white; padding: 10px;">{moving_text}</marquee>',
        unsafe_allow_html=True
    )

    st.subheader("🔄 CRUD Operations")

    with st.expander("➕ Insert New Row"):
        new_data = {}
        for col in df.columns:
            new_data[col] = st.text_input(f"{col}", key=f"insert_{col}")
        if st.button("Insert"):
            insert_row(new_data)
            st.success("Inserted! Refreshing...")
            st.rerun()

    with st.expander("✏️ Update Message by Session ID"):
        sid = st.text_input("Session ID:")
        new_msg = st.text_input("New Message:")
        if st.button("Update"):
            update_message(sid, new_msg)
            st.success("Updated! Refreshing...")
            st.rerun()

    with st.expander("❌ Delete by Session ID"):
        sid_del = st.text_input("Session ID to delete:")
        if st.button("Delete"):
            delete_row(sid_del)
            st.warning("Deleted! Refreshing...")
            st.rerun()
else:
    st.warning("⚠️ No data found.")
# ================================
# Attack Graph Modeling (with colors)
# ================================
st.subheader("🕸️ Attack Graph Visualization")

def generate_attack_graph_combined(df):
    net = Network(height="600px", width="100%", bgcolor="#222222", font_color="white", directed=True)
    net.barnes_hut()  # Enables force-directed physics
    added_nodes = set()

    for idx, row in df.iterrows():
        src_ip = row.get('src_ip')
        dst_ip = row.get('dst_ip')
        session = row.get('session')
        eventid = row.get('eventid')
        dst_port = row.get('dst_port')

        # Add nodes with more informative labels and titles
        if src_ip and src_ip not in added_nodes:
            net.add_node(src_ip, label=f"Source: {src_ip}", title=f"Source IP: {src_ip}", color="red", size=15)
            added_nodes.add(src_ip)
        if dst_ip and dst_ip not in added_nodes:
            net.add_node(dst_ip, label=f"Dest: {dst_ip}", title=f"Destination IP: {dst_ip}", color="blue", size=15)
            added_nodes.add(dst_ip)
        if session and session not in added_nodes:
            net.add_node(session, label=f"Session: {session[:8]}...", title=f"Session ID: {session}", color="green", size=10)
            added_nodes.add(session)
        if eventid and eventid not in added_nodes:
            net.add_node(eventid, label=f"Event: {eventid}", title=f"Event ID: {eventid}", color="orange", size=10)
            added_nodes.add(eventid)
        if dst_port is not None and str(dst_port) not in added_nodes:
            net.add_node(str(dst_port), label=f"Port: {dst_port}", title=f"Destination Port: {dst_port}", color="lightblue", size=10)
            added_nodes.add(str(dst_port))

        # Add edges based on the flow
        if src_ip and dst_ip:
            net.add_edge(src_ip, dst_ip, title="Initiated Connection")
        if src_ip and eventid:
            net.add_edge(src_ip, eventid, title="Triggered Event")
        if eventid and dst_port is not None:
            net.add_edge(eventid, str(dst_port), title="Targeted Port")
        if session and src_ip:
            net.add_edge(session, src_ip, title="Belongs to Session", color="gray", width=0.5)
        if session and dst_ip:
            net.add_edge(session, dst_ip, title="Related to Session", color="gray", width=0.5)

    # Save and read the HTML
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp_file:
        net.save_graph(tmp_file.name)
        graph_html = tmp_file.read().decode("utf-8")
        temp_file_path = tmp_file.name
    components.html(graph_html, height=600, scrolling=True)
    os.unlink(temp_file_path) # Clean up the temporary file

if not df.empty:
    generate_attack_graph_combined(df)

    st.subheader("📝 Auto-Generated Attack Descriptions")
    for idx, row in df.iterrows():
        src_ip = row.get('src_ip', 'Unknown')
        dst_ip = row.get('dst_ip', 'Unknown')
        eventid = row.get('eventid', 'Unknown')
        session = row.get('session', 'Unknown')
        message = row.get('message', 'No message provided.')
        timestamp = row.get('timestamp', 'Unknown time')
        dst_port = row.get('dst_port', 'N/A')

        st.markdown(f"""
        **Log {idx+1}:**
        - **Source IP:** {src_ip}
        - **Destination IP:** {dst_ip}
        - **Destination Port:** {dst_port}
        - **Event ID:** {eventid}
        - **Session:** {session}
        - **Timestamp:** {timestamp}
        - **Message:** {message}
        """)
        st.markdown("---")
else:
    st.info("No data to visualize the attack graph.")
