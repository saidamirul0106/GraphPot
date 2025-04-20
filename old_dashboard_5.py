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

def generate_attack_graph(df):
    net = Network(height="600px", width="100%", bgcolor="#222222", font_color="white")
    net.barnes_hut()  # Enables force-directed physics
    added_nodes = set()

    for idx, row in df.iterrows():
        src_ip = row.get('src_ip', f"src_{idx}")
        dst_ip = row.get('dst_ip', f"dst_{idx}")
        session = row.get('session', f"session_{idx}")
        eventid = row.get('eventid', f"event_{idx}")
        message = row.get('message', "No message")

        # Add nodes with colors
        if src_ip not in added_nodes:
            net.add_node(src_ip, label=src_ip, title=f"Source IP: {src_ip}", color="red")
            added_nodes.add(src_ip)

        if dst_ip not in added_nodes:
            net.add_node(dst_ip, label=dst_ip, title=f"Destination IP: {dst_ip}", color="blue")
            added_nodes.add(dst_ip)

        if session not in added_nodes:
            net.add_node(session, label=session, title=f"Session: {session}", color="green")
            added_nodes.add(session)

        if eventid not in added_nodes:
            net.add_node(eventid, label=eventid, title=f"Event ID: {eventid}", color="orange")
            added_nodes.add(eventid)

        # Add edges
        net.add_edge(src_ip, dst_ip, title="Traffic", color="white")
        net.add_edge(session, eventid, title="Session Event", color="yellow")

    # Save and read the HTML
    net.save_graph("/tmp/attack_graph.html")
    with open("/tmp/attack_graph.html", "r", encoding="utf-8") as f:
        graph_html = f.read()
    return graph_html

if not df.empty:
    graph_html = generate_attack_graph(df)
    components.html(graph_html, height=600, scrolling=True)

    st.subheader("📝 Auto-Generated Attack Descriptions")
    for idx, row in df.iterrows():
        src_ip = row.get('src_ip', 'Unknown')
        dst_ip = row.get('dst_ip', 'Unknown')
        eventid = row.get('eventid', 'Unknown')
        session = row.get('session', 'Unknown')
        message = row.get('message', 'No message provided.')
        timestamp = row.get('timestamp', 'Unknown time')

        st.markdown(f"""
        **Log {idx+1}:**
        - **Source IP:** {src_ip}
        - **Destination IP:** {dst_ip}
        - **Event ID:** {eventid}
        - **Session:** {session}
        - **Timestamp:** {timestamp}
        - **Message:** {message}
        """)
        st.markdown("---")
