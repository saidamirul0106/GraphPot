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

# Save graph metadata
def save_attack_graph(session_id, G, description):
    conn = get_connection()
    with conn.cursor() as cur:
        nodes = list(G.nodes())
        edges = [{'from': u, 'to': v} for u, v in G.edges()]
        cur.execute("""
            INSERT INTO attack_graphs (session_id, nodes, edges, description)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (session_id) DO NOTHING;
        """, (session_id, json.dumps(nodes), json.dumps(edges), description))
        conn.commit()

# Generate description
def generate_description(row):
    return f"Session {row.get('session', 'N/A')} from {row.get('src_ip', 'Unknown IP')} attempted {row.get('eventid', 'unknown event')} on port {row.get('dst_port', 'unknown port')}."

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
st.title("🛡️ GraphPot Dashboard")

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

    st.subheader("🔄 Operations")

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

    st.subheader("🎯 Attack Graph Modelling")

    # Dropdown to select session_id
    selected_session = st.selectbox(
        "Select a Session ID to visualize:",
        options=df['session'].unique()
    )

    if selected_session:
        selected_row = df[df['session'] == selected_session].iloc[0]
        graph = build_attack_graph(selected_row)

        # Save graph metadata
        description = generate_description(selected_row)
        save_attack_graph(selected_session, graph, description)

        # Visualize using Pyvis
        net = Network(height="500px", width="100%", directed=True)
        for node in graph.nodes():
            net.add_node(node, label=node)
        for edge in graph.edges():
            net.add_edge(edge[0], edge[1])

        # Render the graph to HTML
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
        path = tmp_file.name
        net.save_graph(path)
        components.html(open(path, 'r', encoding='utf-8').read(), height=550)
        os.unlink(path)	

        # Show description
        st.info(f"📄 Description:\n\n{description}")

else:
    st.warning("⚠️ No data found.")
