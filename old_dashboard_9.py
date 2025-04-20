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

# --- PostgreSQL Config ---
DB_HOST = "localhost"
DB_NAME = "hornet7_db"
DB_USER = "postgres"
DB_PASS = "Serigala76!"  # Update this securely in production

# --- Kafka Config ---
KAFKA_BROKER = "10.0.2.15:9092"
KAFKA_GROUP = "streamlit_consumer_group"
KAFKA_TOPIC = "cowrie_logs"

# --- Telegram Bot Config ---
TELEGRAM_TOKEN = "8083560973:AAGoQstYrKVGVSIincqQ3r_MyGvurDVtNMo"
TELEGRAM_CHAT_ID = "623056896"

# --- Functions ---
def send_telegram_alert(data, source="Manual"):
    """Send simplified Telegram alert."""
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
    """Create a cached database connection."""
    return psycopg2.connect(
        host=DB_HOST,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        cursor_factory=RealDictCursor
    )

def load_data():
    """Load recent data from PostgreSQL."""
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM hornet7_data ORDER BY timestamp DESC LIMIT 1000;")
        rows = cur.fetchall()
        return pd.DataFrame(rows)

def insert_row(data):
    """Insert a new row into the database."""
    conn = get_connection()
    with conn.cursor() as cur:
        placeholders = ', '.join(['%s'] * len(data))
        columns = ', '.join(data.keys())
        sql = f"INSERT INTO hornet7_data ({columns}) VALUES ({placeholders})"
        cur.execute(sql, list(data.values()))
        conn.commit()
    send_telegram_alert(data, source="Manual")

def delete_row(session_id):
    """Delete a row by session ID."""
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM hornet7_data WHERE session = %s", (session_id,))
        conn.commit()

def update_message(session_id, new_message):
    """Update the message field by session ID."""
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("UPDATE hornet7_data SET message = %s WHERE session = %s", (new_message, session_id))
        conn.commit()

def fetch_kafka_and_insert():
    """Fetch new logs from Kafka and insert them."""
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
                send_telegram_alert(log, source="Kafka")
            except Exception as e:
                st.error(f"Failed to insert Kafka message: {e}")
    consumer.close()

def save_attack_graph(session_id, G, description):
    """Save graph metadata to database."""
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

def generate_description(row):
    """Generate a simple textual description."""
    return f"Session {row.get('session', 'N/A')} from {row.get('src_ip', 'Unknown IP')} attempted {row.get('eventid', 'unknown event')} on port {row.get('dst_port', 'unknown port')}."

def build_attack_graph(row):
    G = nx.DiGraph()

    src_ip = row.get('src_ip')
    event = row.get('eventid')
    dst_port = row.get('dst_port')

    if src_ip:
        G.add_node(src_ip, label=src_ip, type="source")
    if event:
        G.add_node(event, label=event, type="event")
    if dst_port:
        port_node = f"Port {dst_port}"
        G.add_node(port_node, label=port_node, type="destination")

    # Create edges with titles
    if src_ip and event:
        G.add_edge(src_ip, event, title="Trigger Event")
    if event and dst_port:
        port_node = f"Port {dst_port}"
        G.add_edge(event, port_node, title="Target Port")

    return G


# --- Streamlit Dashboard ---
st.set_page_config(page_title="GraphPot", layout="wide")
st.title("🛡️ GraphPot - Network Session Analysis")

st_autorefresh(interval=20 * 1000, key="refresh")

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

    st.subheader("🔄 Manage Sessions")

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

    st.subheader("🎯 Network Session Mapping")

    selected_session = st.selectbox(
        "Select Session ID for Graph View:",
        options=df['session'].unique()
    )

    if selected_session:
        selected_row = df[df['session'] == selected_session].iloc[0]
        graph = build_attack_graph(selected_row)

        # Save graph metadata
        description = generate_description(selected_row)
        save_attack_graph(selected_session, graph, description)

        # Create Pyvis network
        net = Network(height="550px", width="100%", directed=True)
        net.toggle_physics(True)
        net.barnes_hut(gravity=-40000, central_gravity=0.3, spring_length=150, spring_strength=0.05)

        # Set node colors and shapes based on type
        for node, data in graph.nodes(data=True):
            node_type = data.get('type', 'other')
            if node_type == "source":
                net.add_node(node, label=data['label'], color="red", shape="dot", title=f"Source IP: {node}")
            elif node_type == "event":
                net.add_node(node, label=data['label'], color="orange", shape="diamond", title=f"Event: {node}")
            elif node_type == "destination":
                net.add_node(node, label=data['label'], color="blue", shape="square", title=f"Destination Port: {node}")
            else:
                net.add_node(node, label=data['label'], color="gray", shape="ellipse", title=node)

        # Add edges with hoverable titles
        for src, dst, edata in graph.edges(data=True):
            title = edata.get('title', 'Connection')
            net.add_edge(src, dst, title=title, arrows="to")

        # Render to temporary HTML
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
            path = tmp_file.name
            net.save_graph(path)
            components.html(open(path, 'r', encoding='utf-8').read(), height=600)
            os.unlink(path)

        # Show description
        st.info(f"📄 Session Overview:\n\n{description}")

else:
    st.warning("⚠️ No data found.")
