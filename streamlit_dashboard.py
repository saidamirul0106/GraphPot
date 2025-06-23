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

# --- Telegram Alert (Unchanged) ---
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

# --- Fixed Load Data ---
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

# --- Fixed Insert Function ---
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

# --- Fixed Delete Function ---
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
            "timestamp": pd.Timestamp.now().isoformat()
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
            "timestamp": pd.Timestamp.now().isoformat()
        }, source="Error")
        return False

# --- Rest of your unchanged functions ---
# (detect_attack_type, build_session_graph, generate_description, etc.)
# ...

# --- Streamlit UI (Completely Unchanged) ---
st.set_page_config(page_title="GraphPot - Network Session Analysis", layout="wide")
st.title("🛡️ GraphPot - Network Session Analysis")

if st.button("🔄 Refresh"):
    st.rerun()

# ... [Rest of your existing UI code] ...

with st.expander("➕ Insert New Row"):
    new_data = {}
    for col in df.columns:
        if col not in ["attack_type", "id", "created_at"]:
            new_data[col] = st.text_input(f"{col}", key=f"insert_{col}")
    if st.button("Insert"):
        if insert_row(new_data):
            st.rerun()

with st.expander("❌ Delete by Session ID"):
    sid_del = st.text_input("Session ID to delete:")
    if st.button("Delete"):
        if delete_row(sid_del):
            st.rerun()

# ... [Rest of your existing dashboard code] ...
