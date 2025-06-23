import streamlit as st
st.set_page_config(page_title="GraphPot - Network Session Analysis", layout="wide")

import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
from pyvis.network import Network
import streamlit.components.v1 as components
import networkx as nx
import tempfile
import os
from contextlib import contextmanager
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

# Initialize auto-refresh
st_autorefresh(interval=30000, key="data_refresh")

# --- Configuration ---
DB_HOST = "aws-0-ap-southeast-1.pooler.supabase.com"
DB_NAME = "postgres"
DB_USER = "postgres.ypsdflhceqxrjwyxvclr"
DB_PASS = "Serigala76!"
DB_PORT = "5432"
TELEGRAM_TOKEN = "8083560973:AAGoQstYrKVGVSIincqQ3r_MyGvurDVtNMo"
TELEGRAM_CHAT_ID = "623056896"

# --- Connection Handling ---
@contextmanager
def get_connection():
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
        connect_timeout=5
    )
    try:
        yield conn
    finally:
        conn.close()

# --- Telegram Alert ---
def send_telegram_alert(data, source="Manual"):
    try:
        attack_type = detect_attack_type(data.get('eventid'), data.get('input'), data.get('message'))
        alert_message = (
            f"🚨 <b>New {source} Alert</b>\n\n"
            f"<b>Type:</b> {attack_type}\n"
            f"<b>Source IP:</b> {data.get('src_ip', 'N/A')}\n"
            f"<b>Event:</b> {data.get('eventid', 'N/A')}\n"
            f"<b>Message:</b> {data.get('message', 'N/A')}\n"
            f"<b>Time:</b> {data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}"
        )
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": alert_message,
                "parse_mode": "HTML"
            },
            timeout=5
        )
    except Exception as e:
        st.error(f"Failed to send Telegram alert: {str(e)}")

# --- Attack Detection ---
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
        if any(k in input_command for k in ["wget", "curl", ".sh", ".bin"]):
            return "Malware Download Attempt"
        elif any(k in input_command for k in ["rm -rf", "dd if=", ":(){ :|:& };:"]):
            return "Destructive Attack (Wiper)"
        elif any(k in input_command for k in ["cat /etc/passwd", "uname -a", "whoami"]):
            return "Reconnaissance / Enumeration"
    elif eventid == "cowrie.session.connect":
        return "Port Scanning / Connection Attempt"
    else:
        return "Unknown Activity"

# --- Data Functions ---
def load_data():
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM hornet7_data ORDER BY timestamp DESC LIMIT 1000")
                df = pd.DataFrame(cur.fetchall())
                if not df.empty:
                    df['attack_type'] = df.apply(
                        lambda row: detect_attack_type(
                            row.get('eventid'), 
                            row.get('input'), 
                            row.get('message')
                        ), 
                        axis=1
                    )
                return df
    except Exception as e:
        st.error(f"Failed to load data: {str(e)}")
        return pd.DataFrame()

def insert_row(data):
    try:
        # Auto-detect attack type before insertion
        data['attack_type'] = detect_attack_type(
            data.get('eventid'),
            data.get('input'),
            data.get('message')
        )
        
        # Clean empty strings
        data = {k: (None if v == '' else v) for k, v in data.items()}
        data.pop('id', None)
        data.pop('created_at', None)
        
        with get_connection() as conn:
            with conn.cursor() as cur:
                columns = ', '.join(data.keys())
                placeholders = ', '.join(['%s'] * len(data))
                cur.execute(
                    f"INSERT INTO hornet7_data ({columns}) VALUES ({placeholders})",
                    list(data.values())
                )
                conn.commit()
                send_telegram_alert(data, "Manual")
                return True
    except Exception as e:
        st.error(f"Insert failed: {str(e)}")
        return False

def update_row(row_id, data):
    try:
        data.pop('id', None)
        data = {k: v for k, v in data.items() if v not in [None, ""]}
        
        if any(k in data for k in ['eventid', 'input', 'message']):
            data['attack_type'] = detect_attack_type(
                data.get('eventid', ''),
                data.get('input', ''),
                data.get('message', '')
            )
        
        if not data:
            return True

        with get_connection() as conn:
            with conn.cursor() as cur:
                set_clause = ', '.join([f"{k} = %s" for k in data.keys()])
                values = list(data.values()) + [row_id]
                cur.execute(
                    f"UPDATE hornet7_data SET {set_clause} WHERE id = %s",
                    values
                )
                conn.commit()
                send_telegram_alert(
                    {
                        "src_ip": data.get("src_ip", "N/A"),
                        "eventid": "update",
                        "message": f"Updated row {row_id}",
                        "attack_type": data.get("attack_type", "Unknown")
                    },
                    "Update"
                )
                return True
    except Exception as e:
        st.error(f"Update failed: {str(e)}")
        return False

def delete_row(session_id):
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM hornet7_data WHERE id = %s LIMIT 1", (id,))
                if not cur.fetchone():
                    st.error(f"Session {session_id} not found!")
                    return False
                
                cur.execute("DELETE FROM hornet7_data WHERE  = %s", (id,))
                conn.commit()
                send_telegram_alert(
                    {
                        "src_ip": "N/A", 
                        "eventid": "delete", 
                        "message": f"Deleted session {session_id}"
                    },
                    "Delete"
                )
                return True
    except Exception as e:
        st.error(f"Delete failed: {str(e)}")
        return False

# --- Visualization Helpers ---
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
        G.add_edge(eventid, port_node, title=f"{eventid} targeted port {dst_port}")

    return G

def generate_description(row):
    return f"Session {row.get('session', 'N/A')} from {row.get('src_ip', 'Unknown IP')} attempted {row.get('eventid', 'unknown event')} on port {row.get('dst_port', 'unknown port')}."

def get_attack_color(attack_type):
    color_map = {
        'Destructive Attack (Wiper)': '#FFEBEE',  # Light red
        'Malware Download Attempt': '#FFF8E1',    # Light orange
        'Brute Force Attack': '#E8F5E9',         # Light green
        'Reconnaissance / Enumeration': '#E3F2FD', # Light blue
        'Port Scanning / Connection Attempt': '#E0E0E0', # Light gray
        'Successful Login': '#E8F5E9',            # Light green
        'Unknown Activity': '#FAFAFA'             # White
    }
    return color_map.get(attack_type, '#FFFFFF')

# --- Streamlit UI ---
def main():
    st.title("🛡️ GraphPot - Network Session Analysis")

    if st.button("🔄 Refresh"):
        st.experimental_rerun()

    st.markdown("---")

    df = load_data()

    if not df.empty:
        # --- Summary Metrics ---
        st.subheader("📊 Attack Summary")
        cols = st.columns(4)
        cols[0].metric("🔒 Brute Force", (df['attack_type'] == "Brute Force Attack").sum())
        cols[1].metric("🐍 Malware Download", (df['attack_type'] == "Malware Download Attempt").sum())
        cols[2].metric("🔥 Wiper Attack", (df['attack_type'] == "Destructive Attack (Wiper)").sum())
        cols[3].metric("🕵️ Reconnaissance", (df['attack_type'] == "Reconnaissance / Enumeration").sum())

        st.markdown("---")

        # --- Moving Marquee ---
        top_ips = df['src_ip'].value_counts().head(3).index.tolist()
        top_sessions = df['session'].value_counts().head(3).index.tolist()
        top_events = df['eventid'].value_counts().head(3).index.tolist()
        
        moving_text = f"Top IPs: {', '.join(top_ips)} | Top Sessions: {', '.join(top_sessions)} | Top Events: {', '.join(top_events)}"
        st.markdown(
            f'<marquee style="color: white; background-color: #FFFFFF; padding: 10px; border-radius: 5px;">{moving_text}</marquee>',
            unsafe_allow_html=True
        )

        st.markdown("---")

        # --- Data Table ---
        st.subheader("📋 Latest Captured Sessions")
        
        def highlight_rows(row):
            colors = {
                'Destructive Attack (Wiper)': '#FFB6B6',
                'Malware Download Attempt': '#FFF3CD',
                'Brute Force Attack': '#D1ECF1',
                'Reconnaissance / Enumeration': '#E2E3E5',
                'Port Scanning / Connection Attempt': '#BDBDBD',
                'Successful Login': '#C8E6C9',
                'Unknown Activity': '#FFFFFF'
            }
            return ['background-color: ' + colors.get(row['attack_type'], '#FFFFFF')] * len(row)

        attack_filter = st.selectbox(
            "🔍 Filter by Attack Type:", 
            ["All"] + sorted(df['attack_type'].fillna("Unknown Activity").unique())
        )
        
        display_df = df if attack_filter == "All" else df[df['attack_type'] == attack_filter]
        st.dataframe(
            display_df.style.apply(highlight_rows, axis=1), 
            use_container_width=True
        )

        st.markdown("---")

        # --- Data Modification ---
        with st.expander("➕ Insert New Row"):
            new_data = {}
            for col in df.columns:
                if col not in ["attack_type", "id", "created_at"]:
                    new_data[col] = st.text_input(col, key=f"insert_{col}")
            if st.button("Insert"):
                if insert_row(new_data):
                    st.experimental_rerun()

        with st.expander("✏️ Update Sessions"):
            row_id = st.text_input("Row ID to update:")
            if row_id:
                updated_data = {}
                for col in df.columns:
                    if col not in ["attack_type", "id", "created_at"]:
                        updated_data[col] = st.text_input(
                            f"New {col}", 
                            key=f"update_{col}"
                        )
                if st.button("Update"):
                    if update_row(row_id, updated_data):
                        st.experimental_rerun()

        with st.expander("❌ Delete by Session ID"):
            session_id = st.text_input("Session ID to delete:")
            if st.button("Delete"):
                if delete_row(session_id):
                    st.experimental_rerun()

        st.markdown("---")

        # --- Network Visualization ---
        st.subheader("🧠 Network Session Mapping")
        selected_session = st.selectbox(
            "Select Session:", 
            df['session'].unique()
        )
        
        if selected_session:
            row = df[df['session'] == selected_session].iloc[0]
            G = build_session_graph(row)
            
            net = Network(height="600px", width="100%", directed=True)
            for node, attrs in G.nodes(data=True):
                net.add_node(node, **attrs)
            for src, dst, attrs in G.edges(data=True):
                net.add_edge(src, dst, **attrs)
            
            with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp:
                net.save_graph(tmp.name)
                components.html(open(tmp.name).read(), height=650)
                os.unlink(tmp.name)
            
            attack_type = detect_attack_type(
                row.get('eventid'), 
                row.get('input'), 
                row.get('message')
            )
            
            border_colors = {
                'Destructive Attack (Wiper)': '#F44336',
                'Malware Download Attempt': '#FF9800',
                'Brute Force Attack': '#4CAF50',
                'Reconnaissance / Enumeration': '#2196F3',
                'Port Scanning / Connection Attempt': '#607D8B',
                'Successful Login': '#4CAF50',
                'Unknown Activity': '#9E9E9E'
            }

            st.markdown(
                    f"""
                    <div style="
                        background-color: {get_attack_color(attack_type)};
                        padding: 15px;
                        border-radius: 5px;
                        margin: 10px 0;
                        border-left: 5px solid {border_colors.get(attack_type, '#9E9E9E')};
                    ">
                        <h4>Session Overview</h4>
                        <p>{generate_description(row)}</p>
                        <h4>Attack Type</h4>
                        <p><strong>{attack_type}</strong></p>
                    </div>
                     """,
                    unsafe_allow_html=True
            )

    else:
        st.warning("⚠️ No data found")

if __name__ == "__main__":
    main()
