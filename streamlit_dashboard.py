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
import random
from datetime import datetime
import socket
import time

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
    "Brute Force Attack": "#D1ECF1",
    "Destructive Attack (Wiper)": "#FFB6B6",
    "Malware Download Attempt": "#FFF3CD",
    "Reconnaissance / Enumeration": "#E2E3E5",
    "Port Scanning / Connection Attempt": "#D4EDDA",
    "Command Injection Attempt": "#F8D7DA",
    "Successful Login": "#D1E7DD",
    "Failed Login": "#F8F9FA"
}

# --- Database Functions ---
@st.cache_resource(ttl=3600)
def get_connection():
    """Create and cache database connection with comprehensive error handling"""
    connection_params = {
        "host": DB_HOST,
        "dbname": DB_NAME,
        "user": DB_USER,
        "password": DB_PASS,
        "port": DB_PORT,
        "cursor_factory": RealDictCursor,
        "sslmode": "require",
        "connect_timeout": 5
    }
    
    try:
        # Attempt connection
        conn = psycopg2.connect(**connection_params)
        
        # Verify connection works
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            if cur.fetchone()[0] != 1:
                raise ValueError("Connection test failed")
        
        st.success("✅ Database connection established successfully!")
        return conn
        
    except psycopg2.OperationalError as e:
        st.error(f"""
        ❌ Database connection failed:
        - Check your internet connection
        - Verify database is running
        - Confirm host/port are correct
        Error details: {str(e)}
        """)
    except psycopg2.Error as e:
        st.error(f"""
        ❌ PostgreSQL error:
        - Check your credentials
        - Verify user permissions
        Error details: {str(e)}
        """)
    except Exception as e:
        st.error(f"""
        ❌ Unexpected error:
        - Please check all parameters
        Error details: {str(e)}
        """)
    
    return None

def execute_query(query, params=None):
    """Execute SQL query with robust connection handling"""
    conn = None
    max_retries = 2
    retry_delay = 1  # seconds
    
    for attempt in range(max_retries + 1):
        try:
            conn = get_connection()
            if conn is None:
                return None
                
            # Check if connection is still open
            if conn.closed != 0:
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    continue
                raise psycopg2.InterfaceError("Connection is closed")
                
            with conn.cursor() as cur:
                cur.execute(query, params or ())
                if cur.description:  # If query returns results
                    return cur.fetchall()
                conn.commit()
                return True
                
        except (psycopg2.InterfaceError, psycopg2.OperationalError) as e:
            if attempt < max_retries:
                st.warning(f"⚠️ Connection issue detected, retrying... (attempt {attempt + 1})")
                time.sleep(retry_delay)
                continue
            st.error(f"❌ Query failed after retries: {str(e)}")
            return None
        except psycopg2.Error as e:
            st.error(f"❌ PostgreSQL error: {str(e)}")
            return None
        except Exception as e:
            st.error(f"❌ Unexpected error: {str(e)}")
            return None
        finally:
            # Don't close the connection - let Streamlit manage it
            pass

def test_network():
    """Test network connectivity to database host"""
    try:
        with st.spinner(f"Testing connection to {DB_HOST}:{DB_PORT}..."):
            sock = socket.create_connection((DB_HOST, DB_PORT), timeout=5)
            sock.close()
            st.success("✅ Network connection to database host successful!")
            return True
    except Exception as e:
        st.error(f"""
        ❌ Network connection failed:
        {str(e)}
        
        Possible issues:
        1. Firewall blocking port 5432
        2. DNS resolution failure
        3. Host is unreachable
        """)
        return False

def test_db_connection():
    """Test database connectivity with detailed feedback"""
    with st.spinner("Testing database connection..."):
        try:
            conn = psycopg2.connect(
                host=DB_HOST,
                dbname=DB_NAME,
                user=DB_USER,
                password=DB_PASS,
                port=DB_PORT,
                sslmode="require",
                connect_timeout=5
            )
            
            with conn.cursor() as cur:
                cur.execute("SELECT version()")
                version = cur.fetchone()
                
                cur.execute("SELECT current_database()")
                db_name = cur.fetchone()
                
                cur.execute("SELECT current_user")
                db_user = cur.fetchone()
                
            conn.close()
            
            st.success("✅ Connection successful!")
            st.json({
                "PostgreSQL Version": version[0],
                "Database Name": db_name[0],
                "Connected As": db_user[0]
            })
            return True
            
        except Exception as e:
            st.error(f"""
            ❌ Connection failed:
            Error details: {str(e)}
            
            Troubleshooting steps:
            1. Verify credentials in Supabase dashboard
            2. Check network connectivity
            3. Ensure SSL is enabled
            4. Confirm database is running
            """)
            return False

@st.cache_data(ttl=60)
def load_data():
    """Load and process data from database"""
    query = """
        SELECT *, 
               COUNT(*) OVER (PARTITION BY src_ip, eventid) as attempt_count
        FROM hornet7_data 
        ORDER BY timestamp DESC 
        LIMIT 500
    """
    rows = execute_query(query)
    if rows is None:
        return pd.DataFrame()
    
    df = pd.DataFrame(rows)
    
    # Apply attack detection
    attack_info = []
    for _, row in df.iterrows():
        attack_info.append(detect_attack_type(row))
    
    df['attack_type'] = [x[0] for x in attack_info]
    df['attack_details'] = [x[1] for x in attack_info]
    
    return df

def detect_attack_type(row):
    """Classify attack type based on log entry"""
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
    """Create network graph for a session"""
    G = nx.DiGraph()
    src_ip = row.get('src_ip')
    eventid = row.get('eventid')
    dst_port = row.get('dst_port')
    attack_type = row.get('attack_type')
    
    # Node styling
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

def main():
    st.set_page_config(
        page_title="GraphPot - Network Session Analysis", 
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.title("🛡️ GraphPot - Network Session Analysis")
    
    # Connection diagnostics
    with st.expander("🔍 Connection Diagnostics", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Network Test")
            if st.button("Test Network Connectivity"):
                test_network()
        
        with col2:
            st.subheader("Database Test")
            if st.button("Test Database Connection"):
                test_db_connection()
    
    # Only proceed if both tests pass
    if not (test_network() and test_db_connection()):
        st.error("""
        ❌ Critical connection issues detected. 
        Please resolve these before continuing.
        """)
        return
    
    # Rest of your application code
    st.success("✅ All systems operational - loading dashboard...")
    
    if st.button("🔄 Refresh"):
        st.rerun()

    st.markdown("---")

    # --- Auto Test Data Generator ---
    st.sidebar.header("🧪 Test Data Generator")
    attack_type = st.sidebar.selectbox(
        "Select attack type:",
        ["Brute Force", "Malware Download", "Wiper Attack", "Reconnaissance", "Port Scan"]
    )
    
    if st.sidebar.button("🚀 Auto Insert Test Data"):
        test_data = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",
            "session": f"TEST-{random.randint(1000,9999)}",
            "dst_port": str(random.choice([22, 80, 443, 8080]))
        }
        
        if attack_type == "Brute Force":
            test_data.update({
                "eventid": "cowrie.login.failed",
                "attempt_count": random.randint(5,20),
                "message": "Failed login attempt"
            })
        elif attack_type == "Malware Download":
            test_data.update({
                "eventid": "cowrie.command.input",
                "input": "wget http://test.com/malware.sh"
            })
        elif attack_type == "Wiper Attack":
            test_data.update({
                "eventid": "cowrie.command.input",
                "input": "rm -rf /important/files"
            })
        elif attack_type == "Reconnaissance":
            test_data.update({
                "eventid": "cowrie.command.input",
                "input": "cat /etc/passwd"
            })
        elif attack_type == "Port Scan":
            test_data.update({
                "eventid": "cowrie.session.connect",
                "message": f"Port scan detected on {test_data['dst_port']}"
            })
        
        if execute_query("""
            INSERT INTO hornet7_data 
            (timestamp, src_ip, eventid, input, message, session, dst_port)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, 
            (
                test_data.get('timestamp'),
                test_data.get('src_ip'),
                test_data.get('eventid'),
                test_data.get('input'),
                test_data.get('message'),
                test_data.get('session'),
                test_data.get('dst_port')
            )
        ):
            st.sidebar.success(f"Inserted {attack_type} test data!")
            st.rerun()
        else:
            st.sidebar.error("Failed to insert test data")

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

        # --- Data Management Section ---
        with st.expander("🛠️ Data Management Controls", expanded=False):
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("➕ Insert New Entry")
                with st.form("insert_form"):
                    new_data = {
                        "timestamp": st.text_input("Timestamp", datetime.now().isoformat()),
                        "src_ip": st.text_input("Source IP", "192.168.1.1"),
                        "eventid": st.selectbox("Event Type", [
                            "cowrie.login.failed", 
                            "cowrie.login.success",
                            "cowrie.command.input",
                            "cowrie.session.connect"
                        ]),
                        "input": st.text_input("Command Input (if applicable)"),
                        "message": st.text_area("Log Message"),
                        "session": st.text_input("Session ID", f"MANUAL-{random.randint(1000,9999)}"),
                        "dst_port": st.text_input("Destination Port")
                    }
                    if st.form_submit_button("Insert"):
                        if execute_query("""
                            INSERT INTO hornet7_data 
                            (timestamp, src_ip, eventid, input, message, session, dst_port)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                            """, 
                            (
                                new_data.get('timestamp'),
                                new_data.get('src_ip'),
                                new_data.get('eventid'),
                                new_data.get('input'),
                                new_data.get('message'),
                                new_data.get('session'),
                                new_data.get('dst_port')
                            )
                        ):
                            st.success("Entry inserted successfully!")
                            st.rerun()
                        else:
                            st.error("Failed to insert entry")
            
            with col2:
                st.subheader("✏️ Update Entry")
                with st.form("update_form"):
                    session_id = st.text_input("Session ID to update")
                    new_status = st.selectbox("Update Status", [
                        "investigating", 
                        "resolved", 
                        "false_positive"
                    ])
                    if st.form_submit_button("Update"):
                        if execute_query("""
                            UPDATE hornet7_data 
                            SET status = %s
                            WHERE session = %s
                            """, 
                            (new_status, session_id)
                        ):
                            st.success("Entry updated successfully!")
                            st.rerun()
                        else:
                            st.error("Failed to update entry")
                
                st.subheader("❌ Delete Entry")
                with st.form("delete_form"):
                    del_id = st.text_input("Session ID to delete")
                    if st.form_submit_button("Delete"):
                        if execute_query("""
                            DELETE FROM hornet7_data 
                            WHERE session = %s
                            """, 
                            (del_id,)
                        ):
                            st.success("Entry deleted successfully!")
                            st.rerun()
                        else:
                            st.error("Failed to delete entry")

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
        st.warning("⚠️ No data found. Check database connection if this persists.")

    # Auto-refresh every 2 minutes
    st_autorefresh(interval=120000, key="data_refresh")

if __name__ == "__main__":
    main()
