import streamlit as st
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
import socket
import time
from datetime import datetime
import random

# --- Configuration ---
DB_HOST = "aws-0-ap-southeast-1.pooler.supabase.com"
DB_NAME = "postgres"
DB_USER = "postgres.ypsdflhceqxrjwyxvclr"  # Format: postgres.[project-ref]
DB_PASS = "Serigala76!"  # MUST match exactly what's in Supabase
DB_PORT = 5432

# --- Enhanced Connection Testing ---
def test_network_connection():
    """Test if we can reach the database host"""
    try:
        with socket.create_connection((DB_HOST, DB_PORT), timeout=10) as sock:
            return True
    except Exception as e:
        st.error(f"❌ Cannot reach {DB_HOST}:{DB_PORT} - {str(e)}")
        return False

def test_database_credentials():
    """Test if credentials are correct"""
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
        return True
    except psycopg2.OperationalError as e:
        st.error(f"❌ Connection failed: {str(e)}")
        return False
    except psycopg2.ProgrammingError as e:
        st.error(f"❌ Authentication failed: {str(e)}")
        return False

def test_table_exists():
    """Check if the hornet7_data table exists"""
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
            exists = cur.fetchone()[0]
        conn.close()
        return exists
    except Exception as e:
        st.error(f"❌ Error checking table: {str(e)}")
        return False

# --- Database Connection with Retry Logic ---
@st.cache_resource(ttl=3600)
def get_db_connection(max_retries=3, retry_delay=2):
    """Create database connection with retry logic"""
    for attempt in range(max_retries + 1):
        try:
            conn = psycopg2.connect(
                host=DB_HOST,
                dbname=DB_NAME,
                user=DB_USER,
                password=DB_PASS,
                port=DB_PORT,
                cursor_factory=RealDictCursor,
                sslmode="require",
                connect_timeout=10
            )
            
            # Verify connection works
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                if cur.fetchone()[0] != 1:
                    raise ValueError("Connection test failed")
            
            return conn
            
        except Exception as e:
            if attempt < max_retries:
                time.sleep(retry_delay)
                continue
            st.error(f"❌ Database connection failed after {max_retries} attempts: {str(e)}")
            return None

def execute_query(query, params=None):
    """Execute SQL query with proper connection handling"""
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            return None
            
        with conn.cursor() as cur:
            cur.execute(query, params or ())
            if cur.description:  # If query returns results
                return cur.fetchall()
            conn.commit()
            return True
    except Exception as e:
        st.error(f"❌ Query failed: {str(e)}")
        return None
    finally:
        if conn:
            conn.close()

# --- Data Loading ---
@st.cache_data(ttl=60)
def load_data():
    """Load data from database with error handling"""
    if not test_table_exists():
        return pd.DataFrame()
    
    query = """
        SELECT *, 
               COUNT(*) OVER (PARTITION BY src_ip, eventid) as attempt_count
        FROM hornet7_data 
        ORDER BY timestamp DESC 
        LIMIT 500
    """
    
    result = execute_query(query)
    return pd.DataFrame(result) if result else pd.DataFrame()

# --- Main Application ---
def main():
    st.set_page_config(
        page_title="GraphPot - Network Session Analysis", 
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.title("🛡️ GraphPot - Network Session Analysis")
    
    # --- Connection Verification ---
    with st.expander("🔍 Connection Diagnostics", expanded=True):
        st.subheader("Connection Tests")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("Test Network"):
                if test_network_connection():
                    st.success("✅ Network connection successful")
        
        with col2:
            if st.button("Test Credentials"):
                if test_database_credentials():
                    st.success("✅ Database authentication successful")
        
        with col3:
            if st.button("Check Table"):
                if test_table_exists():
                    st.success("✅ Table exists")
                else:
                    st.error("❌ Table not found")
    
    # Only proceed if all tests pass
    if not (test_network_connection() and 
            test_database_credentials() and 
            test_table_exists()):
        st.error("""
        ❌ Critical connection issues detected. Please:
        1. Verify your Supabase credentials
        2. Check network connectivity
        3. Ensure database is running
        4. Confirm 'hornet7_data' table exists
        """)
        return
    
    # --- Data Loading ---
    with st.spinner('Loading data...'):
        df = load_data()
    
    if df.empty:
        st.warning("""
        ⚠️ No data found. Possible reasons:
        1. Table is empty
        2. Connection issues
        3. Query failed
        
        Try inserting test data first.
        """)
        
        # --- Test Data Insertion ---
        with st.expander("Insert Test Data", expanded=True):
            if st.button("Insert Sample Record"):
                sample_data = {
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                    "eventid": "cowrie.session.connect",
                    "message": "Test connection",
                    "session": f"TEST-{random.randint(1000,9999)}",
                    "dst_port": str(random.choice([22, 80, 443]))
                }
                
                query = """
                    INSERT INTO hornet7_data 
                    (timestamp, src_ip, eventid, message, session, dst_port)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """
                
                if execute_query(query, list(sample_data.values())):
                    st.success("✅ Test data inserted!")
                    st.cache_data.clear()
                    st.rerun()
                else:
                    st.error("Failed to insert test data")
        return
    
    # --- Main Dashboard ---
    st.success(f"✅ Loaded {len(df)} records")
    
    # Display data
    st.dataframe(df.head())
    
    # Add your dashboard components here...

if __name__ == "__main__":
    main()
