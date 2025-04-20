import streamlit as st
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor

# PostgreSQL connection config
DB_HOST = "localhost"
DB_NAME = "hornet7_db"
DB_USER = "postgres"
DB_PASS = "Serigala76!"  # Replace with actual password

# Connect to PostgreSQL
@st.cache_resource
def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        cursor_factory=RealDictCursor
    )

# Load data from PostgreSQL
def load_data():
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM hornet7_data LIMIT 1000;")  # Limit for performance
        rows = cur.fetchall()
        return pd.DataFrame(rows)

# Insert new row
def insert_row(data):
    conn = get_connection()
    with conn.cursor() as cur:
        placeholders = ', '.join(['%s'] * len(data))
        columns = ', '.join(data.keys())
        sql = f"INSERT INTO hornet7_data ({columns}) VALUES ({placeholders})"
        cur.execute(sql, list(data.values()))
        conn.commit()

# Delete by session ID
def delete_row(session_id):
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM hornet7_data WHERE session = %s", (session_id,))
        conn.commit()

# Update example (e.g., update message field)
def update_message(session_id, new_message):
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("UPDATE hornet7_data SET message = %s WHERE session = %s", (new_message, session_id))
        conn.commit()

# Dashboard
st.title("GraphPot Dashboard - PostgreSQL Version")

df = load_data()

if not df.empty:
    st.subheader("Top Entries")
    st.dataframe(df)

    # Moving marquee text
    top_ips = df['src_ip'].value_counts().head(3).index.tolist()
    top_sessions = df['session'].value_counts().head(3).index.tolist()
    top_events = df['eventid'].value_counts().head(3).index.tolist()

    moving_text = f"Top IPs: {', '.join(top_ips)} | Top Sessions: {', '.join(top_sessions)} | Top Events: {', '.join(top_events)}"
    st.markdown(
        f'<marquee style="font-size: 18px; color: black; background-color: white; padding: 10px;">{moving_text}</marquee>',
        unsafe_allow_html=True,
    )

    st.subheader("🔄 CRUD Operations")

    with st.expander("➕ Insert New Row"):
        new_data = {}
        for col in df.columns:
            new_data[col] = st.text_input(f"{col}", key=f"insert_{col}")
        if st.button("Insert"):
            insert_row(new_data)
            st.success("New row inserted. Refresh to see updates.")

    with st.expander("✏️ Update Message by Session ID"):
        session_id_to_update = st.text_input("Session ID to update:")
        new_msg = st.text_input("New message:")
        if st.button("Update"):
            update_message(session_id_to_update, new_msg)
            st.success("Message updated. Refresh to see updates.")

    with st.expander("❌ Delete by Session ID"):
        session_id_to_delete = st.text_input("Session ID to delete:")
        if st.button("Delete"):
            delete_row(session_id_to_delete)
            st.warning("Row deleted. Refresh to see updates.")
else:
    st.warning("No data found in the table.")
