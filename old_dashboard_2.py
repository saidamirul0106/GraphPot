import pandas as pd
import streamlit as st
from confluent_kafka import Consumer
import json

# Apply custom CSS styling
st.markdown(
    """
    <style>
    /* Background styling */
    body {
        background-color: #000000; /* Dark background */
        color: #33ff33; /* Neon green text */
        font-family: "Courier New", Courier, monospace; /* Hacker font */
    }
    h1, h2, h3 {
        color: #ff0000; /* Red titles */
    }
    .stButton>button {
        background-color: #333333;
        color: #33ff33;
        font-size: 16px;
        border-radius: 10px;
        border: 2px solid #33ff33;
    }
    .stButton>button:hover {
        background-color: #000000;
        color: #ff0000;
        border: 2px solid #ff0000;
        transition: all 0.3s ease-in-out;
    }
    .stDataFrame {
        border: 2px solid #33ff33;
        border-radius: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Streamlit Debugging: Show basic connection test message
st.markdown("<h3>💻 Initializing Kafka Consumer...</h3>", unsafe_allow_html=True)

# Kafka configuration
KAFKA_BROKER = "10.0.2.15:9092"
KAFKA_GROUP = "kafka_consumer"
KAFKA_TOPIC = "cowrie_logs"

# Kafka consumer setup
consumer_config = {
    'bootstrap.servers': KAFKA_BROKER,
    'group.id': KAFKA_GROUP,
    'auto.offset.reset': 'earliest'
}
consumer = Consumer(consumer_config)

def get_logs():
    """Fetch logs from Kafka."""
    consumer.subscribe([KAFKA_TOPIC])
    logs = []
    try:
        while True:
            msg = consumer.poll(0.5)  # Adjust timeout for polling
            if msg is None:
                break
            if msg.error():
                st.error(f"Consumer error: {msg.error()}")
                continue

            # Safely handle the Kafka message value
            try:
                value = msg.value().decode('utf-8') if msg.value() else None
                if value:
                    logs.append(json.loads(value))
                else:
                    logs.append({"error": "Empty message received"})
            except json.JSONDecodeError:
                logs.append({"error": "Invalid JSON format", "raw_value": value})
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()
    return logs

# Streamlit dashboard
st.markdown("<h1>👾 Cowrie Honeypot Dashboard</h1>", unsafe_allow_html=True)

if st.button("💾 Load Logs"):
    with st.spinner("Fetching logs from Kafka..."):
        logs = get_logs()
        if logs:
            # Convert logs to a DataFrame for better display
            df = pd.DataFrame(logs)
            st.markdown(f"<h3>Total logs fetched: {len(logs)}</h3>", unsafe_allow_html=True)
            st.dataframe(df)
        else:
            st.markdown("<h3 style='color: #ff0000;'>⚠️ No logs found.</h3>", unsafe_allow_html=True)
