import pandas as pd
import streamlit as st
from confluent_kafka import Consumer
import json

# Streamlit Debugging: Initialization message
st.write("Initializing Kafka Consumer...")

# Kafka Configuration
KAFKA_BROKER = "10.0.2.15:9092"
KAFKA_GROUP = "kafka_consumer"
KAFKA_TOPIC = "cowrie_logs"

# Kafka Consumer Setup
consumer_config = {
    'bootstrap.servers': KAFKA_BROKER,
    'group.id': KAFKA_GROUP,
    'auto.offset.reset': 'earliest'  # Start from earliest offset if no committed offset exists
}
consumer = Consumer(consumer_config)

def get_logs():
    """Fetch logs from Kafka and return as a list of dictionaries."""
    consumer.subscribe([KAFKA_TOPIC])  # Subscribe to the topic
    logs = []
    try:
        while True:
            msg = consumer.poll(10.0)  # Wait up to 1 second for a message
            if msg is None:  # No message available
                break
            if msg.error():  # Handle any consumer errors
                st.error(f"Consumer error: {msg.error()}")
                continue

            try:
                # Decode and parse the message
                value = msg.value().decode('utf-8') if msg.value() else None
                if value:
                    log_entry = json.loads(value)  # Parse JSON
                    logs.append(log_entry)  # Add to logs list
                else:
                    logs.append({"error": "Empty message received"})
            except json.JSONDecodeError as e:
                st.error(f"JSON decode error: {e}")
                logs.append({"error": "Invalid JSON format", "raw_value": value})
    except Exception as e:
        st.error(f"Unexpected error: {e}")
    finally:
        consumer.close()  # Ensure the consumer is closed
    return logs

# Streamlit Dashboard UI
st.title("Cowrie Honeypot Dashboard")

if st.button("Load Logs"):
    with st.spinner("Fetching logs from Kafka..."):
        logs = get_logs()
        if logs:
            # Convert logs to DataFrame for easy display
            df = pd.DataFrame(logs)
            st.success(f"Total logs fetched: {len(logs)}")
            st.dataframe(df)  # Display logs in a table
        else:
            st.warning("No logs found.")
