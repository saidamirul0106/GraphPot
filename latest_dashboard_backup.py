import pandas as pd
import streamlit as st
from confluent_kafka import Consumer
import json

# Streamlit Debugging: Show basic connection test message
st.write("Starting Kafka Consumer...")

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
st.title("Cowrie Honeypot Dashboard")

if st.button("Load Logs"):
    st.write("Fetching logs from Kafka...")
    logs = get_logs()
    if logs:
        # Convert logs to a DataFrame for better display
        df = pd.DataFrame(logs)
        st.write(f"Total logs fetched: {len(logs)}")
        st.dataframe(df)
    else:
        st.write("No logs found.")

