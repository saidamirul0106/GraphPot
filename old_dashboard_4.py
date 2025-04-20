import pandas as pd
import streamlit as st
from confluent_kafka import Consumer
import json

# Kafka Configuration
KAFKA_BROKER = "10.0.2.15:9092"
KAFKA_GROUP = "kafka_consumer"
KAFKA_TOPIC = "cowrie_logs"

# Kafka Consumer Setup
consumer_config = {
    'bootstrap.servers': KAFKA_BROKER,
    'group.id': KAFKA_GROUP,
    'auto.offset.reset': 'earliest'
}
consumer = Consumer(consumer_config)

def get_logs():
    """Fetch logs from Kafka and return as a list of dictionaries."""
    st.write("Connecting to Kafka...")
    consumer.subscribe([KAFKA_TOPIC])
    logs = []

    try:
        while True:
            msg = consumer.poll(1.0)  # Adjust timeout for polling
            if msg is None:
                break
            if msg.error():
                st.error(f"Consumer error: {msg.error()}")
                continue

            # Process Kafka message
            try:
                value = msg.value().decode('utf-8') if msg.value() else None
                if value:
                    log_entry = json.loads(value)  # Parse JSON
                    logs.append(log_entry)
                else:
                    st.warning("Empty message received from Kafka.")
            except json.JSONDecodeError as e:
                st.error(f"JSON decode error: {e}")
    except Exception as e:
        st.error(f"Unexpected error: {e}")
    finally:
        consumer.close()
    return logs

def generate_moving_text(df):
    """Generate moving text for top fields such as IPs, sessions, and events."""
    st.write("Debug: Generating moving text for top fields.")
    try:
        # Calculate top IPs, sessions, and events
        top_ips = df['src_ip'].value_counts().head(3).index.tolist() if 'src_ip' in df else []
        top_sessions = df['session'].value_counts().head(3).index.tolist() if 'session' in df else []
        top_events = df['event'].value_counts().head(3).index.tolist() if 'event' in df else []

        # Combine into a moving message
        moving_text = f"Top IPs: {', '.join(top_ips)} | Top Sessions: {', '.join(top_sessions)} | Top Events: {', '.join(top_events)}"
        return moving_text
    except Exception as e:
        st.error(f"Error generating moving text: {e}")
        return "Error generating moving text."

# Streamlit Dashboard UI
st.title("Cowrie Honeypot Dashboard")

if st.button("Load Logs"):
    with st.spinner("Fetching logs from Kafka..."):
        logs = get_logs()
        if logs:
            # Convert logs to DataFrame for better display
            df = pd.DataFrame(logs)
            st.success(f"Total logs fetched: {len(logs)}")
            st.dataframe(df)  # Display logs in a table

            # Generate and display moving text
            moving_text = generate_moving_text(df)
            st.markdown(
                f'<marquee style="font-size: 18px; color: white; background-color: black; padding: 10px;">{moving_text}</marquee>',
                unsafe_allow_html=True,
            )
        else:
            st.warning("No logs found.")

