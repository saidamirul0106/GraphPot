from confluent_kafka import Producer
import json
import time
import os

# Kafka Configuration
producer_config = {
    'bootstrap.servers': '10.0.2.15:9092',
    'client.id': 'cowrie_producer',
}
producer = Producer(producer_config)

# Delivery report callback
def delivery_report(err, msg):
    """Callback for message delivery."""
    if err is not None:
        print(f"Delivery failed for record {msg.key()}: {err}")
    else:
        print(f"Record {msg.key()} successfully delivered to {msg.topic()} [{msg.partition()}]")

def read_cowrie_logs(log_file_path):
    """Reads Cowrie logs and streams them to Kafka in real-time."""
    print(f"Streaming logs from file: {log_file_path}")
    total_logs = 0  # Count total logs processed

    try:
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                print(f"Raw line: {line.strip()}")  # Debug: Print raw log line
                try:
                    log_entry = json.loads(line.strip())  # Parse JSON log entry
                    print(f"Parsed JSON: {log_entry}")  # Debug: Parsed JSON

                    # Send log to Kafka
                    producer.produce(
                        topic='cowrie_logs',
                        key=log_entry.get('session', 'no-key'),
                        value=json.dumps(log_entry),
                        callback=delivery_report,
                    )
                    producer.poll(0)  # Serve delivery reports
                    total_logs += 1
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON: {line.strip()} (Error: {e})")
                except Exception as e:
                    print(f"Error producing message: {e}")

        producer.flush()  # Ensure all messages are sent
        print(f"Finished streaming logs. Total logs sent: {total_logs}")
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def stream_logs_to_kafka():
    """Main function to stream Cowrie logs to Kafka."""
    log_file_path = '/home/user/cowrie/var/log/cowrie/cowrie.json'
    if not os.path.exists(log_file_path):
        print(f"Error: Log file not found at {log_file_path}")
        return

    print("Starting Kafka producer...")
    read_cowrie_logs(log_file_path)

    # Ensure all messages are sent before exiting
    producer.flush()
    print("Finished streaming logs.")

if __name__ == '__main__':
    stream_logs_to_kafka()

