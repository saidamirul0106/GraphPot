from confluent_kafka import Producer
import json
import time
import os

# Kafka configuration
producer_config = {
    'bootstrap.servers': '10.0.2.15:9092',  # Kafka broker
    'client.id': 'cowrie_producer',
}

# Kafka producer instance
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
    
    # Open the log file and start reading from the end (tailing the file)
    with open(log_file_path, 'r') as log_file:
        log_file.seek(0, os.SEEK_END)  # Move to the end of the file
        
        while True:
            line = log_file.readline()
            if not line:  # If no new line, wait for new data
                time.sleep(0.1)
                continue
            
            try:
                log_entry = json.loads(line.strip())  # Parse JSON log entry
                key = log_entry.get('session', 'no-key')  # Use 'session' as key if available
                value = json.dumps(log_entry)  # Convert the entry back to JSON string
                
                # Produce log to Kafka
                producer.produce(
                    topic='cowrie_logs',
                    key=key,
                    value=value,
                    callback=delivery_report,
                )
                producer.poll(0)  # Serve delivery reports
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON: {e}")
            except Exception as e:
                print(f"Error producing log to Kafka: {e}")

def stream_logs_to_kafka():
    """Main function to stream Cowrie logs to Kafka."""
    log_file_path = '/home/user/cowrie/var/log/cowrie/cowrie.json'  # Path to the Cowrie log file
    if not os.path.exists(log_file_path):
        print(f"Error: Log file not found at {log_file_path}")
        return
    
    read_cowrie_logs(log_file_path)

    # Ensure all messages are sent before exiting
    producer.flush()
    print("Finished streaming logs.")

if __name__ == '__main__':
    stream_logs_to_kafka()

