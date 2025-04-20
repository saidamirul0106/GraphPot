from confluent_kafka import Consumer, KafkaError

# Kafka configuration
consumer_config = {
    'bootstrap.servers': '10.0.2.15:9092',  # Kafka broker
    'group.id': 'kafka_consumer',
    'auto.offset.reset': 'earliest',  # Read from the beginning if no offset is committed
    'session.timeout.ms': 10000  # Adjust the session timeout
}

# Kafka consumer instance
consumer = Consumer(consumer_config)

def consume_logs():
    """Consume logs from Kafka."""
    try:
        consumer.subscribe(['cowrie_logs'])  # Replace with your topic name
        print("Subscribed to topic 'cowrie_logs'...")

        while True:
            msg = consumer.poll(5.0)  # Poll messages with a timeout of 5 seconds
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    # End of partition reached
                    continue
                else:
                    print(f"Consumer error: {msg.error()}")
                    break

            # Safely process the message key and value
            key = msg.key().decode('utf-8') if msg.key() else "No Key"
            value = msg.value().decode('utf-8') if msg.value() else "No Value"
            print(f"Received message: {key} -> {value}")

    except KeyboardInterrupt:
        print("\nExiting consumer...")
    finally:
        consumer.close()  # Close the consumer properly
        print("Kafka consumer closed.")

if __name__ == '__main__':
    consume_logs()

