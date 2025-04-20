from confluent_kafka import Consumer, KafkaError
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Kafka configuration
consumer_config = {
    'bootstrap.servers': '10.0.2.15:9092',  # Kafka broker
    'group.id': 'kafka_consumer',
    'auto.offset.reset': 'earliest',  # Read from the beginning if no offset is committed
    'session.timeout.ms': 10000       # Adjust the session timeout
}

def consume_logs():
    """Consume logs from Kafka and print them."""
    # Use context manager for resource management
    with Consumer(consumer_config) as consumer:
        consumer.subscribe(['cowrie_logs'])  # Replace with your topic name
        logging.info("Subscribed to topic 'cowrie_logs'...")

        try:
            while True:
                msg = consumer.poll(1.0)  # Poll messages with a timeout of 1 second
                if msg is None:
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        logging.info("End of partition reached.")
                        continue
                    else:
                        logging.error(f"Consumer error: {msg.error()}")
                        break

                # Safely process the message value
                try:
                    value = msg.value().decode('utf-8') if msg.value() else "No Value"
                    logging.info(f"Received message: {value}")
                except Exception as e:
                    logging.error(f"Error decoding message: {e}")
        except KeyboardInterrupt:
            logging.info("Consumer interrupted by user.")
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
        finally:
            logging.info("Kafka consumer closed.")

if __name__ == '__main__':
    consume_logs()
