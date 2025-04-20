import os
import json
import pandas as pd

# Path to Cowrie log file
log_file_path = "/home/user/cowrie/var/log/cowrie/cowrie.json"

# Initialize an empty list to hold structured data
structured_data = []

try:
    with open(log_file_path, "r") as log_file:
        for line in log_file:
            # Parse each log entry as JSON
            try:
                log_entry = json.loads(line.strip())
                
                # Extract relevant fields
                structured_entry = {
                    "timestamp": log_entry.get("timestamp"),
                    "eventid": log_entry.get("eventid"),
                    "session": log_entry.get("session"),
                    "src_ip": log_entry.get("src_ip"),
                    "username": log_entry.get("username"),
                    "password": log_entry.get("password"),
                    "command": log_entry.get("command"),
                }
                
                # Append to the list
                structured_data.append(structured_entry)
            except json.JSONDecodeError as e:
                print(f"Skipping invalid log entry: {line.strip()}")

except FileNotFoundError:
    print(f"Log file not found: {log_file_path}")

# Convert structured data to a DataFrame
df = pd.DataFrame(structured_data)

# Save DataFrame to a CSV file
output_file_path = "/home/user/cowrie_dashboard/cowrie_logs.csv"
df.to_csv(output_file_path, index=False)
print(f"Structured data saved to {output_file_path}")

# Preview the first 5 rows
print(df.head())

