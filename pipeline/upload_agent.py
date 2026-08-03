"""
Upload Agent - Event-Driven Ingestion Component
Scaffolds a cloud storage / local file listener monitoring the `/raw_intel/` directory.
Extracts data from incoming PDF, CSV, and TXT files and publishes messages to the `new_intel_event` topic.
"""

import os
import csv
import json
import time
from typing import Dict, List, Any


TOPIC_NAME = "new_intel_event"

# Simulated Pub/Sub / Kafka Message Broker Queue
EVENT_BROKER_QUEUE: List[Dict[str, Any]] = []


def publish_to_pubsub(topic: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simulates publishing a payload message to a Kafka / Google Cloud Pub/Sub topic.
    """
    message = {
        "message_id": f"MSG-{int(time.time() * 1000)}",
        "topic": topic,
        "payload": payload,
        "published_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    EVENT_BROKER_QUEUE.append(message)
    print(f"[Upload Agent] Published event {message['message_id']} to topic '{topic}'")
    return message


def extract_content_from_file(file_path: str) -> List[Dict[str, str]]:
    """
    Extracts structured entity records from PDF, CSV, or TXT raw intelligence files.
    """
    records = []
    file_ext = os.path.splitext(file_path)[1].lower()

    if file_ext == ".csv":
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append(dict(row))

    elif file_ext in [".txt", ".log"]:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for idx, line in enumerate(lines):
                line = line.strip()
                if line:
                    records.append({
                        "unique_id": f"RAW_TXT_{idx+1}",
                        "raw_content": line,
                        "file_source": os.path.basename(file_path)
                    })

    elif file_ext == ".pdf":
        # Scaffold PDF extraction logic
        records.append({
            "unique_id": f"PDF_{os.path.basename(file_path)}",
            "company_name": "Intercepted PDF Entity",
            "country": "Panama",
            "registration_id": "PDF-REG-991",
            "file_source": os.path.basename(file_path)
        })

    return records


def process_raw_file(file_path: str) -> Dict[str, Any]:
    """
    Processes an uploaded file, extracts records, and publishes `new_intel_event`.
    """
    print(f"[Upload Agent] Detected new raw intel file: {file_path}")
    extracted_records = extract_content_from_file(file_path)

    payload = {
        "file_name": os.path.basename(file_path),
        "file_path": file_path,
        "record_count": len(extracted_records),
        "records": extracted_records
    }

    message = publish_to_pubsub(TOPIC_NAME, payload)
    return message


def watch_raw_intel_directory(directory_path: str):
    """
    Scaffolds directory polling / cloud trigger listener for /raw_intel/.
    """
    if not os.path.exists(directory_path):
        os.makedirs(directory_path, exist_ok=True)

    print(f"[Upload Agent] Listening for incoming intel files in {directory_path}...")
    processed_files = set()

    for file_name in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file_name)
        if os.path.isfile(file_path) and file_name not in processed_files and not file_name.startswith("."):
            process_raw_file(file_path)
            processed_files.add(file_name)


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    raw_intel_dir = os.path.join(current_dir, "..", "raw_intel")
    watch_raw_intel_directory(raw_intel_dir)
