
import csv
import os
from datetime import datetime

LOG_FILE = 'logs/prediction_logs.csv'

def init_log(file_path=LOG_FILE):
    """
    Initialize the log file with headers if it doesn't exist.
    """
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    if not os.path.exists(file_path):
        with open(file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                'timestamp',
                'source_ip',
                'destination_ip',
                'protocol',
                'duration',
                'prediction',
                'probability',
                'threat_level',
                'description'
            ])

def log_prediction(source_ip, destination_ip, protocol, duration, prediction, probability, threat_level, description, file_path=LOG_FILE):
    """
    Append a single prediction result to the CSV log.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    row = [
        timestamp,
        source_ip,
        destination_ip,
        protocol,
        duration,
        prediction,
        round(probability, 4),
        threat_level,
        description
    ]
    with open(file_path, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(row)
