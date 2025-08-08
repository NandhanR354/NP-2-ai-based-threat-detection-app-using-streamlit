
import pandas as pd
import numpy as np
import socket
import struct
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from imblearn.over_sampling import SMOTE
import joblib

# Set seed for reproducibility
RANDOM_STATE = 42

# Function to convert IP address to integer
def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        return 0

# Load dataset
def load_data(file_path):
    return pd.read_csv(file_path)

# Preprocess dataset
def preprocess_data(df):
    df = df.copy()

    # Drop duplicates
    df.drop_duplicates(inplace=True)

    # Handle missing values
    df.fillna(0, inplace=True)

    # Encode IP addresses
    df['source_ip_int'] = df['source_ip'].apply(ip_to_int)
    df['destination_ip_int'] = df['destination_ip'].apply(ip_to_int)

    # Feature Engineering
    if 'duration' in df.columns and 'packet_size_total' in df.columns:
        df['packet_rate'] = df['packet_size_total'] / (df['duration'] + 1e-5)

    # Encoding categorical features
    if 'protocol' in df.columns:
        protocol_encoder = LabelEncoder()
        df['protocol_encoded'] = protocol_encoder.fit_transform(df['protocol'])
    else:
        df['protocol_encoded'] = 0

    # Select features
    features = [
        'source_ip_int', 'destination_ip_int', 'protocol_encoded',
        'duration', 'packet_size_total', 'packet_rate'
    ]
    X = df[features]
    y = df['binary_label']

    # Scaling
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # SMOTE to balance the data
    smote = SMOTE(random_state=RANDOM_STATE)
    X_resampled, y_resampled = smote.fit_resample(X_scaled, y)

    return X_resampled, y_resampled, scaler

# Save the scaler and other metadata
def save_objects(scaler, output_dir='models'):
    os.makedirs(output_dir, exist_ok=True)
    joblib.dump(scaler, os.path.join(output_dir, 'preprocessor.pkl'))

# Save train/test split
def save_split_data(X, y, output_dir='data'):
    os.makedirs(output_dir, exist_ok=True)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )
    np.save(os.path.join(output_dir, 'X_train.npy'), X_train)
    np.save(os.path.join(output_dir, 'X_test.npy'), X_test)
    np.save(os.path.join(output_dir, 'y_train.npy'), y_train)
    np.save(os.path.join(output_dir, 'y_test.npy'), y_test)

# Entry point
if __name__ == "__main__":
    raw_data_path = '/content/data/processed_data.csv'
    df = load_data(raw_data_path)
    X, y, scaler = preprocess_data(df)
    save_objects(scaler)
    save_split_data(X, y)
    print("[✓] Data preprocessing complete. Processed data and scaler saved.")
