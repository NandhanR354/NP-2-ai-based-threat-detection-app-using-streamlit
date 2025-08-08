
import pandas as pd
import numpy as np
import socket
import pandas as pd
from sklearn.preprocessing import LabelEncoder

def ip_to_int(ip):
    try:
        return int.from_bytes(socket.inet_aton(ip), 'big')
    except:
        return 0

df = pd.read_csv('/content/drive/MyDrive/nandhan.project/UNSW_Flow.csv')

# Convert IPs to integers
df['source_ip_int'] = df['source_ip'].apply(ip_to_int)
df['destination_ip_int'] = df['destination_ip'].apply(ip_to_int)

# Protocol encoding
proto_encoder = LabelEncoder()
df['protocol_encoded'] = proto_encoder.fit_transform(df['protocol'])

# Duration (rename or use directly)
df['duration'] = df['dur']

# Packet size total
df['packet_size_total'] = df['sbytes'] + df['dbytes']

# Packet rate
df['packet_rate'] = (df['spkts'] + df['dpkts']) / df['duration'].replace(0, 0.001)

# Binary label
df['label'] = df['binary_label']

# Save processed version
df.to_csv('data/processed_data.csv', index=False)
