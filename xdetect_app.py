
import streamlit as st
import pandas as pd
import socket
import struct
import joblib
import psutil
import os

from utils.threat_scorer import get_threat_level, describe_threat
from utils.logger import init_log, log_prediction

# Load saved model and scaler
MODEL_PATH = 'models/xgboost_model.pkl'
SCALER_PATH = 'models/preprocessor.pkl'

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# Initialize logger
init_log()

# Convert IP to int
def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        return 0

# Prediction function
def predict_threat(source_ip, destination_ip, protocol, duration, packet_size_total):
    src_ip_int = ip_to_int(source_ip)
    dst_ip_int = ip_to_int(destination_ip)
    packet_rate = packet_size_total / (duration + 1e-5)
    protocol_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2}
    protocol_encoded = protocol_map.get(protocol.upper(), 0)

    features = [[
        src_ip_int,
        dst_ip_int,
        protocol_encoded,
        duration,
        packet_size_total,
        packet_rate
    ]]

    features_scaled = scaler.transform(features)
    prob = model.predict_proba(features_scaled)[0][1]
    prediction = int(prob >= 0.5)
    threat_level = get_threat_level(prob)
    description = describe_threat(threat_level)

    # Log it
    log_prediction(
        source_ip, destination_ip, protocol, duration,
        prediction, prob, threat_level, description
    )

    return prediction, prob, threat_level, description

# Streamlit UI
st.set_page_config(page_title="X-Detect: Cybersecurity Threat Detection", layout="centered")
st.title("🔐 X-Detect: AI Cybersecurity Threat Detection App")

mode = st.sidebar.selectbox("Select Mode", ["Manual Input", "Live Network Scan"])

if mode == "Manual Input":
    st.subheader("📝 Manual Threat Check")
    source_ip = st.text_input("Source IP", "192.168.1.10")
    destination_ip = st.text_input("Destination IP", "8.8.8.8")
    protocol = st.selectbox("Protocol", ["TCP", "UDP", "ICMP"])
    duration = st.number_input("Connection Duration (seconds)", min_value=0.0, value=10.0)
    packet_size_total = st.number_input("Total Packet Size (bytes)", min_value=0, value=500)

    if st.button("Predict Threat"):
        pred, prob, level, desc = predict_threat(
            source_ip, destination_ip, protocol, duration, packet_size_total
        )
        st.success(f"🛡️ Prediction: {'Threat' if pred else 'Safe'}")
        st.info(f"⚠️ Threat Level: {level}")
        st.write(f"📄 Description: {desc}")
        st.write(f"📊 Probability: {prob:.4f}")

elif mode == "Live Network Scan":
    st.subheader("🌐 Live System Connection Threat Detection")

    if st.button("Scan and Predict"):
        connections = psutil.net_connections(kind='inet')

        threat_data = []
        for conn in connections:
            try:
                if conn.raddr:
                    src_ip = conn.laddr.ip
                    dst_ip = conn.raddr.ip
                    protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                    duration = 10.0  # Placeholder
                    packet_size_total = 1000  # Placeholder

                    pred, prob, level, desc = predict_threat(
                        src_ip, dst_ip, protocol, duration, packet_size_total
                    )

                    threat_data.append({
                        "Source IP": src_ip,
                        "Destination IP": dst_ip,
                        "Protocol": protocol,
                        "Prediction": "Threat" if pred else "Safe",
                        "Threat Level": level,
                        "Probability": round(prob, 4),
                    })
            except Exception as e:
                continue

        if threat_data:
            df = pd.DataFrame(threat_data)
            st.dataframe(df)
        else:
            st.warning("No active external connections to evaluate.")
