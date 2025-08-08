
def get_threat_level(probability, thresholds=(0.4, 0.7)):
    """
    Convert prediction probability into threat level:
    - 0.0 to 0.4 → Low
    - 0.4 to 0.7 → Medium
    - 0.7 to 1.0 → High
    """
    low_thresh, high_thresh = thresholds

    if probability < low_thresh:
        return "Low"
    elif low_thresh <= probability < high_thresh:
        return "Medium"
    else:
        return "High"

def describe_threat(threat_level):
    """
    Provide a short description of each threat level.
    """
    messages = {
        "Low": "Minimal or no malicious activity detected.",
        "Medium": "Suspicious behavior detected. Requires inspection.",
        "High": "Potential threat! Immediate attention recommended."
    }
    return messages.get(threat_level, "Unknown threat level.")
