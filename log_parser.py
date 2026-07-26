import json

def parse_log_file(filepath):
    """
    Reads a JSON log file and returns a list of parsed log entries.
    Each entry is a dictionary with standardized fields.
    """
    parsed_logs = []

    try:
        with open(filepath, 'r') as f:
            raw_data = json.load(f)
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

    for entry in raw_data:
        log = {
            "event_id":    entry.get("EventID", "Unknown"),
            "timestamp":   entry.get("TimeCreated", "Unknown"),
            "username":    entry.get("Username", "Unknown"),
            "hostname":    entry.get("Hostname", "Unknown"),
            "process":     entry.get("ProcessName", "Unknown"),
            "commandline": entry.get("CommandLine", "")
        }
        parsed_logs.append(log)

    return parsed_logs
