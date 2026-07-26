import re

def parse_linux_log(filepath):
    """
    Reads a Linux auth.log file (plain text).
    Returns a list of parsed log entries as dictionaries.
    """
    parsed_logs = []

    # Regex pattern to extract the base parts of each log line
    # Format: Month Day Time Hostname Process[PID]: Message
    base_pattern = re.compile(
        r'^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.+)$'
    )

    try:
        with open(filepath, 'r', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        match = base_pattern.match(line)
        if not match:
            continue

        timestamp, hostname, process, message = match.groups()

        log = {
            "timestamp": timestamp,
            "hostname":  hostname,
            "process":   process,
            "message":   message,
            "raw":       line
        }
        parsed_logs.append(log)

    return parsed_logs