import json


# ── Format Detectors ────────────────────────────────────────────────────────

def detect_format(entry):
    """
    Takes a single log entry (dict) and returns which format it is.
    """
    if not isinstance(entry, dict):
        return "unknown"

    # Your sample format
    if "EventID" in entry:
        return "sample"

    # Windows Event Viewer JSON export
    if "Event" in entry and isinstance(entry["Event"], dict):
        if "System" in entry["Event"]:
            return "windows_event_viewer"

    # Wazuh alert format
    if "data" in entry and isinstance(entry["data"], dict):
        if "win" in entry["data"]:
            return "wazuh"

    # Generic flat format (lowercase keys)
    flat_keys = [k.lower() for k in entry.keys()]
    if "eventid" in flat_keys or "event_id" in flat_keys:
        return "generic_flat"

    return "unknown"


# ── Format Normalizers ───────────────────────────────────────────────────────

def normalize_sample(entry):
    """Your original sample format."""
    return {
        "event_id":    entry.get("EventID", "Unknown"),
        "timestamp":   entry.get("TimeCreated", "Unknown"),
        "username":    entry.get("Username", "Unknown"),
        "hostname":    entry.get("Hostname", "Unknown"),
        "process":     entry.get("ProcessName", "Unknown"),
        "commandline": entry.get("CommandLine", "")
    }


def normalize_windows_event_viewer(entry):
    """
    Windows Event Viewer JSON export format.
    Structure: entry["Event"]["System"]["EventID"]
               entry["Event"]["EventData"]["TargetUserName"]
    """
    system    = entry.get("Event", {}).get("System", {})
    eventdata = entry.get("Event", {}).get("EventData", {})

    # EventID can be a number or {"#text": "4625"}
    raw_event_id = system.get("EventID", "Unknown")
    if isinstance(raw_event_id, dict):
        event_id = raw_event_id.get("#text", "Unknown")
    else:
        event_id = raw_event_id

    # Try multiple possible username fields
    username = (
        eventdata.get("TargetUserName") or
        eventdata.get("SubjectUserName") or
        eventdata.get("AccountName") or
        "Unknown"
    )

    # Timestamp can be nested
    raw_time = system.get("TimeCreated", {})
    if isinstance(raw_time, dict):
        timestamp = raw_time.get("@SystemTime", "Unknown")
    else:
        timestamp = raw_time

    hostname = system.get("Computer", "Unknown")

    execution  = system.get("Execution", {})
    process_id = execution.get("@ProcessID", "") if isinstance(execution, dict) else ""

    return {
        "event_id":    int(event_id) if str(event_id).isdigit() else event_id,
        "timestamp":   timestamp,
        "username":    username,
        "hostname":    hostname,
        "process":     eventdata.get("NewProcessName", process_id or "Unknown"),
        "commandline": eventdata.get("CommandLine", "")
    }


def normalize_wazuh(entry):
    """
    Wazuh alert JSON format.
    Structure: entry["data"]["win"]["system"]
               entry["data"]["win"]["eventdata"]
    """
    win       = entry.get("data", {}).get("win", {})
    system    = win.get("system", {})
    eventdata = win.get("eventdata", {})

    raw_event_id = system.get("eventID", "Unknown")

    username = (
        eventdata.get("targetUserName") or
        eventdata.get("subjectUserName") or
        entry.get("data", {}).get("srcuser") or
        "Unknown"
    )

    return {
        "event_id":    int(raw_event_id) if str(raw_event_id).isdigit() else raw_event_id,
        "timestamp":   system.get("systemTime", entry.get("timestamp", "Unknown")),
        "username":    username,
        "hostname":    system.get("computer", "Unknown"),
        "process":     eventdata.get("newProcessName", system.get("processID", "Unknown")),
        "commandline": eventdata.get("commandLine", "")
    }


def normalize_generic_flat(entry):
    """
    Generic flat format with lowercase keys.
    Tries common field name variations.
    """
    def get_any(d, *keys):
        """Try multiple key names and return first match."""
        for k in keys:
            if k in d:
                return d[k]
        # Case-insensitive fallback
        lower_d = {key.lower(): val for key, val in d.items()}
        for k in keys:
            if k.lower() in lower_d:
                return lower_d[k.lower()]
        return "Unknown"

    event_id = get_any(entry,
                       "EventID", "eventID", "event_id",
                       "EventId", "eventid", "id")

    return {
        "event_id":    int(event_id) if str(event_id).isdigit() else event_id,
        "timestamp":   get_any(entry, "TimeCreated", "timestamp",
                               "time", "datetime", "date"),
        "username":    get_any(entry, "Username", "username",
                               "user", "account", "AccountName"),
        "hostname":    get_any(entry, "Hostname", "hostname",
                               "host", "computer", "Computer"),
        "process":     get_any(entry, "ProcessName", "process",
                               "process_name", "Image"),
        "commandline": get_any(entry, "CommandLine", "commandline",
                               "command", "cmd", "") or ""
    }


# ── Main Smart Parser ────────────────────────────────────────────────────────

def smart_parse_json(filepath):
    """
    Main entry point. Reads a JSON log file of any supported format.
    Returns a list of normalized log entries + a format report.
    """
    parsed_logs  = []
    skipped      = 0
    format_used  = "unknown"

    try:
        with open(filepath, 'r', errors='ignore') as f:
            raw_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"JSON parse error: {e}")
        return [], "invalid_json"
    except Exception as e:
        print(f"File read error: {e}")
        return [], "file_error"

    # Handle both array [...] and single object {...}
    if isinstance(raw_data, dict):
        raw_data = [raw_data]

    if not raw_data:
        return [], "empty"

    # Detect format from first valid entry
    format_used = detect_format(raw_data[0])
    print(f"[SmartParser] Detected format: {format_used}")

    # Map format to normalizer function
    normalizer_map = {
        "sample":               normalize_sample,
        "windows_event_viewer": normalize_windows_event_viewer,
        "wazuh":                normalize_wazuh,
        "generic_flat":         normalize_generic_flat,
    }

    normalizer = normalizer_map.get(format_used)

    for entry in raw_data:
        if not isinstance(entry, dict):
            skipped += 1
            continue

        try:
            if normalizer:
                log = normalizer(entry)
            else:
                # Unknown format — try generic as last resort
                log = normalize_generic_flat(entry)
                format_used = "generic_flat (fallback)"

            # Only keep entries where we got at least an event_id
            if log["event_id"] != "Unknown":
                parsed_logs.append(log)
            else:
                skipped += 1

        except Exception as e:
            print(f"[SmartParser] Skipped entry due to error: {e}")
            skipped += 1

    print(f"[SmartParser] Parsed: {len(parsed_logs)} | Skipped: {skipped}")
    return parsed_logs, format_used