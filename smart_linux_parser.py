import re
import json


# ── Format Detectors ────────────────────────────────────────────────────────

def detect_linux_format(line):
    """
    Takes a single log line and returns which format it is.
    """
    line = line.strip()

    if not line:
        return "empty"

    # Journalctl JSON — line starts with {
    if line.startswith("{"):
        try:
            json.loads(line)
            return "journalctl_json"
        except:
            pass

    # RFC 5424 — starts with <number>
    if re.match(r'^<\d+>', line):
        return "rfc5424"

    # Systemd journal export — starts with ISO timestamp
    if re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', line):
        return "systemd"

    # Standard syslog — starts with month abbreviation
    if re.match(r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+', line):
        return "syslog"

    return "unknown"


# ── Format Normalizers ───────────────────────────────────────────────────────

def normalize_syslog(line):
    """
    Standard syslog format used by Ubuntu, Debian, CentOS.
    Format: Jan 15 10:23:45 hostname process[pid]: message
    """
    pattern = re.compile(
        r'^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.+)$'
    )
    match = pattern.match(line.strip())
    if not match:
        return None

    timestamp, hostname, process, message = match.groups()
    return {
        "timestamp": timestamp,
        "hostname":  hostname,
        "process":   process.lower(),
        "message":   message,
        "raw":       line.strip()
    }


def normalize_systemd(line):
    """
    Systemd journal export format.
    Format: 2024-01-15T10:23:45+0000 hostname process[pid]: message
    """
    pattern = re.compile(
        r'^(\d{4}-\d{2}-\d{2}T[\d:+Z]+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.+)$'
    )
    match = pattern.match(line.strip())
    if not match:
        return None

    timestamp, hostname, process, message = match.groups()
    return {
        "timestamp": timestamp,
        "hostname":  hostname,
        "process":   process.lower(),
        "message":   message,
        "raw":       line.strip()
    }


def normalize_rfc5424(line):
    """
    RFC 5424 syslog format.
    Format: <34>1 2024-01-15T10:23:45Z hostname appname pid msgid message
    """
    pattern = re.compile(
        r'^<\d+>\d+\s+'           # priority + version
        r'(\S+)\s+'               # timestamp
        r'(\S+)\s+'               # hostname
        r'(\S+)\s+'               # appname
        r'\S+\s+'                 # pid
        r'\S+\s+'                 # msgid
        r'(.+)$'                  # message
    )
    match = pattern.match(line.strip())
    if not match:
        return None

    timestamp, hostname, process, message = match.groups()
    return {
        "timestamp": timestamp,
        "hostname":  hostname,
        "process":   process.lower(),
        "message":   message,
        "raw":       line.strip()
    }


def normalize_journalctl_json(line):
    """
    Journalctl JSON export format.
    Each line is a separate JSON object with fields like:
    __REALTIME_TIMESTAMP, _HOSTNAME, SYSLOG_IDENTIFIER, MESSAGE
    """
    try:
        entry = json.loads(line.strip())
    except:
        return None

    # Timestamp is microseconds since epoch — convert to readable
    raw_ts = entry.get("__REALTIME_TIMESTAMP", "")
    if raw_ts:
        try:
            from datetime import datetime
            ts = datetime.fromtimestamp(int(raw_ts) / 1_000_000)
            timestamp = ts.strftime("%Y-%m-%dT%H:%M:%S")
        except:
            timestamp = raw_ts
    else:
        timestamp = entry.get("__SOURCE_REALTIME_TIMESTAMP", "Unknown")

    message = entry.get("MESSAGE", "")

    # MESSAGE can sometimes be a list of byte values
    if isinstance(message, list):
        try:
            message = bytes(message).decode("utf-8", errors="ignore")
        except:
            message = str(message)

    return {
        "timestamp": timestamp,
        "hostname":  entry.get("_HOSTNAME", "Unknown"),
        "process":   entry.get("SYSLOG_IDENTIFIER", entry.get("_COMM", "Unknown")).lower(),
        "message":   message,
        "raw":       line.strip()
    }


# ── Main Smart Linux Parser ──────────────────────────────────────────────────

def smart_parse_linux(filepath):
    """
    Main entry point. Reads any supported Linux log format.
    Returns a list of normalized log entries + format report.
    """
    parsed_logs  = []
    skipped      = 0
    format_used  = "unknown"
    format_counts = {}

    try:
        with open(filepath, 'r', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[SmartLinuxParser] File read error: {e}")
        return [], "file_error"

    if not lines:
        return [], "empty"

    # Detect format from first non-empty line
    for line in lines:
        if line.strip():
            format_used = detect_linux_format(line)
            break

    print(f"[SmartLinuxParser] Detected format: {format_used}")

    # Map format to normalizer
    normalizer_map = {
        "syslog":          normalize_syslog,
        "systemd":         normalize_systemd,
        "rfc5424":         normalize_rfc5424,
        "journalctl_json": normalize_journalctl_json,
    }

    normalizer = normalizer_map.get(format_used)

    for line in lines:
        line = line.strip()
        if not line:
            continue

        try:
            if normalizer:
                log = normalizer(line)
            else:
                # Unknown format — try each normalizer until one works
                log = None
                for fmt, norm_fn in normalizer_map.items():
                    log = norm_fn(line)
                    if log:
                        format_used = f"{fmt} (fallback)"
                        break

            if log and log.get("message"):
                parsed_logs.append(log)
            else:
                skipped += 1

        except Exception as e:
            print(f"[SmartLinuxParser] Skipped line: {e}")
            skipped += 1

    print(f"[SmartLinuxParser] Parsed: {len(parsed_logs)} | Skipped: {skipped}")
    return parsed_logs, format_used