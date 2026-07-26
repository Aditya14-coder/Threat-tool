import re

def run_linux_detection(parsed_logs):
    """
    Takes parsed Linux auth.log entries.
    Returns alerts for suspicious activity.
    """
    alerts = []

    for log in parsed_logs:
        message = log["message"].lower()
        process = log["process"].lower()
        raw     = log["raw"]

        # Rule 1: SSH Failed Password
        if "failed password" in message and "sshd" in process:
            # Try to extract username and IP
            user_match = re.search(r'failed password for (\S+)', message)
            ip_match   = re.search(r'from ([\d.]+)', message)
            username   = user_match.group(1) if user_match else "Unknown"
            src_ip     = ip_match.group(1)   if ip_match   else "Unknown"

            alerts.append({
                "alert_name":  "SSH Failed Password",
                "severity":    "Medium",
                "description": f"Failed SSH login for user '{username}' from IP {src_ip}",
                "timestamp":   log["timestamp"],
                "mitre_id":    "T1110.001",
                "mitre_name":  "Password Guessing",
                "event_id":    "SSH-FAIL",
                "username":    username,
                "hostname":    log["hostname"],
                "process":     log["process"]
            })

        # Rule 2: SSH Successful Login
        elif "accepted password" in message and "sshd" in process:
            user_match = re.search(r'accepted password for (\S+)', message)
            ip_match   = re.search(r'from ([\d.]+)', message)
            username   = user_match.group(1) if user_match else "Unknown"
            src_ip     = ip_match.group(1)   if ip_match   else "Unknown"

            alerts.append({
                "alert_name":  "SSH Successful Login",
                "severity":    "Low",
                "description": f"Successful SSH login for user '{username}' from IP {src_ip}",
                "timestamp":   log["timestamp"],
                "mitre_id":    "T1078",
                "mitre_name":  "Valid Accounts",
                "event_id":    "SSH-OK",
                "username":    username,
                "hostname":    log["hostname"],
                "process":     log["process"]
            })

        # Rule 3: Sudo Command Executed
        elif "sudo" in process and "command" in message:
            user_match = re.search(r'^(\S+)\s+:', log["message"])
            cmd_match  = re.search(r'command=(.+)$', log["message"], re.IGNORECASE)
            username   = user_match.group(1) if user_match else "Unknown"
            command    = cmd_match.group(1)  if cmd_match  else "Unknown"

            alerts.append({
                "alert_name":  "Sudo Command Executed",
                "severity":    "High",
                "description": f"User '{username}' ran sudo command: {command}",
                "timestamp":   log["timestamp"],
                "mitre_id":    "T1548.003",
                "mitre_name":  "Sudo and Sudo Caching",
                "event_id":    "SUDO-EXEC",
                "username":    username,
                "hostname":    log["hostname"],
                "process":     log["process"]
            })

        # Rule 4: New User Created
        elif "new user" in message and "useradd" in process:
            user_match = re.search(r'name=(\S+),', message)
            username   = user_match.group(1) if user_match else "Unknown"

            alerts.append({
                "alert_name":  "New Linux User Created",
                "severity":    "High",
                "description": f"New user account '{username}' was created on {log['hostname']}",
                "timestamp":   log["timestamp"],
                "mitre_id":    "T1136",
                "mitre_name":  "Create Account",
                "event_id":    "USERADD",
                "username":    username,
                "hostname":    log["hostname"],
                "process":     log["process"]
            })

        # Rule 5: Failed SU Attempt
        elif "failed su" in message or ("su" in process and "failed" in message):
            user_match = re.search(r'for (\S+) by (\S+)', message)
            target     = user_match.group(1) if user_match else "Unknown"
            attacker   = user_match.group(2) if user_match else "Unknown"

            alerts.append({
                "alert_name":  "Failed SU Attempt",
                "severity":    "Medium",
                "description": f"User '{attacker}' failed to switch to '{target}' using su",
                "timestamp":   log["timestamp"],
                "mitre_id":    "T1548",
                "mitre_name":  "Abuse Elevation Control",
                "event_id":    "SU-FAIL",
                "username":    attacker,
                "hostname":    log["hostname"],
                "process":     log["process"]
            })

    return alerts