def run_detection(parsed_logs):
    """
    Takes a list of parsed log entries.
    Returns a list of alerts for any suspicious activity found.
    """
    alerts = []

    for log in parsed_logs:
        event_id = log["event_id"]

        # Rule 1: Failed Login Attempt
        if event_id == 4625:
            alerts.append({
                "alert_name":   "Failed Login Attempt",
                "severity":     "Medium",
                "description":  f"Failed login detected for user '{log['username']}' on {log['hostname']}",
                "timestamp":    log["timestamp"],
                "mitre_id":     "T1110",
                "mitre_name":   "Brute Force",
                "event_id":     event_id,
                "username":     log["username"],
                "hostname":     log["hostname"],
                "process":      log["process"]
            })

        # Rule 2: New User Account Created
        elif event_id == 4720:
            alerts.append({
                "alert_name":   "New User Account Created",
                "severity":     "High",
                "description":  f"New user account created by '{log['username']}' on {log['hostname']}",
                "timestamp":    log["timestamp"],
                "mitre_id":     "T1136",
                "mitre_name":   "Create Account",
                "event_id":     event_id,
                "username":     log["username"],
                "hostname":     log["hostname"],
                "process":      log["process"]
            })

        # Rule 3: Suspicious PowerShell Execution
        elif event_id == 4104:
            alerts.append({
                "alert_name":   "Suspicious PowerShell Execution",
                "severity":     "High",
                "description":  f"PowerShell script execution detected by '{log['username']}' — possible encoded command",
                "timestamp":    log["timestamp"],
                "mitre_id":     "T1059.001",
                "mitre_name":   "PowerShell",
                "event_id":     event_id,
                "username":     log["username"],
                "hostname":     log["hostname"],
                "process":      log["process"]
            })

        # Rule 4: Scheduled Task Created
        elif event_id == 4698:
            alerts.append({
                "alert_name":   "Scheduled Task Created",
                "severity":     "High",
                "description":  f"Scheduled task created by '{log['username']}' — possible persistence mechanism",
                "timestamp":    log["timestamp"],
                "mitre_id":     "T1053.005",
                "mitre_name":   "Scheduled Task",
                "event_id":     event_id,
                "username":     log["username"],
                "hostname":     log["hostname"],
                "process":      log["process"]
            })

        # Rule 5: New Service Installed
        elif event_id == 7045:
            alerts.append({
                "alert_name":   "New Service Installed",
                "severity":     "Critical",
                "description":  f"A new service was installed by '{log['username']}' — possible malware persistence",
                "timestamp":    log["timestamp"],
                "mitre_id":     "T1543.003",
                "mitre_name":   "Windows Service",
                "event_id":     event_id,
                "username":     log["username"],
                "hostname":     log["hostname"],
                "process":      log["process"]
            })

        # Rule 6: Successful Login (low severity, informational)
        elif event_id == 4624:
            alerts.append({
                "alert_name":   "Successful Login",
                "severity":     "Low",
                "description":  f"Successful login by '{log['username']}' on {log['hostname']}",
                "timestamp":    log["timestamp"],
                "mitre_id":     "T1078",
                "mitre_name":   "Valid Accounts",
                "event_id":     event_id,
                "username":     log["username"],
                "hostname":     log["hostname"],
                "process":      log["process"]
            })

    return alerts


def get_summary(alerts):
    """
    Takes a list of alerts.
    Returns counts by severity for the dashboard.
    """
    summary = {
        "total":    len(alerts),
        "critical": 0,
        "high":     0,
        "medium":   0,
        "low":      0
    }

    for alert in alerts:
        severity = alert["severity"].lower()
        if severity in summary:
            summary[severity] += 1

    return summary