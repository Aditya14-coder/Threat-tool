import re
import requests

VT_BASE = "https://www.virustotal.com/api/v3"


# ── Input Type Detector ──────────────────────────────────────────────────────

def detect_input_type(query):
    """
    Detects whether the input is an IP, domain, or file hash.
    """
    query = query.strip()

    # IPv4 address
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', query):
        return "ip"

    # MD5, SHA1, SHA256 hash
    if re.match(r'^[a-fA-F0-9]{32}$', query):
        return "hash"  # MD5
    if re.match(r'^[a-fA-F0-9]{40}$', query):
        return "hash"  # SHA1
    if re.match(r'^[a-fA-F0-9]{64}$', query):
        return "hash"  # SHA256

    # Domain (basic check)
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', query):
        return "domain"

    return "unknown"


# ── VirusTotal Lookups ───────────────────────────────────────────────────────

def lookup_ip(ip, api_key):
    """Query VirusTotal for an IP address."""
    url     = f"{VT_BASE}/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 404:
            return {"error": f"IP '{ip}' not found in VirusTotal database."}
        if response.status_code == 401:
            return {"error": "Invalid API key."}
        if response.status_code != 200:
            return {"error": f"VirusTotal returned status {response.status_code}"}

        data  = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())

        # Determine verdict
        if malicious >= 5:
            verdict = "Malicious"
        elif malicious >= 1 or suspicious >= 3:
            verdict = "Suspicious"
        else:
            verdict = "Clean"

        # Get engines that flagged it
        engines = attrs.get("last_analysis_results", {})
        flagged = [
            {"engine": name, "result": info.get("result", "N/A")}
            for name, info in engines.items()
            if info.get("category") in ("malicious", "suspicious")
        ]

        return {
            "type":        "IP Address",
            "query":       ip,
            "verdict":     verdict,
            "malicious":   malicious,
            "suspicious":  suspicious,
            "clean":       stats.get("undetected", 0),
            "total":       total,
            "country":     attrs.get("country", "Unknown"),
            "owner":       attrs.get("as_owner", "Unknown"),
            "reputation":  attrs.get("reputation", "N/A"),
            "flagged_by":  flagged[:10],  # top 10 only
            "tags":        attrs.get("tags", []),
            "error":       None
        }

    except requests.exceptions.Timeout:
        return {"error": "Request timed out. Try again."}
    except Exception as e:
        return {"error": f"Lookup failed: {str(e)}"}


def lookup_domain(domain, api_key):
    """Query VirusTotal for a domain."""
    url     = f"{VT_BASE}/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 404:
            return {"error": f"Domain '{domain}' not found in VirusTotal database."}
        if response.status_code == 401:
            return {"error": "Invalid API key."}
        if response.status_code != 200:
            return {"error": f"VirusTotal returned status {response.status_code}"}

        data  = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())

        if malicious >= 5:
            verdict = "Malicious"
        elif malicious >= 1 or suspicious >= 3:
            verdict = "Suspicious"
        else:
            verdict = "Clean"

        engines = attrs.get("last_analysis_results", {})
        flagged = [
            {"engine": name, "result": info.get("result", "N/A")}
            for name, info in engines.items()
            if info.get("category") in ("malicious", "suspicious")
        ]

        # Extract categories
        categories = attrs.get("categories", {})
        category_list = list(set(categories.values()))

        return {
            "type":        "Domain",
            "query":       domain,
            "verdict":     verdict,
            "malicious":   malicious,
            "suspicious":  suspicious,
            "clean":       stats.get("undetected", 0),
            "total":       total,
            "registrar":   attrs.get("registrar", "Unknown"),
            "creation":    attrs.get("creation_date", "Unknown"),
            "reputation":  attrs.get("reputation", "N/A"),
            "categories":  category_list,
            "flagged_by":  flagged[:10],
            "tags":        attrs.get("tags", []),
            "error":       None
        }

    except requests.exceptions.Timeout:
        return {"error": "Request timed out. Try again."}
    except Exception as e:
        return {"error": f"Lookup failed: {str(e)}"}


def lookup_hash(file_hash, api_key):
    """Query VirusTotal for a file hash (MD5/SHA1/SHA256)."""
    url     = f"{VT_BASE}/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 404:
            return {"error": f"Hash '{file_hash}' not found. File may not have been submitted to VirusTotal."}
        if response.status_code == 401:
            return {"error": "Invalid API key."}
        if response.status_code != 200:
            return {"error": f"VirusTotal returned status {response.status_code}"}

        data  = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())

        if malicious >= 5:
            verdict = "Malicious"
        elif malicious >= 1 or suspicious >= 3:
            verdict = "Suspicious"
        else:
            verdict = "Clean"

        engines = attrs.get("last_analysis_results", {})
        flagged = [
            {"engine": name, "result": info.get("result", "N/A")}
            for name, info in engines.items()
            if info.get("category") in ("malicious", "suspicious")
        ]

        return {
            "type":        "File Hash",
            "query":       file_hash,
            "verdict":     verdict,
            "malicious":   malicious,
            "suspicious":  suspicious,
            "clean":       stats.get("undetected", 0),
            "total":       total,
            "file_type":   attrs.get("type_description", "Unknown"),
            "file_size":   attrs.get("size", "Unknown"),
            "file_names":  attrs.get("names", [])[:5],
            "md5":         attrs.get("md5", "N/A"),
            "sha1":        attrs.get("sha1", "N/A"),
            "sha256":      attrs.get("sha256", "N/A"),
            "flagged_by":  flagged[:10],
            "tags":        attrs.get("tags", []),
            "error":       None
        }

    except requests.exceptions.Timeout:
        return {"error": "Request timed out. Try again."}
    except Exception as e:
        return {"error": f"Lookup failed: {str(e)}"}


# ── Main Lookup Router ───────────────────────────────────────────────────────

def threat_lookup(query, api_key):
    """
    Main entry point. Detects input type and routes to correct lookup.
    """
    query       = query.strip()
    input_type  = detect_input_type(query)

    if input_type == "ip":
        return lookup_ip(query, api_key)
    elif input_type == "domain":
        return lookup_domain(query, api_key)
    elif input_type == "hash":
        return lookup_hash(query, api_key)
    else:
        return {"error": "Unrecognized input. Please enter a valid IP address, domain, or MD5/SHA1/SHA256 hash."}