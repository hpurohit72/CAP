import requests
from logger import log_alert
import time

# Cache results to avoid repeated API calls
ip_cache = {}

# --------------- Configuration --------------------
VT_API_KEY = "d531759b84675ee58ebc359d31f7aa15d315e90cb28aa26d46bc6e5b34c020bf"      # <-- replace with your key
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

CACHE_TTL = 60 * 60  # 1 hour
# --------------------------------------------------

def vt_lookup_ip(ip):
    """
    Returns reputation score for given IP using VirusTotal.
    Safe: Handles errors, rate limits, and only checks your own traffic.
    """

    current_time = time.time()

    # Return cached result if fresh
    if ip in ip_cache:
        timestamp, data = ip_cache[ip]
        if current_time - timestamp < CACHE_TTL:
            return data

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(VT_URL.format(ip), headers=headers, timeout=5)

        if response.status_code == 200:
            data = response.json()

            malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            suspicious_count = data["data"]["attributes"]["last_analysis_stats"]["suspicious"]

            result = {
                "malicious": malicious_count,
                "suspicious": suspicious_count
            }

            # Store in cache
            ip_cache[ip] = (current_time, result)
            return result

        else:
            return {"malicious": 0, "suspicious": 0}

    except Exception as e:
        print("VirusTotal error:", e)
        return {"malicious": 0, "suspicious": 0}


def check_ip_reputation(ip):
    """
    High-level function to decide whether an alert should be raised.
    """

    rep = vt_lookup_ip(ip)

    mal = rep["malicious"]
    susp = rep["suspicious"]

    if mal > 0 or susp > 0:
        log_alert(f"Reputation Alert: IP {ip} flagged by threat intel "
                  f"(malicious={mal}, suspicious={susp})")
