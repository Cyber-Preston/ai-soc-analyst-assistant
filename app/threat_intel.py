KNOWN_BAD_IPS = {
    "45.83.12.10": {
        "reputation": "Malicious",
        "confidence": 92,
        "country": "Russia",
        "provider": "Known brute-force activity"
    },
    "185.220.101.8": {
        "reputation": "Suspicious",
        "confidence": 76,
        "country": "Germany",
        "provider": "Tor exit node"
    }
}

def check_ip_reputation(ip: str) -> dict:
    return KNOWN_BAD_IPS.get(ip, {
        "reputation": "Unknown",
        "confidence": 15,
        "country": "Unknown",
        "provider": "No known threat intelligence"
    })