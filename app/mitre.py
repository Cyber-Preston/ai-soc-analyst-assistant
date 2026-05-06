MITRE_MAP = {
    "ssh_bruteforce": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Attackers may use brute-force techniques to guess passwords or credentials."
    },
    "root_login_attempt": {
        "technique": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": "Attackers may attempt to use privileged accounts such as root."
    },
    "successful_ssh_login": {
        "technique": "T1021.004",
        "name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "description": "SSH may be used by legitimate users or attackers for remote access."
    }
}

def get_mitre_mapping(event_type: str) -> dict:
    return MITRE_MAP.get(event_type, {
        "technique": "N/A",
        "name": "Unknown",
        "tactic": "Unknown",
        "description": "No MITRE ATT&CK mapping available."
    })