import re
from collections import defaultdict

FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>[\w.-]+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

ACCEPTED_PATTERN = re.compile(
    r"Accepted password for (?P<user>[\w.-]+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def detect_events(log_text: str) -> list[dict]:
    lines = [line.strip() for line in log_text.splitlines() if line.strip()]
    failed_by_ip = defaultdict(list)
    events = []

    for line in lines:
        failed_match = FAILED_PATTERN.search(line)
        accepted_match = ACCEPTED_PATTERN.search(line)

        if failed_match:
            user = failed_match.group("user")
            ip = failed_match.group("ip")
            failed_by_ip[ip].append(line)

            if user == "root":
                events.append({
                    "title": "Root Login Attempt Detected",
                    "severity": "High",
                    "source_ip": ip,
                    "event_type": "root_login_attempt",
                    "raw_event": line,
                    "details": {
                        "username": user,
                        "reason": "Attackers commonly target root because it has full administrative control."
                    }
                })

        if accepted_match:
            user = accepted_match.group("user")
            ip = accepted_match.group("ip")
            severity = "Medium" if user != "root" else "Critical"
            events.append({
                "title": "Successful SSH Login Detected",
                "severity": severity,
                "source_ip": ip,
                "event_type": "successful_ssh_login",
                "raw_event": line,
                "details": {
                    "username": user,
                    "reason": "Successful login should be reviewed to confirm it was authorized."
                }
            })

    for ip, failed_lines in failed_by_ip.items():
        if len(failed_lines) >= 5:
            events.append({
                "title": "Possible SSH Brute-Force Attack",
                "severity": "Critical" if len(failed_lines) >= 10 else "High",
                "source_ip": ip,
                "event_type": "ssh_bruteforce",
                "raw_event": "\n".join(failed_lines),
                "details": {
                    "failed_attempts": len(failed_lines),
                    "reason": "Multiple failed logins from the same IP indicate possible credential guessing."
                }
            })

    return events
