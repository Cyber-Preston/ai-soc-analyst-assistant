from pathlib import Path
from collections import Counter

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.threat_intel import check_ip_reputation
from app.splunk_connector import pull_splunk_auth_logs
from app.detector import detect_events
from app.ai_engine import generate_analysis
from app.database import init_db, save_alert, get_alerts, clear_alerts
from app.mitre import get_mitre_mapping


app = FastAPI(title="AI-Powered SOC Analyst Assistant")

templates = Environment(
    loader=FileSystemLoader("app/templates"),
    autoescape=select_autoescape()
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.on_event("startup")
def startup_event():
    init_db()


def calculate_risk_score(event: dict) -> int:
    score = 30

    if event["severity"] == "Medium":
        score += 20
    elif event["severity"] == "High":
        score += 40
    elif event["severity"] == "Critical":
        score += 60

    if event["event_type"] == "ssh_bruteforce":
        score += 10

    if event["event_type"] == "root_login_attempt":
        score += 15

    if event["event_type"] == "successful_ssh_login":
        score += 5

    return min(score, 100)


def enrich_and_save_events(events: list[dict]) -> None:
    for event in events:
        ai_result = generate_analysis(event)
        mitre = get_mitre_mapping(event["event_type"])
        intel = check_ip_reputation(event.get("source_ip"))

        event.update(ai_result)
        event["risk_score"] = calculate_risk_score(event)

        event["mitre_technique"] = mitre["technique"]
        event["mitre_name"] = mitre["name"]
        event["mitre_tactic"] = mitre["tactic"]

        event["threat_reputation"] = intel["reputation"]
        event["threat_confidence"] = intel["confidence"]
        event["threat_country"] = intel["country"]

        save_alert(event)


def build_dashboard_metrics(alerts: list[dict]) -> dict:
    source_ips = {
        alert.get("source_ip")
        for alert in alerts
        if alert.get("source_ip")
    }

    mitre_techniques = {
        alert.get("mitre_technique")
        for alert in alerts
        if alert.get("mitre_technique") and alert.get("mitre_technique") != "N/A"
    }

    severity_counts = Counter(
        alert.get("severity", "Unknown")
        for alert in alerts
    )

    top_attackers = Counter(
        alert.get("source_ip")
        for alert in alerts
        if alert.get("source_ip")
    ).most_common(5)

    mitre_counts = Counter(
        alert.get("mitre_technique")
        for alert in alerts
        if alert.get("mitre_technique") and alert.get("mitre_technique") != "N/A"
    )

    return {
        "total_alerts": len(alerts),
        "critical_alerts": severity_counts.get("Critical", 0),
        "high_alerts": severity_counts.get("High", 0),
        "unique_attackers": len(source_ips),
        "mitre_techniques": len(mitre_techniques),
        "top_attackers": top_attackers,

        "severity_labels": list(severity_counts.keys()),
        "severity_values": list(severity_counts.values()),

        "attacker_labels": [ip for ip, count in top_attackers],
        "attacker_values": [count for ip, count in top_attackers],

        "mitre_labels": list(mitre_counts.keys()),
        "mitre_values": list(mitre_counts.values()),
    }


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    template = templates.get_template("dashboard.html")
    alerts = get_alerts()
    metrics = build_dashboard_metrics(alerts)

    return template.render(
        alerts=alerts,
        alert_count=len(alerts),
        metrics=metrics
    )


@app.post("/analyze")
def analyze_logs(log_text: str = Form(...)):
    events = detect_events(log_text)
    enrich_and_save_events(events)

    return RedirectResponse("/", status_code=303)


@app.post("/monitor")
def monitor_sample_log():
    log_path = Path("sample_logs/auth.log")

    if log_path.exists():
        log_text = log_path.read_text(encoding="utf-8")
        events = detect_events(log_text)
        enrich_and_save_events(events)

    return RedirectResponse("/", status_code=303)


@app.post("/clear")
def clear():
    clear_alerts()
    return RedirectResponse("/", status_code=303)


@app.get("/report", response_class=PlainTextResponse)
def export_report():
    alerts = get_alerts()

    report = []
    report.append("AI-Powered SOC Analyst Assistant - Incident Report")
    report.append("=" * 60)
    report.append("")

    if not alerts:
        report.append("No alerts found.")
        return "\n".join(report)

    for alert in alerts:
        report.append(f"Alert: {alert.get('title')}")
        report.append(f"Severity: {alert.get('severity')}")
        report.append(f"Risk Score: {alert.get('risk_score')}/100")
        report.append(f"Source IP: {alert.get('source_ip')}")
        report.append(f"Event Type: {alert.get('event_type')}")
        report.append(f"MITRE ATT&CK: {alert.get('mitre_technique')} - {alert.get('mitre_name')}")
        report.append(f"Tactic: {alert.get('mitre_tactic')}")
        report.append(f"Threat Reputation: {alert.get('threat_reputation')}")
        report.append(f"Confidence: {alert.get('threat_confidence')}%")
        report.append(f"Origin Country: {alert.get('threat_country')}")
        report.append("")
        report.append("AI Analysis:")
        report.append(alert.get("ai_summary", ""))
        report.append("")
        report.append("Recommendation:")
        report.append(alert.get("recommendation", ""))
        report.append("")
        report.append("Raw Event:")
        report.append(alert.get("raw_event", ""))
        report.append("")
        report.append("-" * 60)
        report.append("")

    return "\n".join(report)


@app.post("/splunk")
def pull_from_splunk():
    try:
        log_text = pull_splunk_auth_logs()

        if log_text.strip():
            events = detect_events(log_text)
            enrich_and_save_events(events)
        else:
            print("Splunk pull succeeded, but no logs were returned.")

    except Exception as e:
        print(f"Splunk pull failed: {e}")

    return RedirectResponse("/", status_code=303)


@app.get("/auto-pull")
def auto_pull():
    try:
        log_text = pull_splunk_auth_logs()

        if log_text.strip():
            events = detect_events(log_text)
            enrich_and_save_events(events)

    except Exception as e:
        print(f"Auto pull failed: {e}")

    return {"status": "ok"}


@app.get("/health")
def health():
    return {"status": "ok"}