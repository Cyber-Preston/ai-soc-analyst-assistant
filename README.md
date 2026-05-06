# AI-Powered SOC Analyst Assistant

A beginner-friendly cybersecurity portfolio project that acts like a mini SOC analyst.

It ingests Linux/authentication logs, detects suspicious activity, creates security alerts, and uses an AI-style analyst engine to explain what happened and recommend remediation steps.

## Recruiter-friendly summary

This project demonstrates:

- Python backend development
- Security log analysis
- Detection engineering
- Incident response thinking
- Dashboard development
- Docker deployment
- AI-assisted cyber analysis

## Features

- Upload or paste Linux authentication logs
- Detect failed SSH brute-force attempts
- Detect successful SSH logins
- Detect suspicious root login attempts
- Generate risk score: Low, Medium, High, Critical
- Produce analyst-style explanations
- Recommend remediation steps
- View alerts in a browser dashboard
- Run locally or with Docker

## Tech Stack

- Python
- FastAPI
- SQLite
- Jinja2 templates
- Docker
- Optional OpenAI API integration

## Quick Start

### 1. Run locally

```bash
cd ai-soc-assistant
python -m venv venv
source venv/bin/activate   # Linux/macOS
# venv\Scripts\activate    # Windows

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:

```txt
http://127.0.0.1:8000
```

### 2. Run with Docker

```bash
docker compose up --build
```

Open:

```txt
http://127.0.0.1:8000
```

## Demo Logs

Use the file:

```txt
sample_logs/auth.log
```

Paste the contents into the dashboard and click **Analyze Logs**.

## Optional OpenAI Setup

This app works without an API key using a built-in local analyst engine.

To use OpenAI later, set:

```bash
export OPENAI_API_KEY="your_api_key_here"
```

Then update `app/ai_engine.py` to call your preferred OpenAI model.

## Resume Bullet

Built an AI-powered SOC Analyst Assistant using Python, FastAPI, SQLite, and Docker to analyze Linux authentication logs, detect SSH brute-force activity, generate incident summaries, and recommend remediation steps through a web dashboard.

## Project Structure

```txt
ai-soc-assistant/
├── app/
│   ├── main.py
│   ├── detector.py
│   ├── ai_engine.py
│   ├── database.py
│   └── static/
├── sample_logs/
│   └── auth.log
├── docs/
│   └── architecture.md
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Future Improvements

- Add Suricata or Zeek log support
- Add GeoIP attacker location mapping
- Add Slack or Discord alerts
- Add VirusTotal IP reputation lookup
- Add MITRE ATT&CK mapping
- Add authentication to the dashboard
