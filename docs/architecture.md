# Architecture

## Goal

Create a small SOC-style dashboard that analyzes authentication logs and turns them into understandable security alerts.

## Flow

```txt
Linux/Auth Logs
      |
      v
Log Parser
      |
      v
Detection Engine
      |
      v
AI Analyst Engine
      |
      v
SQLite Database
      |
      v
Web Dashboard
```

## Detection Rules

### SSH Brute Force

Detects 5 or more failed password attempts from the same IP address.

### Successful SSH Login

Detects successful SSH authentication events.

### Root Login Attempt

Detects authentication attempts involving the root account.

## Severity Model

- Critical: many failed attempts or root-related activity
- High: brute-force pattern
- Medium: successful login or suspicious login
- Low: informational event

## Recruiter Talking Points

- I built detection logic for SSH brute-force behavior.
- I created an AI-style analyst engine to summarize alerts.
- I used FastAPI and SQLite to make the project easy to deploy.
- I containerized the project with Docker.
- I designed the project so it can later integrate with Wazuh, Suricata, Zeek, or cloud logs.
