import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2:3b"

def generate_analysis(event: dict) -> dict:
    prompt = f"""
You are a SOC analyst assistant.

Analyze this cybersecurity event.

Title: {event.get("title")}
Severity: {event.get("severity")}
Source IP: {event.get("source_ip")}
Event Type: {event.get("event_type")}
Raw Event:
{event.get("raw_event")}

Provide:
1. Summary
2. Why this matters
3. Recommended remediation

Keep responses concise and professional.
"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False
            },
            timeout=90
        )

        response.raise_for_status()

        ai_text = response.json().get("response", "").strip()

        return {
            "ai_summary": ai_text,
            "recommendation": "Review the AI-generated recommendations above."
        }

    except Exception as e:
        print(f"Ollama AI failed: {e}")

        return fallback_analysis(event)


def fallback_analysis(event: dict) -> dict:
    return {
        "ai_summary": (
            f"{event.get('severity')} alert involving "
            f"{event.get('event_type')} from "
            f"{event.get('source_ip')}."
        ),
        "recommendation": (
            "Investigate the source activity and review related logs."
        )
    }