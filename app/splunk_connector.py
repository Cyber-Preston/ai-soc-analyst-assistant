import os
import splunklib.client as client
import splunklib.results as results
from dotenv import load_dotenv

load_dotenv()

def pull_splunk_auth_logs() -> str:
    host = os.getenv("SPLUNK_HOST", "localhost")
    port = int(os.getenv("SPLUNK_PORT", "8089"))
    username = os.getenv("SPLUNK_USERNAME")
    password = os.getenv("SPLUNK_PASSWORD")

    service = client.connect(
        host=host,
        port=port,
        username=username,
        password=password
    )

    query = """
    search index=* sourcetype=linux_secure
    | table _raw
    """

    stream = service.jobs.export(query)
    reader = results.ResultsReader(stream)

    raw_events = []

    for item in reader:
        if isinstance(item, dict):
            raw = item.get("_raw")
            if raw:
                raw_events.append(raw)

    return "\n".join(raw_events)