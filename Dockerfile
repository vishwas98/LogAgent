FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY splunk_rca_agent.py codebase_context.py logagent_cli.py ./

# Run once and exit (schedule externally via cron / Kubernetes CronJob)
ENTRYPOINT ["python", "splunk_rca_agent.py"]
