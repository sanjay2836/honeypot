FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY decoys/ssh_decoy/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY decoys/ssh_decoy /app/decoys/ssh_decoy

ENV PYTHONPATH=/app
EXPOSE 22

CMD ["python", "decoys/ssh_decoy/server.py"]
