FROM python:3.11-slim

WORKDIR /app

COPY decoys/http_decoy/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY decoys/http_decoy /app/decoys/http_decoy

ENV PYTHONPATH=/app
EXPOSE 80

CMD ["uvicorn", "decoys.http_decoy.app:app", "--host", "0.0.0.0", "--port", "80"]
