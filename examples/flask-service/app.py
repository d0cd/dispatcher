"""Minimal Flask service for dispatcher's service-classification path.

Triggers the service branch (kind=service, long-running lifecycle, 24h cost
assumption, container-required packaging) via:
  - Declared port 8080 in dispatcher.yaml
  - EXPOSE 8080 in the Dockerfile

Health endpoint at /healthz so 'dispatcher status' has something to poll
against if/when adapters add HTTP probes.
"""
import os

from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")


@app.get("/")
def index():
    return jsonify(message="hello from dispatcher flask-service",
                   name=os.environ.get("SERVICE_NAME", "anonymous"))


if __name__ == "__main__":
    # Bind 0.0.0.0 so the container's EXPOSE'd port is reachable.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
