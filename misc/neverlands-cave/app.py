"""Neverland's Cave - address preview service.

``/api/fetch`` fetches a caller-supplied address on the server's behalf and
returns the raw response. The request contract is served by ``GET /api``.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from flask import Flask, jsonify, request, send_file

app = Flask(__name__)

CLOUD_ENDPOINT = os.environ.get("CLOUD_ENDPOINT", "http://broker:8080")
IMDS_IP = os.environ.get("IMDS_IP", "100.100.100.200")

# Machine-readable description of the preview API (discoverable at GET /api).
API = {
    "service": "cave-preview",
    "endpoint": "/api/fetch",
    "methods": ["GET", "POST"],
    "schemes": ["http", "https", "file"],
    "params": {
        "url": "address to fetch (required)",
        "method": "HTTP method used to fetch the address (default: GET)",
        "headers": "JSON object of request headers",
        "body": "request body for POST/PUT",
    },
}


@app.get("/")
def index():
    return send_file(Path(__file__).with_name("index.html"))


@app.get("/api")
def api_index():
    return jsonify(API)


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")


@app.route("/api/fetch", methods=["GET", "POST"])
def fetch():
    """Fetch the requested address and return the raw response."""
    if request.method == "POST" and request.is_json:
        payload = request.get_json(silent=True) or {}
        url = payload.get("url", "")
        method = payload.get("method", "GET")
        headers = payload.get("headers", {}) or {}
        body = payload.get("body")
    else:
        url = request.args.get("url", "")
        method = request.args.get("method", "GET")
        headers = {}
        header_blob = request.args.get("headers")
        if header_blob:
            try:
                headers = json.loads(header_blob)
            except ValueError:
                headers = {}
        body = request.args.get("body")

    if not url:
        return jsonify(error="url is required", **API), 400
    scheme = url.split(":", 1)[0].lower() if ":" in url else ""
    if scheme not in API["schemes"]:
        return jsonify(error=f"unsupported scheme {scheme or '(none)'}", **API), 400

    data = body.encode() if isinstance(body, str) else body
    outbound = urllib.request.Request(url, data=data, method=method.upper())
    for name, value in headers.items():
        outbound.add_header(name, value)

    try:
        with urllib.request.urlopen(outbound, timeout=10) as response:
            content = response.read().decode("utf-8", "replace")
            return jsonify(url=url, status=getattr(response, "status", 200),
                           headers=dict(response.headers), body=content)
    except urllib.error.HTTPError as error:
        return jsonify(url=url, status=error.code,
                       headers=dict(error.headers),
                       body=error.read().decode("utf-8", "replace"))
    except Exception as error:  # noqa: BLE001 - report fetch failures to the caller
        return jsonify(url=url, error=str(error)), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9090)
