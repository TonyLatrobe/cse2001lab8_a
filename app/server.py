# Pure Python stdlib HTTP server. No Flask, no external packages — runs inside `python-ci:lab` with zero downloads.
#!/usr/bin/env python3

# server.py — Hash API HTTP server.
# Pure stdlib: http.server, json, urllib.parse.
# Runs on PORT (default 8080). Reads LOG_LEVEL from environment.

# Endpoints:
#   GET  /health                              → {"status":"ok","service":"hash-api"}
#   GET  /algorithms                          → {"algorithms":["md5","sha1","sha256","sha512"]}
#   GET  /hash?algorithm=sha256&data=hello    → {"algorithm":"sha256","hash":"...","input":"hello"}
#   POST /hash  body: {"algorithm":"...","data":"..."}  → same shape as GET

import json
import logging
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer

# Resolve imports whether run as /app/server.py or from app/ CWD
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hash_service import compute_hash, supported_algorithms, SUPPORTED_ALGORITHMS

PORT = int(os.environ.get("PORT", "8080"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    stream=sys.stdout,
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("hash-api")


class HashHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):  # redirect access log to structlog
        log.info("%s %s", self.address_string(), fmt % args if args else fmt)

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/health":
            self._json(200, {"status": "ok", "service": "hash-api"})

        elif parsed.path == "/algorithms":
            self._json(200, {"algorithms": supported_algorithms()})

        elif parsed.path == "/hash":
            algo = qs.get("algorithm", ["sha256"])[0]
            data = qs.get("data", [""])[0]
            try:
                result = compute_hash(algo, data)
                self._json(200, {"algorithm": algo, "hash": result, "input": data})
            except ValueError as exc:
                self._json(400, {"error": str(exc)})

        else:
            self._json(404, {"error": "not found", "path": parsed.path})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/hash":
            self._json(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            self._json(400, {"error": "invalid JSON body"})
            return

        algo = payload.get("algorithm", "sha256")
        data = payload.get("data", "")
        try:
            result = compute_hash(algo, data)
            self._json(200, {"algorithm": algo, "hash": result, "input": data})
        except ValueError as exc:
            self._json(400, {"error": str(exc)})


if __name__ == "__main__":
    # ThreadingHTTPServer spawns a new thread per request.
    # HTTPServer (single-threaded) would serialise all requests — the k6 load
    # test runs 10 VUs simultaneously, so single-threaded would produce terrible
    # p95 latency and likely threshold failures.
    server = ThreadingHTTPServer(("0.0.0.0", PORT), HashHandler)
    log.info("Hash API (threaded) listening on :%d", PORT)
    server.serve_forever()
