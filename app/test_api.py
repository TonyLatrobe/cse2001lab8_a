# API contract tests. These run against the **live staging deployment** after deploy.
# Uses only `http.client` from the Python standard library — no external packages.

# test_api.py — Topic 2 + 8: API Contract Tests
# Run against the live hash-api service after Deploy to Staging.
# Set API_BASE_URL env var; defaults to staging cluster DNS.

import http.client
import json
import os
import pytest

# Cluster DNS resolved inside the pipeline pod
API_HOST = os.environ.get("API_HOST", "hash-api.staging.svc.cluster.local")
API_PORT = int(os.environ.get("API_PORT", "8080"))


def _get(path: str) -> tuple:
    """Return (status_code, parsed_json_body)."""
    conn = http.client.HTTPConnection(API_HOST, API_PORT, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = json.loads(resp.read())
    conn.close()
    return resp.status, body


def _post(path: str, payload: dict) -> tuple:
    """POST JSON payload; return (status_code, parsed_json_body)."""
    data = json.dumps(payload).encode()
    conn = http.client.HTTPConnection(API_HOST, API_PORT, timeout=10)
    conn.request(
        "POST", path, body=data,
        headers={"Content-Type": "application/json", "Content-Length": str(len(data))}
    )
    resp = conn.getresponse()
    body = json.loads(resp.read())
    conn.close()
    return resp.status, body


# ── Health endpoint ───────────────────────────────────────────────────────────

def test_health_returns_200():
    status, body = _get("/health")
    assert status == 200

def test_health_returns_ok_status():
    _, body = _get("/health")
    assert body["status"] == "ok"

def test_health_names_the_service():
    _, body = _get("/health")
    assert body["service"] == "hash-api"

# ── Algorithms endpoint ───────────────────────────────────────────────────────

def test_algorithms_returns_200():
    status, _ = _get("/algorithms")
    assert status == 200

def test_algorithms_includes_sha256():
    _, body = _get("/algorithms")
    assert "sha256" in body["algorithms"]

def test_algorithms_list_is_sorted():
    _, body = _get("/algorithms")
    algos = body["algorithms"]
    assert algos == sorted(algos)

# ── GET /hash — correctness ───────────────────────────────────────────────────

def test_get_hash_sha256_returns_200():
    status, _ = _get("/hash?algorithm=sha256&data=hello")
    assert status == 200

def test_get_hash_sha256_correct_value():
    _, body = _get("/hash?algorithm=sha256&data=hello")
    assert body["hash"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

def test_get_hash_echoes_input():
    _, body = _get("/hash?algorithm=sha256&data=hello")
    assert body["input"] == "hello"
    assert body["algorithm"] == "sha256"

def test_get_hash_md5_correct_value():
    _, body = _get("/hash?algorithm=md5&data=hello")
    assert body["hash"] == "5d41402abc4b2a76b9719d911017c592"

def test_get_hash_sha512_output_length():
    _, body = _get("/hash?algorithm=sha512&data=test")
    assert len(body["hash"]) == 128

def test_get_hash_empty_data():
    status, body = _get("/hash?algorithm=sha256&data=")
    assert status == 200
    assert len(body["hash"]) == 64

def test_get_hash_default_algorithm_is_sha256():
    _, body = _get("/hash?data=hello")
    assert body["algorithm"] == "sha256"

# ── GET /hash — error handling ────────────────────────────────────────────────

def test_get_hash_invalid_algorithm_returns_400():
    status, _ = _get("/hash?algorithm=md99&data=hello")
    assert status == 400

def test_get_hash_invalid_algorithm_returns_error_field():
    _, body = _get("/hash?algorithm=md99&data=hello")
    assert "error" in body

# ── POST /hash — correctness ──────────────────────────────────────────────────

def test_post_hash_returns_200():
    status, _ = _post("/hash", {"algorithm": "sha256", "data": "hello"})
    assert status == 200

def test_post_hash_sha256_correct_value():
    _, body = _post("/hash", {"algorithm": "sha256", "data": "hello"})
    assert body["hash"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

def test_post_hash_matches_get_hash():
    _, get_body = _get("/hash?algorithm=sha256&data=consistency-check")
    _, post_body = _post("/hash", {"algorithm": "sha256", "data": "consistency-check"})
    assert get_body["hash"] == post_body["hash"]

def test_post_hash_invalid_algorithm_returns_400():
    status, body = _post("/hash", {"algorithm": "ripemd", "data": "hello"})
    assert status == 400
    assert "error" in body

# ── 404 for unknown paths ─────────────────────────────────────────────────────

def test_unknown_path_returns_404():
    status, _ = _get("/does-not-exist")
    assert status == 404