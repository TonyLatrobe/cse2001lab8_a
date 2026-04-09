# Unit tests targeting `hash_service.py`. No HTTP, no running services, no network.
# SHA-256 expected values are computed offline and hard-coded — deterministic verification.

# test_unit.py
# Fast, isolated, no external dependencies. Tests hash_service.py only.

import hashlib
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hash_service import compute_hash, supported_algorithms, SUPPORTED_ALGORITHMS

# ── Supported algorithm set ────────────────────────────────────────────────────

def test_supported_algorithms_contains_sha256():
    assert "sha256" in SUPPORTED_ALGORITHMS

def test_supported_algorithms_contains_md5():
    assert "md5" in SUPPORTED_ALGORITHMS

def test_supported_algorithms_contains_sha1():
    assert "sha1" in SUPPORTED_ALGORITHMS

def test_supported_algorithms_contains_sha512():
    assert "sha512" in SUPPORTED_ALGORITHMS

def test_supported_algorithms_list_is_sorted():
    result = supported_algorithms()
    assert result == sorted(result)

# ── SHA-256 correctness ────────────────────────────────────────────────────────

def test_sha256_hello():
    # hashlib.sha256(b"hello").hexdigest() == 2cf24dba...
    expected = hashlib.sha256(b"hello").hexdigest()
    assert compute_hash("sha256", "hello") == expected

def test_sha256_empty_string():
    expected = hashlib.sha256(b"").hexdigest()
    assert compute_hash("sha256", "") == expected

def test_sha256_unicode():
    data = "héllo wörld"
    expected = hashlib.sha256(data.encode("utf-8")).hexdigest()
    assert compute_hash("sha256", data) == expected

def test_sha256_known_value():
    # Hard-coded ground truth — catches any accidental encoding change
    result = compute_hash("sha256", "hello")
    assert result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

# ── MD5 correctness ────────────────────────────────────────────────────────────

def test_md5_hello():
    expected = hashlib.md5(b"hello").hexdigest()
    assert compute_hash("md5", "hello") == expected

def test_md5_known_value():
    result = compute_hash("md5", "hello")
    assert result == "5d41402abc4b2a76b9719d911017c592"

# ── SHA-1 correctness ─────────────────────────────────────────────────────────

def test_sha1_hello():
    expected = hashlib.sha1(b"hello").hexdigest()
    assert compute_hash("sha1", "hello") == expected

# ── SHA-512 correctness ───────────────────────────────────────────────────────

def test_sha512_hello():
    expected = hashlib.sha512(b"hello").hexdigest()
    assert compute_hash("sha512", "hello") == expected

def test_sha512_output_length():
    result = compute_hash("sha512", "test")
    assert len(result) == 128  # SHA-512 = 512 bits = 128 hex chars

# ── Output format ─────────────────────────────────────────────────────────────

def test_sha256_output_is_lowercase_hex():
    result = compute_hash("sha256", "abc")
    assert result == result.lower()
    assert all(c in "0123456789abcdef" for c in result)

def test_sha256_output_length():
    result = compute_hash("sha256", "test")
    assert len(result) == 64  # SHA-256 = 256 bits = 64 hex chars

def test_md5_output_length():
    result = compute_hash("md5", "test")
    assert len(result) == 32  # MD5 = 128 bits = 32 hex chars

# ── Idempotency ───────────────────────────────────────────────────────────────

def test_same_input_same_output():
    assert compute_hash("sha256", "hello") == compute_hash("sha256", "hello")

def test_different_inputs_different_outputs():
    assert compute_hash("sha256", "hello") != compute_hash("sha256", "world")

# ── Error handling ────────────────────────────────────────────────────────────

def test_unsupported_algorithm_raises_value_error():
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        compute_hash("md99", "hello")

def test_unsupported_algorithm_error_names_the_algo():
    with pytest.raises(ValueError, match="md99"):
        compute_hash("md99", "test")

def test_empty_algorithm_raises():
    with pytest.raises(ValueError):
        compute_hash("", "hello")
