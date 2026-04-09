#The testable business logic layer. No HTTP, no I/O — pure functions only.
# hash_service.py — core hashing logic.
#All business rules live here so unit tests need no HTTP server.
import hashlib

SUPPORTED_ALGORITHMS = {"md5", "sha1", "sha256", "sha512"}


def compute_hash(algorithm: str, data: str) -> str:
    """
    Return the hex digest of data using algorithm.
    Raises ValueError for unsupported algorithms.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Supported: {sorted(SUPPORTED_ALGORITHMS)}"
        )
    h = hashlib.new(algorithm)
    h.update(data.encode("utf-8"))
    return h.hexdigest()


def supported_algorithms() -> list:
    """Return sorted list of supported algorithm names."""
    return sorted(SUPPORTED_ALGORITHMS)
