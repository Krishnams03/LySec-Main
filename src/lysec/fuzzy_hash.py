"""
LySec - Fuzzy Hash Utilities
Optional ssdeep / TLSH hashing for near-similarity comparisons.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


try:
    import ssdeep  # type: ignore
    HAS_SSDEEP = True
except Exception:
    ssdeep = None
    HAS_SSDEEP = False

try:
    import tlsh  # type: ignore
    HAS_TLSH = True
except Exception:
    tlsh = None
    HAS_TLSH = False


def compute_fuzzy_hashes(file_path: str, algorithms: list[str] | None = None) -> dict[str, str]:
    """Compute fuzzy hashes for file path using available libraries."""
    algorithms = [a.lower() for a in (algorithms or ["ssdeep", "tlsh"])]
    result: dict[str, str] = {}

    if not Path(file_path).is_file():
        return result

    if "ssdeep" in algorithms and HAS_SSDEEP:
        try:
            digest = ssdeep.hash_from_file(file_path)
            if digest:
                result["ssdeep"] = str(digest)
        except Exception:
            pass

    if "tlsh" in algorithms and HAS_TLSH:
        try:
            data = Path(file_path).read_bytes()
            # TLSH requires enough content/entropy. Skip tiny files.
            if len(data) >= 50:
                digest = tlsh.hash(data)
                if digest and digest != "TNULL":
                    result["tlsh"] = str(digest)
        except Exception:
            pass

    return result


def compare_fuzzy_hashes(
    previous_hashes: dict[str, str] | None,
    current_hashes: dict[str, str] | None,
) -> dict[str, Any]:
    """
    Compare two fuzzy hash dictionaries.

    Returns:
      - ssdeep_score (0-100, higher means more similar)
      - tlsh_distance (0+, lower means more similar)
    """
    previous_hashes = previous_hashes or {}
    current_hashes = current_hashes or {}

    out: dict[str, Any] = {}

    prev_ssdeep = previous_hashes.get("ssdeep")
    curr_ssdeep = current_hashes.get("ssdeep")
    if prev_ssdeep and curr_ssdeep and HAS_SSDEEP:
        try:
            out["ssdeep_score"] = int(ssdeep.compare(prev_ssdeep, curr_ssdeep))
        except Exception:
            pass

    prev_tlsh = previous_hashes.get("tlsh")
    curr_tlsh = current_hashes.get("tlsh")
    if prev_tlsh and curr_tlsh and HAS_TLSH:
        try:
            out["tlsh_distance"] = int(tlsh.diffxlen(prev_tlsh, curr_tlsh))
        except Exception:
            pass

    return out
