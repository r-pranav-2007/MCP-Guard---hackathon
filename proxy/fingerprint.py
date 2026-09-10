"""Hashing for MCP Guard.

compute() hashes the ENTIRE manifest (name, description, all parameters,
tool_id, server_url, version) — not just the description field, per
PROJECT_BRIEF.md section 9. The manifest is canonicalized (keys sorted,
consistent JSON encoding) before hashing so harmless field reordering
doesn't cause false alarms, but the actual text content is never altered.
"""

import hashlib
import json


def _canonicalize(manifest: dict) -> str:
    """Deterministic JSON encoding of a manifest: sorted keys, no
    whitespace variance. Nested structures (e.g. the parameters list)
    keep their original order — that order is part of the manifest's
    content, only key ordering within objects is normalized."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute(manifest: dict) -> str:
    """Return the SHA-256 hex digest of the canonicalized manifest."""
    canonical = _canonicalize(manifest)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compare(old_hash: str, new_hash: str) -> bool:
    """True if the two fingerprints match (i.e. nothing changed)."""
    return old_hash == new_hash
