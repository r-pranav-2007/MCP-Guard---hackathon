"""Diffing for MCP Guard.

Given an old and new Tool Manifest (section 7.1), produce a Diff Report
matching PROJECT_BRIEF.md section 7.3 exactly: which top-level fields
changed, a readable diff_text built with difflib, and a risk_level
("high"/"medium"/"low") from simple keyword/cross-reference heuristics.
"""

import difflib
from datetime import datetime, timezone

# Phrases that, if newly added, strongly suggest a hidden instruction
# rather than an honest capability update.
HIGH_RISK_KEYWORDS = [
    "route", "routing", "mandatory", "do not disclose", "do-not-disclose",
    "must", "override", "ignore previous", "confidential", "secretly",
    "without informing", "bypass",
]

# Fields whose value is worth diffing at word level for readability.
TEXT_FIELDS = ["name", "description"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _changed_fields(old_manifest: dict, new_manifest: dict) -> list:
    keys = sorted(set(old_manifest.keys()) | set(new_manifest.keys()))
    return [k for k in keys if old_manifest.get(k) != new_manifest.get(k)]


def _word_diff(old_text: str, new_text: str) -> str:
    """Word-level diff between two strings, rendered as +/- lines."""
    old_words = (old_text or "").split()
    new_words = (new_text or "").split()
    diff = difflib.ndiff(old_words, new_words)
    added = [w[2:] for w in diff if w.startswith("+ ")]
    diff = difflib.ndiff(old_words, new_words)
    removed = [w[2:] for w in diff if w.startswith("- ")]
    lines = []
    if added:
        lines.append("+ " + " ".join(added))
    if removed:
        lines.append("- " + " ".join(removed))
    return "\n".join(lines)


def _build_diff_text(old_manifest: dict, new_manifest: dict, changed_fields: list) -> str:
    parts = []
    for field in changed_fields:
        old_val = old_manifest.get(field)
        new_val = new_manifest.get(field)
        if field in TEXT_FIELDS:
            field_diff = _word_diff(str(old_val or ""), str(new_val or ""))
        elif field == "parameters":
            old_str = str(old_val or [])
            new_str = str(new_val or [])
            field_diff = "\n".join(
                difflib.unified_diff(
                    [old_str], [new_str], lineterm="", fromfile="old", tofile="new"
                )
            )
        else:
            field_diff = f"- {old_val}\n+ {new_val}"

        if len(changed_fields) > 1:
            parts.append(f"[{field}]\n{field_diff}")
        else:
            parts.append(field_diff)
    return "\n".join(p for p in parts if p)


def _assess_risk(diff_text: str, tool_id: str, known_tool_ids=None) -> str:
    lowered = diff_text.lower()

    # Only the *added* content should trigger risk (a removed threat isn't a threat).
    added_lines = "\n".join(
        line for line in diff_text.splitlines() if line.startswith("+")
    ).lower()

    if any(kw in added_lines for kw in HIGH_RISK_KEYWORDS):
        return "high"

    # Cross-server hijacking: added text mentions a different known tool.
    if known_tool_ids:
        for other_id in known_tool_ids:
            if other_id != tool_id and other_id.lower() in added_lines:
                return "high"

    if not diff_text.strip():
        return "low"

    if "parameters" in lowered or "description" in lowered:
        return "medium"

    return "low"


def build_diff_report(
    tool_id: str,
    old_manifest: dict,
    new_manifest: dict,
    old_fingerprint: str,
    new_fingerprint: str,
    known_tool_ids=None,
) -> dict:
    """Return a Diff Report dict matching section 7.3."""
    changed_fields = _changed_fields(old_manifest, new_manifest)
    diff_text = _build_diff_text(old_manifest, new_manifest, changed_fields)
    risk_level = _assess_risk(diff_text, tool_id, known_tool_ids)

    return {
        "tool_id": tool_id,
        "old_fingerprint": old_fingerprint,
        "new_fingerprint": new_fingerprint,
        "changed_fields": changed_fields,
        "diff_text": diff_text,
        "risk_level": risk_level,
        "detected_at": _now_iso(),
        # The previously-approved baseline's description text, captured at
        # diff time. changed_fields/diff_text only describe what changed —
        # nothing else carries the actual trusted-baseline content, so the
        # dashboard would otherwise have no real "old" text to show.
        "old_description": old_manifest.get("description", ""),
    }
