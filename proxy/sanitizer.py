"""Output sanitizing for MCP Guard.

strip_commands() removes whatever scanner.py flagged (its matched_patterns
/ removed_text) from a piece of text, so a poisoned tool output never
reaches the agent with its embedded instruction intact.

This module does not re-implement detection — it trusts a Scan Result
(section 7.4) produced by scanner.scan_text() and just does the stripping,
so scanning and sanitizing stay separate concerns.
"""

import re


def strip_commands(text: str, scan_result: dict) -> dict:
    """Remove every sentence/snippet in scan_result['removed_text'] from
    `text`. Returns {"cleaned_text": str, "removed_text": list[str]}.

    If scan_result already carries a cleaned_text (scanner.py computes
    one too), that value is preferred since it was derived from the same
    removed_text list against the same original text.
    """
    removed = scan_result.get("removed_text", []) if scan_result else []

    if not scan_result or not scan_result.get("flagged") or not removed:
        return {"cleaned_text": text or "", "removed_text": []}

    if scan_result.get("cleaned_text") is not None:
        return {"cleaned_text": scan_result["cleaned_text"], "removed_text": removed}

    cleaned = text or ""
    for snippet in removed:
        cleaned = cleaned.replace(snippet, "")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    return {"cleaned_text": cleaned, "removed_text": removed}
