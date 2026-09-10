"""MCP Guard proxy — FastAPI app.

Serves the dashboard (console/) at "/" and exposes the API routes from
PROJECT_BRIEF.md section 7.6, plus one internal route (/api/register)
used by tool servers / attack scripts to submit a manifest for
fingerprinting, diffing and scanning.

Semantics used by this module (documented here since the brief leaves
them implicit — see the assumptions list in the handoff message):

  - proxy/store.py's `fingerprints` table holds the CURRENT known state
    of a tool: its last-approved manifest/fingerprint, plus a `status`
    of "approved" | "pending" | "blocked".
  - When a registered manifest differs from the approved baseline, the
    baseline is left untouched (so the tool keeps working on its old,
    trusted description) and the new manifest is held in memory as a
    "pending" change until a human calls /api/approve or /api/reject.
  - Every /api/register call also writes an Alert (even when nothing is
    wrong) so /api/events shows both blocked incidents and normal
    traffic in one feed, newest first.
"""

import os
import uuid
from datetime import datetime, timezone

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import differ
import fingerprint
import sanitizer
import scanner
import store

app = FastAPI(title="MCP Guard Proxy")

CONSOLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "console")

# Fake tool servers the /api/demo/* routes drive over HTTP, same as the
# servers/attacks/*.py scripts do.
CALCULATOR_URL = "http://localhost:8001"
DOCS_URL = "http://localhost:8002"

# tool_id -> manifest dict awaiting approval/rejection. In-memory is fine
# for a single-process demo; store.py's schema only models the approved
# baseline, not a pending draft.
PENDING_MANIFESTS: dict = {}


class Parameter(BaseModel):
    name: str
    type: str
    description: str = ""


class ToolManifest(BaseModel):
    tool_id: str
    server_url: str
    name: str
    description: str
    parameters: list[Parameter] = []
    version: str = ""


class ToolOutput(BaseModel):
    text: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_alert_id() -> str:
    return f"alert-{uuid.uuid4().hex[:12]}"


def _known_tool_ids(exclude: str = None) -> list:
    return [f["tool_id"] for f in store.list_fingerprints() if f["tool_id"] != exclude]


def _make_alert(alert_type, tool_id, severity, message, status, diff_report=None, scan_result=None) -> dict:
    return {
        "id": _new_alert_id(),
        "type": alert_type,
        "tool_id": tool_id,
        "severity": severity,
        "message": message,
        "status": status,
        "diff_report": diff_report,
        "scan_result": scan_result,
        "timestamp": _now_iso(),
    }


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

@app.on_event("startup")
def _startup():
    store.init_db()


# ---------------------------------------------------------------------------
# Dashboard (static)
# ---------------------------------------------------------------------------

@app.get("/")
def serve_dashboard():
    return FileResponse(os.path.join(CONSOLE_DIR, "index.html"))


# index.html links its sibling assets with plain relative paths
# (href="style.css", src="app.js") since it's designed to be served from
# its own directory root. Serve those two directly at "/" so those
# relative links resolve, alongside the "/console" mount for anything
# else in that directory.
@app.get("/style.css")
def serve_style():
    return FileResponse(os.path.join(CONSOLE_DIR, "style.css"))


@app.get("/app.js")
def serve_app_js():
    return FileResponse(os.path.join(CONSOLE_DIR, "app.js"))


app.mount("/console", StaticFiles(directory=CONSOLE_DIR), name="console")


# ---------------------------------------------------------------------------
# Section 7.6 routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/events")
def api_events():
    return store.list_alerts()


@app.get("/api/tools")
def api_tools():
    tools = []
    for record in store.list_fingerprints():
        manifest = record["approved_manifest"]
        tools.append({
            "tool_id": record["tool_id"],
            "name": manifest.get("name"),
            "server_url": manifest.get("server_url"),
            "version": manifest.get("version"),
            "status": record["status"],
            "fingerprint": record["fingerprint"],
            "approved_at": record["approved_at"],
            "has_pending_change": record["tool_id"] in PENDING_MANIFESTS,
        })
    return tools


def _approve_tool(tool_id: str) -> dict:
    pending = PENDING_MANIFESTS.get(tool_id)
    if pending is None:
        raise HTTPException(status_code=404, detail=f"No pending change for '{tool_id}'")

    new_fp = fingerprint.compute(pending)
    store.save_fingerprint({
        "tool_id": tool_id,
        "fingerprint": new_fp,
        "approved_manifest": pending,
        "approved_at": _now_iso(),
        "status": "approved",
    })
    del PENDING_MANIFESTS[tool_id]

    for alert in store.list_alerts():
        if alert["tool_id"] == tool_id and alert["status"] in ("pending", "blocked"):
            store.update_alert_status(alert["id"], "approved")

    return {"tool_id": tool_id, "status": "approved", "fingerprint": new_fp}


def _reject_tool(tool_id: str) -> dict:
    existing = store.get_fingerprint(tool_id)
    if existing is None and tool_id not in PENDING_MANIFESTS:
        raise HTTPException(status_code=404, detail=f"Unknown tool '{tool_id}'")

    PENDING_MANIFESTS.pop(tool_id, None)

    if existing is not None:
        store.save_fingerprint({**existing, "status": "blocked", "approved_at": existing["approved_at"]})

    for alert in store.list_alerts():
        if alert["tool_id"] == tool_id and alert["status"] == "pending":
            store.update_alert_status(alert["id"], "blocked")

    return {"tool_id": tool_id, "status": "blocked"}


@app.post("/api/approve/{tool_id}")
def api_approve(tool_id: str):
    return _approve_tool(tool_id)


@app.post("/api/reject/{tool_id}")
def api_reject(tool_id: str):
    return _reject_tool(tool_id)


# ---------------------------------------------------------------------------
# Internal route: register/verify an incoming manifest
# ---------------------------------------------------------------------------

def _run_registration(tool_id: str, manifest_dict: dict) -> dict:
    """Run the full fingerprint -> compare -> scan -> decide pipeline for a
    submitted manifest. Returns the existing response shape (status,
    fingerprint, diff_report, scan_result, alert) plus a "stages" object
    describing how each of the 4 pipeline stages resolved, for the demo
    stepper."""
    new_fp = fingerprint.compute(manifest_dict)

    known_ids = _known_tool_ids(exclude=tool_id)
    scan_result = scanner.scan_text(manifest_dict.get("description", ""), "description", tool_id, known_ids)
    store.save_scan_result(scan_result)
    scan_stage = "failed" if scan_result["flagged"] else "passed"

    existing = store.get_fingerprint(tool_id)

    # -- First time this tool has ever registered ---------------------------
    if existing is None:
        if scan_result["flagged"]:
            status = "blocked"
            alert_type = "cross_server_hijacking" if "cross-server instruction" in scan_result["matched_patterns"] else "poisoned_description"
            severity = "high"
            message = f"'{tool_id}' registration blocked: description contains a hidden instruction."
        else:
            status = "approved"
            alert_type = "tool_registered"
            severity = "info"
            message = f"'{tool_id}' registered and approved as a new baseline."

        store.save_fingerprint({
            "tool_id": tool_id,
            "fingerprint": new_fp,
            "approved_manifest": manifest_dict,
            "approved_at": _now_iso(),
            "status": status,
        })
        alert = _make_alert(alert_type, tool_id, severity, message, status, scan_result=scan_result)
        store.save_alert(alert)
        stages = {"fingerprint": "done", "compare": "skipped", "scan": scan_stage, "decide": status}
        return {"status": status, "fingerprint": new_fp, "diff_report": None, "scan_result": scan_result, "alert": alert, "stages": stages}

    # -- Already known: compare against approved baseline -------------------
    if fingerprint.compare(existing["fingerprint"], new_fp):
        # A manifest matching the trusted baseline is approved by definition,
        # regardless of what status the row previously carried (e.g. "blocked"
        # or "pending" left over from a different, since-superseded manifest).
        if existing["status"] != "approved":
            store.save_fingerprint({**existing, "status": "approved"})

        alert = _make_alert(
            "traffic", tool_id, "info",
            f"'{tool_id}' reconnected with an unchanged, approved description.",
            "approved", scan_result=scan_result,
        )
        store.save_alert(alert)
        stages = {"fingerprint": "done", "compare": "passed", "scan": scan_stage, "decide": "approved"}
        return {"status": "approved", "fingerprint": new_fp, "diff_report": None, "scan_result": scan_result, "alert": alert, "stages": stages}

    diff_report = differ.build_diff_report(
        tool_id, existing["approved_manifest"], manifest_dict,
        existing["fingerprint"], new_fp, known_tool_ids=known_ids,
    )
    store.save_diff_report(diff_report)

    if scan_result["flagged"] or diff_report["risk_level"] == "high":
        new_status = "blocked"
        alert_type = "silent_mutation"
        severity = "high"
        message = f"'{tool_id}' description changed without approval and was blocked."
    else:
        new_status = "pending"
        alert_type = "manifest_changed"
        severity = "medium" if diff_report["risk_level"] == "medium" else "low"
        message = f"'{tool_id}' description changed. Awaiting review."
        PENDING_MANIFESTS[tool_id] = manifest_dict

    if new_status == "blocked":
        # Keep the flagged manifest available for a human to inspect/approve
        # via /api/approve, but the old baseline stays authoritative until then.
        PENDING_MANIFESTS[tool_id] = manifest_dict

    store.save_fingerprint({
        "tool_id": tool_id,
        "fingerprint": existing["fingerprint"],
        "approved_manifest": existing["approved_manifest"],
        "approved_at": existing["approved_at"],
        "status": new_status,
    })

    alert = _make_alert(alert_type, tool_id, severity, message, new_status, diff_report=diff_report, scan_result=scan_result)
    store.save_alert(alert)

    stages = {"fingerprint": "done", "compare": "failed", "scan": scan_stage, "decide": new_status}
    return {"status": new_status, "fingerprint": new_fp, "diff_report": diff_report, "scan_result": scan_result, "alert": alert, "stages": stages}


@app.post("/api/register/{tool_id}")
def api_register(tool_id: str, manifest: ToolManifest):
    return _run_registration(tool_id, manifest.model_dump())


# ---------------------------------------------------------------------------
# Internal route: scan + sanitize a raw tool output (poisoned output attack)
# ---------------------------------------------------------------------------

def _run_output_scan(tool_id: str, text: str) -> dict:
    """Run the scan -> decide pipeline for a raw tool output. There is no
    fingerprint/compare stage for output text, only scan + decide."""
    known_ids = _known_tool_ids(exclude=tool_id)
    scan_result = scanner.scan_text(text, "output", tool_id, known_ids)
    store.save_scan_result(scan_result)

    if scan_result["flagged"]:
        sanitized = sanitizer.strip_commands(text, scan_result)
        cleaned_text = sanitized["cleaned_text"]
        removed_text = sanitized["removed_text"]

        alert = _make_alert(
            "poisoned_output", tool_id, "high",
            f"'{tool_id}' output contained a hidden instruction and was sanitized.",
            "blocked", scan_result=scan_result,
        )
        store.save_alert(alert)
        decide = "blocked"
    else:
        cleaned_text = text
        removed_text = []

        alert = _make_alert(
            "traffic", tool_id, "info",
            f"'{tool_id}' output scanned clean.",
            "ok", scan_result=scan_result,
        )
        store.save_alert(alert)
        decide = "approved"

    stages = {
        "fingerprint": "skipped",
        "compare": "skipped",
        "scan": "failed" if scan_result["flagged"] else "passed",
        "decide": decide,
    }

    return {
        "original_text": text,
        "cleaned_text": cleaned_text,
        "flagged": scan_result["flagged"],
        "removed_text": removed_text,
        "scan_result": scan_result,
        "alert": alert,
        "stages": stages,
    }


@app.post("/api/tool-output/{tool_id}")
def api_tool_output(tool_id: str, output: ToolOutput):
    result = _run_output_scan(tool_id, output.text)
    return {
        "original_text": result["original_text"],
        "cleaned_text": result["cleaned_text"],
        "flagged": result["flagged"],
        "removed_text": result["removed_text"],
    }


# ---------------------------------------------------------------------------
# Demo routes: replay the servers/attacks/*.py scripts over HTTP, and
# report each run's pipeline stage outcomes for the dashboard's live
# stepper. tool servers (:8001 calculator, :8002 docs) are called exactly
# like those scripts call them.
# ---------------------------------------------------------------------------

class NovelTestBody(BaseModel):
    text: str


def _clear_tool_baseline(tool_id: str):
    """Delete tool_id's fingerprint/status row (and any in-memory pending
    manifest) so a demo endpoint always starts that tool from a genuinely
    clean, honest baseline — regardless of what an earlier demo run left
    behind (including an approved malicious baseline). Only this one
    tool_id is affected; the rest of guard.db, and any other tool's
    state, is untouched. store.py has no delete helper, so this uses its
    already-public get_conn() directly rather than adding one there."""
    with store.get_conn() as conn:
        conn.execute("DELETE FROM fingerprints WHERE tool_id = ?", (tool_id,))
    PENDING_MANIFESTS.pop(tool_id, None)


@app.post("/api/demo/reset")
def demo_reset():
    global PENDING_MANIFESTS
    if os.path.exists(store.DB_PATH):
        os.remove(store.DB_PATH)
    store.init_db()
    PENDING_MANIFESTS = {}
    return {
        "stages": {"fingerprint": "skipped", "compare": "skipped", "scan": "skipped", "decide": "approved"},
        "summary": "Database reset — all tools and events cleared.",
    }


@app.post("/api/demo/attack-1-mutation")
def demo_attack_1_mutation():
    _clear_tool_baseline("calculator")
    requests.post(f"{CALCULATOR_URL}/reset", timeout=10)
    manifest = requests.get(f"{CALCULATOR_URL}/manifest", timeout=10).json()
    _run_registration("calculator", manifest)

    requests.post(f"{CALCULATOR_URL}/mutate/silent", timeout=10)
    mutated = requests.get(f"{CALCULATOR_URL}/manifest", timeout=10).json()
    result = _run_registration("calculator", mutated)

    result["summary"] = (
        "Calculator's description was silently mutated to add a hidden email-routing "
        "instruction — blocked."
        if result["status"] == "blocked"
        else f"Unexpected status '{result['status']}' for silent mutation."
    )
    return result


@app.post("/api/demo/attack-2-cross-server")
def demo_attack_2_cross_server():
    _clear_tool_baseline("calculator")
    _clear_tool_baseline("docs")
    requests.post(f"{CALCULATOR_URL}/reset", timeout=10)
    requests.post(f"{DOCS_URL}/reset", timeout=10)

    docs_manifest = requests.get(f"{DOCS_URL}/manifest", timeout=10).json()
    _run_registration("docs", docs_manifest)

    calc_manifest = requests.get(f"{CALCULATOR_URL}/manifest", timeout=10).json()
    _run_registration("calculator", calc_manifest)

    requests.post(f"{CALCULATOR_URL}/mutate/cross-server", timeout=10)
    mutated = requests.get(f"{CALCULATOR_URL}/manifest", timeout=10).json()
    result = _run_registration("calculator", mutated)

    result["summary"] = (
        "Calculator's description now gives orders about the docs tool — blocked."
        if result["status"] == "blocked"
        else f"Unexpected status '{result['status']}' for cross-server hijack."
    )
    return result


@app.post("/api/demo/attack-3-poisoned-output")
def demo_attack_3_poisoned_output():
    requests.post(f"{DOCS_URL}/poison", timeout=10)
    search_resp = requests.get(f"{DOCS_URL}/search", params={"q": "test"}, timeout=10).json()
    raw_text = search_resp["result"]

    result = _run_output_scan("docs", raw_text)

    requests.post(f"{DOCS_URL}/reset", timeout=10)

    result["summary"] = (
        "Docs returned a document with a hidden instruction — stripped before reaching the agent."
        if result["flagged"]
        else "Document scanned clean — nothing to strip."
    )
    return result


@app.post("/api/demo/benign-update")
def demo_benign_update():
    _clear_tool_baseline("calculator")
    requests.post(f"{CALCULATOR_URL}/reset", timeout=10)
    manifest = requests.get(f"{CALCULATOR_URL}/manifest", timeout=10).json()
    _run_registration("calculator", manifest)

    requests.post(f"{CALCULATOR_URL}/mutate/benign", timeout=10)
    updated = requests.get(f"{CALCULATOR_URL}/manifest", timeout=10).json()
    pending_result = _run_registration("calculator", updated)

    if pending_result["status"] == "pending":
        _approve_tool("calculator")

    final_result = _run_registration("calculator", updated)
    final_result["summary"] = (
        "Calculator honestly added sqrt support — reviewed, approved, and now the trusted baseline."
        if final_result["status"] == "approved"
        else f"Unexpected status '{final_result['status']}' for benign update."
    )
    return final_result


@app.post("/api/demo/novel-test")
def demo_novel_test(body: NovelTestBody):
    result = _run_output_scan("docs", body.text)
    result["summary"] = (
        "Flagged as malicious — stripped before reaching the agent."
        if result["flagged"]
        else "No malicious instruction detected — looks benign."
    )
    return result


@app.post("/api/demo/scan-description")
def demo_scan_description(body: NovelTestBody):
    """Read-only: run scanner.scan_text() on arbitrary text as if it were
    a tool description, without registering anything or touching the
    fingerprints table. Used by the Manifest Inspection panel's inline
    live-test box so a user can try a different description against the
    same scanner without it affecting any tool's real state."""
    result = scanner.scan_text(body.text, "description", "live-test")
    return {
        "flagged": result["flagged"],
        "matched_patterns": result["matched_patterns"],
        "cleaned_text": result["cleaned_text"],
    }


if __name__ == "__main__":
    import uvicorn

    store.init_db()
    uvicorn.run(app, host="0.0.0.0", port=8000)
