"""Runs all four MCP Guard demo scenarios end-to-end and prints a final
PASS/FAIL summary (PROJECT_BRIEF.md section 8).

Assumes proxy (:8000), calculator_server (:8001) and docs_server (:8002)
are already running — this script only makes HTTP calls to them, it does
not start any service itself.

Each scenario is one of the standalone scripts in servers/attacks/. They
are imported and run in-process (not as subprocesses) so their own
print() output — which already shows the diff_text / cleaned_text
evidence for that scenario — streams straight to this terminal, in
order, before the final summary block. A scenario raising an exception
(e.g. a service isn't reachable) is caught so the remaining scenarios
still run.

Run standalone:

    python scenarios/run_scenarios.py
"""

import contextlib
import importlib.util
import io
import os
import sys

# Windows terminals often default stdout to a non-UTF-8 codepage (e.g.
# cp1252), which can't encode the checkmark/cross characters used in the
# summary below. Force UTF-8 where possible so the demo output doesn't
# crash mid-run; if the stream can't be reconfigured, leave it as-is.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACKS_DIR = os.path.join(REPO_ROOT, "servers", "attacks")
PROXY_DIR = os.path.join(REPO_ROOT, "proxy")
DB_PATH = os.path.join(REPO_ROOT, "guard.db")

# proxy/store.py has no reset() of its own, so we delete guard.db directly
# and re-run its init_db() to recreate empty tables at the same path. The
# running proxy process opens a fresh sqlite3 connection per request
# (see store.get_conn()) rather than holding one open, so it picks up the
# recreated file/tables on its very next call without needing a restart.
sys.path.insert(0, PROXY_DIR)
import store  # noqa: E402  (import after sys.path setup, by necessity)

# (module filename without .py, summary label, expected-outcome word(s))
SCENARIOS = [
    ("attack_1_mutation", "[1] Silent mutation", "BLOCKED"),
    ("attack_2_cross_server", "[2] Cross-server hijacking", "BLOCKED"),
    ("attack_3_poisoned_output", "[3] Poisoned output", "STRIPPED"),
    ("benign_update", "[4] Legitimate benign update", "RE-APPROVED, WORKING"),
]

PASS_MARKER = "RESULT: PASS"
CHECK = "✅"
CROSS = "❌ FAILED"


def _reset_database():
    """Delete guard.db (if present) and recreate empty tables, so every
    full run of this script starts from a completely clean state."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"[reset] Deleted existing database: {DB_PATH}")
    else:
        print(f"[reset] No existing database found at {DB_PATH} (already clean)")
    store.init_db()
    print("[reset] Fresh guard.db initialized. Starting all scenarios from a clean baseline.")


def _load_module(module_name: str):
    path = os.path.join(ATTACKS_DIR, f"{module_name}.py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_scenario(module_name: str) -> bool:
    """Import + run one attack script's main(), echoing its stdout live
    (this is the diff_text / cleaned_text evidence for that scenario).
    Returns True if that script reported RESULT: PASS."""
    buf = io.StringIO()
    try:
        module = _load_module(module_name)
        with contextlib.redirect_stdout(buf):
            module.main()
        output = buf.getvalue()
        print(output, end="")
        return PASS_MARKER in output
    except Exception as exc:
        print(buf.getvalue(), end="")
        print(f"\n!!! Scenario '{module_name}' raised an exception: {exc}")
        return False


def _print_summary_line(label: str, expected: str, passed: bool):
    mark = CHECK if passed else CROSS
    status_field = f"{expected:<9}" if len(expected) <= 9 else f"{expected} "
    print(f"{label:<36}{status_field}{mark}")


def main():
    print("=" * 70)
    print("RESETTING DATABASE")
    print("=" * 70)
    _reset_database()

    results = []

    for module_name, label, expected in SCENARIOS:
        print("\n" + "#" * 70)
        print(f"# Running {module_name}")
        print("#" * 70 + "\n")
        passed = _run_scenario(module_name)
        results.append((label, expected, passed))

    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    for label, expected, passed in results:
        _print_summary_line(label, expected, passed)
    print("=" * 70)


if __name__ == "__main__":
    main()
