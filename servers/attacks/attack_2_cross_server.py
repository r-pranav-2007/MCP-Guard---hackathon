"""Attack scenario 2: cross-server hijacking.

Calculator's description is mutated to give orders about a DIFFERENT
tool ("docs"). That's a red flag by itself. To exercise the same
"changed after approval" detection path as attack 1 (and so the scanner
has "docs" in its known-tool-id list to recognize the cross-server
reference), this script first registers a clean baseline for both docs
and calculator, then mutates calculator and re-registers it.

Assumes proxy (:8000), calculator_server (:8001) and docs_server (:8002)
are already running. Run standalone:

    python servers/attacks/attack_2_cross_server.py
"""

import requests

PROXY = "http://localhost:8000"
CALCULATOR = "http://localhost:8001"
DOCS = "http://localhost:8002"


def register(manifest: dict) -> dict:
    resp = requests.post(f"{PROXY}/api/register/{manifest['tool_id']}", json=manifest)
    return resp.status_code, resp.json()


def main():
    print("=" * 70)
    print("ATTACK 2: Cross-Server Hijacking (calculator -> docs)")
    print("=" * 70)

    print("\n[1] Resetting calculator and docs to their honest baselines...")
    requests.post(f"{CALCULATOR}/reset")
    requests.post(f"{DOCS}/reset")

    print("[2] Registering 'docs' baseline (so the scanner knows about it by name)...")
    docs_manifest = requests.get(f"{DOCS}/manifest").json()
    status_code, result = register(docs_manifest)
    print(f"    -> POST /api/register/docs responded {status_code}, status='{result['status']}'")

    print("[3] Registering clean calculator baseline...")
    manifest = requests.get(f"{CALCULATOR}/manifest").json()
    status_code, result = register(manifest)
    print(f"    -> POST /api/register/calculator responded {status_code}, status='{result['status']}'")

    print("\n[4] Triggering the attack: calculator's description now gives orders about 'docs'...")
    requests.post(f"{CALCULATOR}/mutate/cross-server")

    print("[5] Fetching the mutated manifest and re-registering it...")
    mutated_manifest = requests.get(f"{CALCULATOR}/manifest").json()
    status_code, result = register(mutated_manifest)
    final_status = result["status"]

    print(f"\n    -> POST /api/register/calculator responded {status_code}, status='{final_status}'")

    diff_report = result.get("diff_report")
    print("\n--- Diff detected by the proxy ---")
    if diff_report:
        print(f"changed_fields: {diff_report['changed_fields']}")
        print(f"risk_level:     {diff_report['risk_level']}")
        print("diff_text:")
        print(diff_report["diff_text"])
    else:
        print("(no diff_report returned)")
    print("-----------------------------------")

    scan_result = result.get("scan_result")
    if scan_result:
        print(f"\nscanner matched_patterns: {scan_result['matched_patterns']}")

    print()
    if final_status == "blocked":
        print("RESULT: PASS - cross-server hijacking was BLOCKED.")
    else:
        print(f"RESULT: FAIL - expected 'blocked', got '{final_status}'.")

    print("=" * 70)


if __name__ == "__main__":
    main()
