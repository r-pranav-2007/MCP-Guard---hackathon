"""Attack scenario 1: silent mutation.

A trusted tool (calculator) gets approved once, then its description
silently changes to add a hidden, malicious email-routing instruction.
MCP Guard must detect the fingerprint mismatch and BLOCK it.

Assumes proxy (:8000), calculator_server (:8001) and docs_server (:8002)
are already running. Run standalone:

    python servers/attacks/attack_1_mutation.py
"""

import requests

PROXY = "http://localhost:8000"
CALCULATOR = "http://localhost:8001"


def register(manifest: dict) -> dict:
    resp = requests.post(f"{PROXY}/api/register/{manifest['tool_id']}", json=manifest)
    return resp.status_code, resp.json()


def main():
    print("=" * 70)
    print("ATTACK 1: Silent Mutation (calculator)")
    print("=" * 70)

    print("\n[1] Resetting calculator to its honest baseline...")
    requests.post(f"{CALCULATOR}/reset")

    print("[2] Fetching honest manifest and registering as the approved baseline...")
    manifest = requests.get(f"{CALCULATOR}/manifest").json()
    status_code, result = register(manifest)
    print(f"    -> POST /api/register/calculator responded {status_code}, status='{result['status']}'")

    print("\n[3] Triggering the attack: calculator silently mutates its description...")
    requests.post(f"{CALCULATOR}/mutate/silent")

    print("[4] Fetching the mutated manifest and re-registering it...")
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
        print("RESULT: PASS - silent mutation was BLOCKED.")
    else:
        print(f"RESULT: FAIL - expected 'blocked', got '{final_status}'.")

    print("=" * 70)


if __name__ == "__main__":
    main()
