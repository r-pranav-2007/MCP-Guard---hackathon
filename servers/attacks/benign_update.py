"""Scenario 4: benign, legitimate update.

Calculator honestly adds a new "sqrt" capability. MCP Guard must show the
diff as "pending" (not auto-block it), and once a human approves it via
/api/approve, it becomes the new trusted baseline and future
registrations with the same manifest come back "approved".

Assumes proxy (:8000) and calculator_server (:8001) are already running.
Run standalone:

    python servers/attacks/benign_update.py
"""

import requests

PROXY = "http://localhost:8000"
CALCULATOR = "http://localhost:8001"


def register(manifest: dict) -> dict:
    resp = requests.post(f"{PROXY}/api/register/{manifest['tool_id']}", json=manifest)
    return resp.status_code, resp.json()


def main():
    print("=" * 70)
    print("SCENARIO 4: Benign Legitimate Update (calculator)")
    print("=" * 70)

    print("\n[1] Resetting calculator to its honest baseline...")
    requests.post(f"{CALCULATOR}/reset")

    print("[2] Registering the clean baseline...")
    manifest = requests.get(f"{CALCULATOR}/manifest").json()
    status_code, result = register(manifest)
    print(f"    -> POST /api/register/calculator responded {status_code}, status='{result['status']}'")

    print("\n[3] Calculator honestly adds a real 'sqrt' operation...")
    requests.post(f"{CALCULATOR}/mutate/benign")

    print("[4] Registering the updated manifest...")
    updated_manifest = requests.get(f"{CALCULATOR}/manifest").json()
    status_code, result = register(updated_manifest)
    pending_status = result["status"]
    print(f"\n    -> POST /api/register/calculator responded {status_code}, status='{pending_status}'")
    print(f"    -> expected 'pending': {'OK' if pending_status == 'pending' else 'MISMATCH'}")

    diff_report = result.get("diff_report")
    if diff_report:
        print("\n--- Diff detected by the proxy ---")
        print(f"changed_fields: {diff_report['changed_fields']}")
        print(f"risk_level:     {diff_report['risk_level']}")
        print("diff_text:")
        print(diff_report["diff_text"])
        print("-----------------------------------")

    print("\n[5] A human reviews the diff and approves it...")
    approve_resp = requests.post(f"{PROXY}/api/approve/calculator")
    approve_result = approve_resp.json()
    print(f"    -> POST /api/approve/calculator responded {approve_resp.status_code}, status='{approve_result['status']}'")

    print("\n[6] Registering the same manifest again to confirm it's now the trusted baseline...")
    status_code, result = register(updated_manifest)
    final_status = result["status"]
    print(f"    -> POST /api/register/calculator responded {status_code}, status='{final_status}'")

    tools = requests.get(f"{PROXY}/api/tools").json()
    calculator_entry = next((t for t in tools if t["tool_id"] == "calculator"), None)
    print("\n--- Current /api/tools entry for calculator ---")
    if calculator_entry:
        print(f"status:  {calculator_entry['status']}")
        print(f"version: {calculator_entry['version']}")
    print("------------------------------------------------")

    baseline_has_sqrt = any(p.get("name") == "operation" for p in updated_manifest["parameters"])

    print()
    if pending_status == "pending" and final_status == "approved" and baseline_has_sqrt:
        print("RESULT: PASS - benign update went pending -> approved, sqrt is now the baseline.")
    else:
        print(
            "RESULT: FAIL - expected pending -> approved with sqrt baseline, "
            f"got pending_status='{pending_status}', final_status='{final_status}'."
        )

    print("=" * 70)


if __name__ == "__main__":
    main()
