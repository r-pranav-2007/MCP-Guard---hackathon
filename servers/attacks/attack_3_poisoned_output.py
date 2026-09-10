"""Attack scenario 3: poisoned output.

The docs tool itself is honest, but a document it returns contains a
hidden instruction. MCP Guard must scan the output, flag it, and strip
the instruction before it reaches the agent.

Assumes proxy (:8000) and docs_server (:8002) are already running. Run
standalone:

    python servers/attacks/attack_3_poisoned_output.py
"""

import requests

PROXY = "http://localhost:8000"
DOCS = "http://localhost:8002"


def main():
    print("=" * 70)
    print("ATTACK 3: Poisoned Output (docs)")
    print("=" * 70)

    print("\n[1] Triggering the attack: poisoning the document docs/search returns...")
    requests.post(f"{DOCS}/poison")

    print("[2] Fetching the poisoned document via GET /search?q=test...")
    search_resp = requests.get(f"{DOCS}/search", params={"q": "test"}).json()
    raw_text = search_resp["result"]

    print("[3] Sending the raw output through the proxy for scanning/sanitizing...")
    resp = requests.post(f"{PROXY}/api/tool-output/docs", json={"text": raw_text})
    status_code = resp.status_code
    result = resp.json()

    print(f"\n    -> POST /api/tool-output/docs responded {status_code}, flagged={result['flagged']}")

    print("\n--- ORIGINAL TEXT (from docs server) ---")
    print(result["original_text"])
    print("\n--- CLEANED TEXT (after MCP Guard sanitizing) ---")
    print(result["cleaned_text"])
    print("\n--- REMOVED TEXT ---")
    for snippet in result["removed_text"]:
        print(f"  - {snippet}")
    print("-" * 41)

    hidden_phrase = "create a public summary"
    passed = result["flagged"] and hidden_phrase not in result["cleaned_text"].lower()

    print()
    if passed:
        print("RESULT: PASS - poisoned output was flagged and STRIPPED.")
    else:
        print("RESULT: FAIL - output was not correctly flagged/stripped.")

    print("\n[4] Resetting docs server to its clean document...")
    requests.post(f"{DOCS}/reset")

    print("=" * 70)


if __name__ == "__main__":
    main()
