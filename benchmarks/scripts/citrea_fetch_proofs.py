"""Download Citrea batch proofs and sequencer commitments for a range of Bitcoin heights from a Citrea node.

usage: python -I citrea_fetch_proofs.py <num_btc_blocks> <out.json> [rpc]
Uses `ledger_getVerifiedBatchProofsBySlotHeight` / `ledger_getSequencerCommitmentsOnSlotByNumber`.
"""
import json
import sys
import time
import urllib.request

n, dst = int(sys.argv[1]), sys.argv[2]
R = sys.argv[3] if len(sys.argv) > 3 else "https://rpc.mainnet.citrea.xyz"


def rpc(m, p):
    for a in range(5):
        try:
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode()
            req = urllib.request.Request(R, body, {"Content-Type": "application/json", "User-Agent": "research-script"})
            d = json.load(urllib.request.urlopen(req, timeout=60))
            if "error" not in d:
                return d.get("result")
            err = d
        except Exception as e:  # noqa: BLE001
            err = e
        time.sleep(1.5 * (a + 1))
    raise RuntimeError(err)


top = int(rpc("ledger_getLastScannedL1Height", []), 16)
proofs, comms = {}, {}
for h in range(top - n + 1, top + 1):
    p = rpc("ledger_getVerifiedBatchProofsBySlotHeight", [hex(h)])
    c = rpc("ledger_getSequencerCommitmentsOnSlotByNumber", [hex(h)])
    if p:
        proofs[h] = p
    if c:
        comms[h] = c
json.dump({"top": top, "proofs": proofs, "comms": comms}, open(dst, "w"))
print(f"btc heights {top - n + 1}..{top}: {sum(map(len, proofs.values()))} proofs, {sum(map(len, comms.values()))} commitments")
