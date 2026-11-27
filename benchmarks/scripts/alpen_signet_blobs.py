"""Reassemble Alpen EE DA blobs from Signet: commit tx (OP_RETURN "ALPN"+u32 version) -> reveal txs
spending its outputs -> taproot envelope pushes in the reveal witness, concatenated in output order.

usage: python -I alpen_signet_blobs.py <scan.json> <out_dir>
"""
import json
import os
import sys
import time
import urllib.request

API = "https://mempool.space/signet/api"


def get(path, raw=False):
    for a in range(6):
        try:
            with urllib.request.urlopen(urllib.request.Request(API + path, headers={"User-Agent": "research-script"}), timeout=90) as r:
                b = r.read()
            return b if raw else json.loads(b)
        except Exception as e:  # noqa: BLE001
            err = e
            time.sleep(2 * (a + 1))
    raise RuntimeError(f"{path}: {err}")


def envelope_payload(script: bytes) -> bytes:
    """Concatenate data pushes between OP_FALSE OP_IF ... OP_ENDIF (skip the first push = tag if any)."""
    i, out, inside = 0, [], False
    while i < len(script):
        op = script[i]
        i += 1
        if op == 0x00 and i < len(script) and script[i] == 0x63:  # OP_FALSE OP_IF
            inside, i = True, i + 1
            continue
        if op == 0x68:  # OP_ENDIF
            inside = False
            continue
        if 1 <= op <= 75:
            n = op
        elif op == 0x4C:
            n, i = script[i], i + 1
        elif op == 0x4D:
            n, i = int.from_bytes(script[i:i + 2], "little"), i + 2
        elif op == 0x4E:
            n, i = int.from_bytes(script[i:i + 4], "little"), i + 4
        else:
            continue
        data = script[i:i + n]
        i += n
        if inside:
            out.append(data)
    return b"".join(out)


scan, dst = json.load(open(sys.argv[1])), sys.argv[2]
os.makedirs(dst, exist_ok=True)
summary = []
for c in scan["commits"]:
    if not c["op_return"].startswith("6a08414c504e"):  # EE DA commit: magic + u32 version
        continue
    tx = get(f"/tx/{c['txid']}")
    spends = get(f"/tx/{c['txid']}/outspends")
    chunks, fee, vsize = [], tx["fee"], tx["weight"] / 4
    for vout, sp in enumerate(spends):
        if not sp.get("spent") or tx["vout"][vout]["scriptpubkey_type"] != "v1_p2tr":
            continue
        rv = get(f"/tx/{sp['txid']}")
        wit = rv["vin"][sp["vin"]]["witness"]
        script = bytes.fromhex(wit[-2])  # tapscript is the second-to-last witness element
        chunks.append(envelope_payload(script))
        fee += rv["fee"]
        vsize += rv["weight"] / 4
    blob = b"".join(chunks)
    name = f"{c['height']}_{c['txid'][:12]}.bin"
    open(os.path.join(dst, name), "wb").write(blob)
    summary.append({"height": c["height"], "commit_txid": c["txid"], "version": int(c["op_return"][12:20], 16),
                    "reveal_txs": len(chunks), "blob_bytes": len(blob), "total_fee_sat": fee, "total_vbytes": round(vsize, 1), "file": name})
json.dump(summary, open(os.path.join(dst, "summary.json"), "w"), indent=1)
print(json.dumps(summary, indent=1))
