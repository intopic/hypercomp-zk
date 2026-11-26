"""Find Citrea DA reveal transactions in given Bitcoin blocks and report their real fees.

Citrea grinds a nonce until the reveal tx WTXID starts with 0x0202 (docs.citrea.xyz/advanced/data-availability).
A random tx matches with p = 1/65536, so ~6-7 unrelated txs per day also match; `citrea_da_cost.py`
filters them by shape (proof reveals > 2 KB, sequencer-commitment reveals 392 B / 674 WU) and the
counts are cross-checked against Citrea's own node (`ledger_*` RPC).
Each reveal's funding commit tx (vin[0]) fee is included.

usage: python -I citrea_bitcoin_txs.py <height> [<height> ...]
"""
import hashlib
import json
import sys
import time
import urllib.request

API = "https://mempool.space/api"


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


def varint(b, i):
    x = b[i]
    if x < 0xFD:
        return x, i + 1
    n = {0xFD: 2, 0xFE: 4, 0xFF: 8}[x]
    return int.from_bytes(b[i + 1:i + 1 + n], "little"), i + 1 + n


def parse_block(b):
    i = 80
    ntx, i = varint(b, i)
    txs = []
    for _ in range(ntx):
        start = i
        i += 4
        segwit = b[i] == 0 and b[i + 1] == 1  # BIP144 marker+flag
        if segwit:
            i += 2
        nin, i = varint(b, i)
        for _ in range(nin):
            i += 36
            l, i = varint(b, i)
            i += l + 4
        nout, i = varint(b, i)
        for _ in range(nout):
            i += 8
            l, i = varint(b, i)
            i += l
        wit_pos = i
        if segwit:
            for _ in range(nin):
                nst, i = varint(b, i)
                for _ in range(nst):
                    l, i = varint(b, i)
                    i += l
        i += 4
        full = b[start:i]
        wtxid = hashlib.sha256(hashlib.sha256(full).digest()).digest()
        if segwit:
            # legacy serialization: version | inputs..outputs (skip marker+flag) | locktime
            body_end = wit_pos
            legacy = full[:4] + full[6:body_end - start] + full[-4:]
        else:
            legacy = full
        txid = hashlib.sha256(hashlib.sha256(legacy).digest()).digest()[::-1].hex()
        txs.append((wtxid, len(full), txid))
    return txs


out = []
for h in map(int, sys.argv[1:]):
    bh = get(f"/block-height/{h}", raw=True).decode()
    raw = get(f"/block/{bh}/raw", raw=True)
    for wtxid, size, txid in parse_block(raw):
        disp = wtxid[::-1].hex()
        if wtxid[:2] == b"\x02\x02" or disp.startswith("0202"):
            t = get(f"/tx/{txid}")
            commit = get(f"/tx/{t['vin'][0]['txid']}")
            out.append({"height": h, "txid": txid, "size": size, "weight": t["weight"], "fee": t["fee"],
                        "commit_txid": commit["txid"], "commit_fee": commit["fee"], "commit_weight": commit["weight"],
                        "feerate_sat_vb": round(t["fee"] / (t["weight"] / 4), 2)})
print(json.dumps(out))
