"""Find Alpen EE DA commit txs (OP_RETURN containing magic b"ALPN") in recent Bitcoin Signet blocks.

usage: python -I alpen_signet_scan.py <num_blocks> <out.json> [<last_height>]
"""
import json
import sys
import time
import urllib.request

API = "https://mempool.space/signet/api"
MAGIC = b"ALPN"


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


def scan(b):
    i = 80
    ntx, i = varint(b, i)
    hits = []
    for idx in range(ntx):
        i += 4
        segwit = b[i] == 0 and b[i + 1] == 1
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
            spk = b[i:i + l]
            i += l
            if spk[:1] == b"\x6a" and MAGIC in spk:
                hits.append((idx, spk.hex()))
        if segwit:
            for _ in range(nin):
                nst, i = varint(b, i)
                for _ in range(nst):
                    l, i = varint(b, i)
                    i += l
        i += 4
    return hits


n, dst = int(sys.argv[1]), sys.argv[2]
tip = int(sys.argv[3]) if len(sys.argv) > 3 else int(get("/blocks/tip/height", raw=True))
out = []
for h in range(tip - n + 1, tip + 1):
    bh = get(f"/block-height/{h}", raw=True).decode()
    for idx, spk in scan(get(f"/block/{bh}/raw", raw=True)):
        txid = get(f"/block/{bh}/txid/{idx}", raw=True).decode()
        out.append({"height": h, "txid": txid, "op_return": spk})
json.dump({"tip": tip, "scanned": n, "commits": out}, open(dst, "w"), indent=1)
print(f"signet {tip - n + 1}..{tip}: {len(out)} ALPN commit txs")
