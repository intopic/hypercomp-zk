"""Per-rollup Ethereum DA profile from Blobscan windows (one JSON per rollup from blobscan_window.py).

usage: python -I rollup_da_profile.py <dir_with_rollup_jsons> <eth_usd_by_day.txt> <l2_blocks_per_day.json> <out.json>
eth_usd_by_day.txt: lines "<day-of-month> <usd>"; l2_blocks_per_day.json: {"base": 432000, ...}
"""
import collections
import json
import os
import sys

src, prices, l2f, dst = sys.argv[1:5]
px = {int(a): float(b) for a, b in (line.split() for line in open(prices) if line.strip())}
l2 = json.load(open(l2f))
out = {}
for f in sorted(os.listdir(src)):
    if not f.endswith(".json"):
        continue
    r = f[:-5]
    d = json.load(open(os.path.join(src, f)))
    day = collections.defaultdict(lambda: [0, 0, 0.0, 0.0])
    for t in d["transactions"]:
        k = int(t["blockTimestamp"][8:10])
        day[k][0] += 1
        day[k][1] += len(t["blobs"])
        day[k][2] += int(t["blobGasBaseFee"]) / 1e18 * px[k]
        day[k][3] += int(t["executionFee"]) / 1e18 * px[k]
    use = sum(b["usageSize"] for b in d["blobs"])
    cap = sum(b["size"] for b in d["blobs"])
    n = len(day)
    tx = sum(v[0] for v in day.values()) / n
    out[r] = {
        "days": n, "window": [d["start"], d["end"]],
        "posting_txs_per_day": tx,
        "blobs_per_day": sum(v[1] for v in day.values()) / n,
        "blob_fill_pct": use / cap * 100,
        "posted_mb_per_day": use / 1e6 / n,
        "blob_fee_usd_per_day": {"mean": sum(v[2] for v in day.values()) / n,
                                 "min": min(v[2] for v in day.values()), "max": max(v[2] for v in day.values())},
        "execution_fee_usd_per_day": sum(v[3] for v in day.values()) / n,
        "l2_blocks_per_day": l2.get(r),
        "l2_blocks_per_posting_tx": (l2[r] / tx) if r in l2 else None,
        "posted_bytes_per_l2_block": (use / n / l2[r]) if r in l2 else None,
    }
json.dump(out, open(dst, "w"), indent=1)
print(json.dumps(out, indent=1))
