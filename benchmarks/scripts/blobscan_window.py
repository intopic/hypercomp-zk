"""Collect every blob transaction and blob of one rollup for one UTC window from Blobscan.

usage: python -I blobscan_window.py <rollup> <startISO> <endISO> <out.json>
"""
import json
import sys
import time
import urllib.request

API = "https://api.blobscan.com"


def get(path):
    for attempt in range(6):
        try:
            req = urllib.request.Request(API + path, headers={"User-Agent": "research-script"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except Exception as e:  # noqa: BLE001
            time.sleep(2 * (attempt + 1))
            err = e
    raise RuntimeError(f"{path}: {err}")


def paginate(kind, rollup, start, end):
    out, page = [], 1
    while True:
        d = get(f"/{kind}?rollups={rollup}&startDate={start}&endDate={end}&ps=100&p={page}&sort=asc")
        items = d.get(kind, [])
        out.extend(items)
        if len(items) < 100:
            return out
        page += 1
        time.sleep(0.15)


rollup, start, end, dst = sys.argv[1:5]
txs = paginate("transactions", rollup, start, end)
blobs = paginate("blobs", rollup, start, end)
json.dump({"rollup": rollup, "start": start, "end": end, "transactions": txs, "blobs": blobs}, open(dst, "w"))
print(rollup, len(txs), "txs", len(blobs), "blobs")
