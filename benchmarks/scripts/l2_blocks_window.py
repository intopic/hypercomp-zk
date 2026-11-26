"""Find the first block at/after two UTC timestamps on an EVM chain (binary search on timestamps).

usage: python -I l2_blocks_window.py <name> <rpc> <start_unix> <end_unix>
prints: name first_block_at_start first_block_at_end blocks_in_window avg_block_time_s
"""
import json
import sys
import time
import urllib.request


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, body, {"Content-Type": "application/json", "User-Agent": "research-script"})
            with urllib.request.urlopen(req, timeout=60) as r:
                d = json.load(r)
            if "result" in d and d["result"] is not None:
                return d["result"]
            err = d
        except Exception as e:  # noqa: BLE001
            err = e
        time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"{method} {params}: {err}")


def ts(url, n):
    return int(rpc(url, "eth_getBlockByNumber", [hex(n), False])["timestamp"], 16)


def first_at_or_after(url, t, hi):
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        if ts(url, mid) < t:
            lo = mid + 1
        else:
            hi = mid
    return lo


name, url, t0, t1 = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
head = int(rpc(url, "eth_blockNumber", []), 16)
b0 = first_at_or_after(url, t0, head)
b1 = first_at_or_after(url, t1, head)
n = b1 - b0
print(f"{name} {b0} {b1} {n} {86400 / n if n else 0:.3f}")
