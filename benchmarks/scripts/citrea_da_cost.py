"""Summarise Citrea's real Bitcoin DA cost from `citrea_bitcoin_txs.py` output.

usage: python -I citrea_da_cost.py <fees.json> <btc_usd> <expected_proofs> <expected_commitments>
"""
import json
import statistics as st
import sys

t = json.load(open(sys.argv[1]))
btc, exp_p, exp_c = float(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
proofs = [x for x in t if x["size"] > 2000]
comms = [x for x in t if x["size"] == 392 and x["weight"] == 674]
noise = [x for x in t if x not in proofs and x not in comms]
fee = lambda xs: sum(x["fee"] + x["commit_fee"] for x in xs)  # noqa: E731
pb = sum(x["size"] for x in proofs)
out = {
    "proof_reveals": len(proofs), "expected_proofs_from_node": exp_p,
    "commitment_reveals": len(comms), "expected_commitments_from_node": exp_c,
    "random_prefix_matches_discarded": len(noise),
    "proof_bytes": pb, "proof_tx_size_median": st.median(x["size"] for x in proofs),
    "feerate_sat_vb": {"median": st.median(x["feerate_sat_vb"] for x in proofs + comms),
                       "min": min(x["feerate_sat_vb"] for x in proofs + comms),
                       "max": max(x["feerate_sat_vb"] for x in proofs + comms)},
    "fees_sat": {"proofs": fee(proofs), "commitments": fee(comms), "total": fee(proofs) + fee(comms)},
    "btc_usd": btc,
}
out["usd"] = {k: v / 1e8 * btc for k, v in out["fees_sat"].items()}
out["usd_per_mb_proof_data"] = out["usd"]["proofs"] / (pb / 1e6)
print(json.dumps(out, indent=1))
