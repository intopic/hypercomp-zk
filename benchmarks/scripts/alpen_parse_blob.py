"""Parse an Alpen EE DA blob (spec V1/V2 layout) into its sections, following alpenlabs/alpen-ee
`crates/da/types/src/blob.rs` and `crates/reth/statediff/src/batch/*` (strata_codec, big-endian ints).

usage: python -I alpen_parse_blob.py <blob.bin> [...]   -> JSON per blob on stdout

Layout: u64 update_seq_no | EvmHeaderSummary (block_num, timestamp, base_fee, gas_used, gas_limit, da_rate: u64)
| accounts: u32 n, n x (address[20], AccountChange) | storage: u32 n, n x (address[20], u32 m, m x (key[32],
TrimmedStorageValue)) | bytecodes: u32 n, n x (hash[32], u32 len, bytes).
AccountChange: u8 tag (0 created, 1 updated, 2 deleted); diff = u8 presence mask, then
balance SignedU256Delta (u8 sign 0/1/2 + trimmed len-prefixed magnitude), nonce SignedVarInt, code_hash[32].
"""
import json
import sys


class R:
    def __init__(self, b):
        self.b, self.i = b, 0

    def take(self, n):
        if self.i + n > len(self.b):
            raise ValueError(f"truncated at {self.i} (+{n} > {len(self.b)})")
        s = self.b[self.i:self.i + n]
        self.i += n
        return s

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return int.from_bytes(self.take(4), "big")

    def u64(self):
        return int.from_bytes(self.take(8), "big")

    def trimmed(self):
        n = self.u8()
        if n > 32:
            raise ValueError(f"trimmed length {n} > 32 at {self.i - 1}")
        return int.from_bytes(self.take(n), "big") if n else 0

    def signed_varint(self):
        first = self.u8()
        if first & 0x80 == 0:
            return first & 0x3F
        mag, shift = first & 0x3F, 6
        while True:
            byte = self.u8()
            mag |= (byte & 0x7F) << shift
            shift += 7
            if byte & 0x80 == 0:
                return mag


def parse(b):
    r = R(b)
    out = {"bytes": len(b), "seq": r.u64(),
           "header": dict(zip(["block_num", "timestamp", "base_fee", "gas_used", "gas_limit", "da_rate"], [r.u64() for _ in range(6)]))}
    s0 = r.i
    accts = []
    for _ in range(r.u32()):
        addr = r.take(20).hex()
        tag = r.u8()
        a = {"address": addr, "tag": tag}
        if tag in (0, 1):
            mask = r.u8()
            if mask & 1:
                sign = r.u8()
                a["balance_delta"] = (r.trimmed() if sign else 0) * (-1 if sign == 2 else 1)
            if mask & 2:
                a["nonce_delta"] = r.signed_varint()
            if mask & 4:
                a["code_hash"] = r.take(32).hex()
        accts.append(a)
    s1 = r.i
    storage = []
    for _ in range(r.u32()):
        addr = r.take(20).hex()
        for _ in range(r.u32()):
            storage.append({"address": addr, "slot": r.take(32).hex(), "value": hex(r.trimmed())})
    s2 = r.i
    codes = []
    for _ in range(r.u32()):
        h = r.take(32).hex()
        codes.append({"hash": h, "len": len(r.take(r.u32()))})
    if r.i != len(b):
        raise ValueError(f"{len(b) - r.i} trailing bytes")
    out.update(accounts=accts, storage=storage, bytecodes=codes,
               section_bytes={"header": s0, "accounts": s1 - s0, "storage": s2 - s1, "bytecodes": len(b) - s2})
    return out


for p in sys.argv[1:]:
    print(json.dumps({"file": p, **parse(open(p, "rb").read())}))
