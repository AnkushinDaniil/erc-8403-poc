"""
ERC-8403 reference model (shared).

Extracted verbatim from erc8403_poc.py so every scenario suite runs the same
canonical key-addressed sparse-Merkle fold, the two tiers, the lifecycle, and
the counted-op cost model. Importing this module has no side effects.
"""
from Crypto.Hash import keccak
from dataclasses import dataclass, field

DEPTH = 64

def k256(b: bytes) -> bytes:
    h = keccak.new(digest_bits=256); h.update(b); return h.digest()

class Counter:
    def __init__(self): self.hashes = 0; self.sloads = 0; self.ecrecovers = 0
    def reset(self): self.hashes = 0; self.sloads = 0; self.ecrecovers = 0
CTR = Counter()

def H(b: bytes) -> bytes:
    CTR.hashes += 1; return k256(b)

ZERO = [b"\x00" * 32]
for _ in range(DEPTH):
    ZERO.append(k256(ZERO[-1] + ZERO[-1]))

def leaf_value(authority_id, predicate, kind=0, cls=0, expiry=0):
    return H(authority_id + bytes([kind]) + bytes([cls]) + expiry.to_bytes(8, "big") + H(predicate))

def key_of(authority_id: bytes) -> int:
    return int.from_bytes(k256(b"pos" + authority_id), "big") >> (256 - DEPTH)

def bit(key: int, level: int) -> int:
    return (key >> (DEPTH - 1 - level)) & 1

def _single_collapse(key: int, val: bytes, depth: int) -> bytes:
    cur = val
    for lvl in range(DEPTH - 1, depth - 1, -1):
        sib = ZERO[DEPTH - 1 - lvl]
        cur = H(cur + sib) if bit(key, lvl) == 0 else H(sib + cur)
    return cur

def _subtree_root(members, depth: int) -> bytes:
    if not members: return ZERO[DEPTH - depth]
    if len(members) == 1:
        k, v = members[0]; return _single_collapse(k, v, depth)
    left = [m for m in members if bit(m[0], depth) == 0]
    right = [m for m in members if bit(m[0], depth) == 1]
    return H(_subtree_root(left, depth + 1) + _subtree_root(right, depth + 1))

class SparseTree:
    def __init__(self): self.leaves = {}

    def _members(self): return [(key_of(aid), v) for aid, v in self.leaves.items()]

    def root(self): return _subtree_root(self._members(), 0)

    def proof(self, authority_id: bytes):
        key = key_of(authority_id); members = self._members()
        sibs = []
        for d in range(DEPTH):
            sib_members = [m for m in members if m[0] >> (DEPTH - 1 - d) == ((key >> (DEPTH - 1 - d)) ^ 1)]
            if not sib_members:
                sibs.append((d, ZERO[DEPTH - (d + 1)], True))
            else:
                sibs.append((d, _subtree_root(sib_members, d + 1), False))
        return sibs

    @staticmethod
    def compressed_proof_bytes(sibs):
        nondefault = [s for s in sibs if not s[2]]
        return 32 + len(nondefault) * 32, len(nondefault)

def verify_membership(root: bytes, authority_id: bytes, leafval: bytes, sibs) -> bool:
    key = key_of(authority_id); cur = leafval
    for d in reversed(range(DEPTH)):
        _, sib, _ = sibs[d]
        cur = H(cur + sib) if bit(key, d) == 0 else H(sib + cur)
    return cur == root

@dataclass
class Authority:
    authority_id: bytes; predicate: bytes; cls: str; kind: int = 0; expiry: int = 0

def leaf_of_auth(a): return leaf_value(a.authority_id, a.predicate, a.kind, 1 if a.cls == "AMEND" else 0, a.expiry)

@dataclass
class Account:
    addr: bytes
    tree: SparseTree = field(default_factory=SparseTree)
    authorities: dict = field(default_factory=dict)
    recent_roots: list = field(default_factory=list)
    slot_root: bytes = ZERO[DEPTH]
    floor_slot: int = 0
    window: int = 4
    set_version: int = 0

    def _commit(self, block):
        r = self.tree.root(); self.recent_roots.append((block, r))
        self.slot_root = r; self.floor_slot = block

    def add(self, a: Authority, block):
        self.authorities[a.authority_id] = a
        self.tree.leaves[a.authority_id] = leaf_of_auth(a)
        self._commit(block)
    def add_bulk(self, auths):
        for a in auths:
            self.authorities[a.authority_id] = a
            self.tree.leaves[a.authority_id] = leaf_of_auth(a)
    def rotate(self, aid, new_pred, block):
        old = self.authorities[aid]; self.add(Authority(aid, new_pred, old.cls, old.kind, old.expiry), block)
    def revoke(self, aid, block):
        del self.authorities[aid]; del self.tree.leaves[aid]; self._commit(block)
    def referenceable(self, block):
        return [r for (s, r) in self.recent_roots if block - s <= self.window]

def sign(priv, digest): return k256(b"SIG" + priv + digest)
PRIV_OF = {}
def verify_sig(pub, digest, sig):
    CTR.ecrecovers += 1
    return sig == k256(b"SIG" + PRIV_OF[pub] + digest)
def keypair(seed):
    priv = k256(b"priv" + seed); pub = k256(b"pub" + priv); PRIV_OF[pub] = priv
    return priv, pub
def tx_digest(sender, nonce, calls, root_ref, authority_id, chain=b"CHAIN:1"):
    return k256(sender + nonce.to_bytes(8, "big") + calls + root_ref + authority_id + chain)

def build_account(seed, n_extra=0, block=1, bulk=False):
    acct = Account(addr=k256(seed + b"acct"))
    priv_a, pub_a = keypair(seed + b"A"); priv_m, pub_m = keypair(seed + b"M")
    aid_a = k256(seed + b"id_A"); aid_m = k256(seed + b"id_M")
    auths = [Authority(aid_a, b"KEY:" + pub_a, "ACT"), Authority(aid_m, b"AMEND:" + pub_m, "AMEND")]
    extra = []
    for i in range(n_extra):
        pv, pb = keypair(seed + b"X" + i.to_bytes(4, "big")); aid = k256(seed + b"idX" + i.to_bytes(4, "big"))
        auths.append(Authority(aid, b"KEY:" + pb, "ACT")); extra.append((aid, pv, pb))
    if bulk:
        acct.add_bulk(auths); acct._commit(block)
    else:
        for a in auths: acct.add(a, block)
    return acct, (aid_a, priv_a, pub_a), (aid_m, priv_m, pub_m), extra
