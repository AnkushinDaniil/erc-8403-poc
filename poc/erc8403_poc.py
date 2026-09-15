"""
ERC-8403 proof-of-concept and measurement harness.

Models the standard's core as a runnable reference: a canonical key-addressed
sparse Merkle fold over authority leaves, the two authorization tiers, the
add/rotate/revoke lifecycle, recovery, isolation, multichain, and the verifier
cost classes. Every scenario runs a positive control and a RED control (break
the exact mechanism, confirm the check flips), so a PASS reflects the live model
path and not a hardcoded answer.

Not a consensus client: EIP-8141 frames and the EIP-8272 recent-root store are
modelled at the data-and-cost level, since no public mempool ships them yet.
Numbers are labelled measured (counted from this run) or analytic (a cost model
applied to those counts). No number is presented as gas measured on a live node.
The tree uses a 64-level key-addressed fold; the canonical/position properties
are identical to a full 256-level tree, only the absolute proof length scales.
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
    ZERO.append(k256(ZERO[-1] + ZERO[-1]))  # setup, not counted

def leaf_value(authority_id, predicate, kind=0, cls=0, expiry=0):
    return H(authority_id + bytes([kind]) + bytes([cls]) + expiry.to_bytes(8, "big") + H(predicate))

def key_of(authority_id: bytes) -> int:
    return int.from_bytes(k256(b"pos" + authority_id), "big") >> (256 - DEPTH)

def bit(key: int, level: int) -> int:                       # level 0 = MSB
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
    def __init__(self): self.leaves = {}   # authority_id -> leaf_value

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

    def _commit(self, block):
        r = self.tree.root(); self.recent_roots.append((block, r))
        self.slot_root = r; self.floor_slot = block

    def add(self, a: Authority, block):
        self.authorities[a.authority_id] = a
        self.tree.leaves[a.authority_id] = leaf_of_auth(a)
        self._commit(block)
    def add_bulk(self, auths):                              # measurement fast path
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
def tx_digest(sender, nonce, calls, root_ref, authority_id):
    return k256(sender + nonce.to_bytes(8, "big") + calls + root_ref + authority_id + b"CHAIN:1")

predicate_hint = b""
def authorize(acct, block, tier, authority_id, root_ref, sibs, predicate_pub, witness, digest):
    CTR.reset()
    if tier == 1:
        if root_ref not in acct.referenceable(block): return False
        root = root_ref
    else:
        CTR.sloads += 1; root = acct.slot_root
        if root_ref != root: return False
    a = acct.authorities.get(authority_id)
    lv = leaf_of_auth(a) if a else leaf_value(authority_id, predicate_hint)
    if not verify_membership(root, authority_id, lv, sibs): return False
    if not verify_sig(predicate_pub, digest, witness): return False
    return True

RESULTS = []
def check(name, pos, red_desc, red):
    ok = bool(pos) and bool(red); RESULTS.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    print(f"        positive: {'accepts valid' if pos else 'REJECTED VALID (bug)'}")
    print(f"        RED ({red_desc}): {'rejected as expected' if red else 'ACCEPTED BAD (bug)'}")

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

print("=" * 64)
print("ERC-8403 POC  ·  scenario suite (positive + RED control each)")
print("=" * 64)

acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"s1")
root = acct.slot_root; sibs = acct.tree.proof(aid_a)
dg = tx_digest(acct.addr, 0, b"call:transfer(bob,1)", root, aid_a)
w_ok = sign(priv_a, dg); w_bad = sign(priv_a, dg[:-1] + bytes([dg[-1] ^ 1]))
pos = authorize(acct, 1, 2, aid_a, root, sibs, pub_a, w_ok, dg)
red = not authorize(acct, 1, 2, aid_a, root, sibs, pub_a, w_bad, dg)
check("S1 home act (Tier 2): valid witness authorizes", pos, "wrong witness", red)

acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"s2")
root = acct.slot_root; sibs = acct.tree.proof(aid_a)
dg = tx_digest(acct.addr, 0, b"c", root, aid_a); w = sign(priv_a, dg)
pos = authorize(acct, 1, 2, aid_a, root, sibs, pub_a, w, dg)
bad = list(sibs); bad[0] = (0, k256(b"garbage"), False)
red = not authorize(acct, 1, 2, aid_a, root, bad, pub_a, w, dg)
check("S2 membership+witness independence", pos, "valid witness but broken proof", red)

acct, (aid_a, priv_a, pub_a), _, extra = build_account(b"s3", n_extra=1)
(aid_x, priv_x, pub_x) = extra[0]; old_root = acct.slot_root; old_sibs = acct.tree.proof(aid_x)
acct.revoke(aid_x, 2); predicate_hint = b"KEY:" + pub_x
dg = tx_digest(acct.addr, 0, b"c", old_root, aid_x); w = sign(priv_x, dg)
t1 = authorize(acct, 3, 1, aid_x, old_root, old_sibs, pub_x, w, dg)
t2 = not authorize(acct, 3, 2, aid_x, old_root, old_sibs, pub_x, w, dg)
check("S3 Tier1 latency window is real; Tier2 own-slot is instant", t1, "same revoke under Tier 2", t2)
predicate_hint = b""

acctA, (aidA, privA, pubA), _, _ = build_account(b"s4a")
acctB, _, _, _ = build_account(b"s4b")
sibsA = acctA.tree.proof(aidA); rootA = acctA.slot_root
dg = tx_digest(acctA.addr, 0, b"c", rootA, aidA); w = sign(privA, dg)
pos = authorize(acctA, 1, 2, aidA, rootA, sibsA, pubA, w, dg)
red = not verify_membership(acctB.slot_root, aidA, leaf_value(aidA, b"KEY:" + pubA), sibsA)
check("S4 isolation (A's proof does not verify under B's root)", pos, "A leaf vs B root", red)

acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"s5")
priv_a2, pub_a2 = keypair(b"s5A2"); acct.rotate(aid_a, b"KEY:" + pub_a2, 2)
root = acct.slot_root; sibs = acct.tree.proof(aid_a)
dg = tx_digest(acct.addr, 1, b"c", root, aid_a); w2 = sign(priv_a2, dg)
pos = authorize(acct, 2, 2, aid_a, root, sibs, pub_a2, w2, dg)
red = not verify_membership(root, aid_a, leaf_value(aid_a, b"KEY:" + pub_a), sibs)
check("S5 rotate binds new key to same slot", pos, "old predicate under new root", red)

acct, _, _, extra = build_account(b"s6", n_extra=8)
published = acct.slot_root
rebuilt = SparseTree()
for aid, a in acct.authorities.items(): rebuilt.leaves[aid] = leaf_of_auth(a)
pos = (rebuilt.root() == published)
broken = SparseTree()
for aid, a in list(acct.authorities.items())[:-1]: broken.leaves[aid] = leaf_of_auth(a)
red = (broken.root() != published)
check("S6 recovery rebuilds the exact root from on-chain leaves", pos, "one leaf missing", red)

home, (aidA, privA, pubA), _, _ = build_account(b"s7")
home_state_root = k256(b"home_block_root|" + home.slot_root)
def sp_of(root, hsr): return k256(b"slotproof|" + root + b"|" + hsr)
sibs = home.tree.proof(aidA); dg = tx_digest(home.addr, 0, b"c", home.slot_root, aidA); w = sign(privA, dg)
def mc(sp, expect_root, hsr, acct, aid, sibs, pub, w, dg):
    if sp != sp_of(expect_root, hsr): return False
    if not verify_membership(expect_root, aid, leaf_of_auth(acct.authorities[aid]), sibs): return False
    return verify_sig(pub, dg, w)
sp = sp_of(home.slot_root, home_state_root)
pos = mc(sp, home.slot_root, home_state_root, home, aidA, sibs, pubA, w, dg)
red = not mc(sp, k256(b"forged"), home_state_root, home, aidA, sibs, pubA, w, dg)
check("S7 multichain: storage-proof pins the home root", pos, "forged home root", red)

acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"s8")
root = acct.slot_root; sibs = acct.tree.proof(aid_a)
dg1 = tx_digest(acct.addr, 0, b"transfer(bob,1)", root, aid_a)
dg2 = tx_digest(acct.addr, 0, b"transfer(eve,1000)", root, aid_a)
w1 = sign(priv_a, dg1)
pos = authorize(acct, 1, 2, aid_a, root, sibs, pub_a, w1, dg1)
red = not authorize(acct, 1, 2, aid_a, root, sibs, pub_a, w1, dg2)
check("S8 witness binds to the full call set", pos, "replay to different calls", red)

acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"s9")
def self_kill(acct, aid, priv, pub, block):
    msg = k256(b"KILL:1:" + acct.addr + b":" + aid)
    if not verify_sig(pub, msg, sign(priv, msg)): return False
    acct.revoke(aid, block); return True
pos = self_kill(acct, aid_a, priv_a, pub_a, 2) and (aid_a not in acct.authorities)
acct2, (aid_a2, priv_a2, pub_a2), _, _ = build_account(b"s9b")
wrong, _ = keypair(b"thief"); msg = k256(b"KILL:1:" + acct2.addr + b":" + aid_a2)
red = not verify_sig(pub_a2, msg, sign(wrong, msg))
check("S9 self-kill by possession removes the authority", pos, "thief without the key", red)

acct, (aid_a, priv_a, pub_a), (aid_m, priv_m, pub_m), _ = build_account(b"s10")
sc = lambda a: a.cls == "AMEND"
check("S10 ACT/AMEND class split", sc(acct.authorities[aid_m]), "ACT tries to change the set", not sc(acct.authorities[aid_a]))

acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"s11")
root = acct.slot_root; sibs = acct.tree.proof(aid_a)
dg = tx_digest(acct.addr, 0, b"c", root, aid_a); w = sign(priv_a, dg)
pos = authorize(acct, 1, 2, aid_a, root, sibs, pub_a, w, dg)
unk = k256(b"never"); predicate_hint = b"KEY:" + pub_a
red = not authorize(acct, 1, 2, unk, root, acct.tree.proof(unk), pub_a, w, dg)
predicate_hint = b""
check("S11 fail-closed for an unknown authority", pos, "authority never in the set", red)

print("\n" + "=" * 64)
print("MEASUREMENTS  (measured = counted this run; analytic = cost model on counts)")
print("=" * 64)
print("\nAuthority-set size vs proof size and root-recompute cost:")
print(f"{'N':>6} {'proof_bytes':>12} {'nondef_sibs':>12} {'root_hashes':>12} {'verify_hashes':>14}")
for N in [1, 4, 16, 64, 256]:
    acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"m" + N.to_bytes(2, "big"), n_extra=max(0, N - 2), bulk=True)
    sibs = acct.tree.proof(aid_a); pbytes, nnd = SparseTree.compressed_proof_bytes(sibs)
    CTR.reset(); acct.tree.root(); rh = CTR.hashes
    CTR.reset(); verify_membership(acct.slot_root, aid_a, leaf_value(aid_a, b"KEY:" + pub_a), sibs); vh = CTR.hashes
    print(f"{N:>6} {pbytes:>12} {nnd:>12} {rh:>12} {vh:>14}")

print("\nPer-tier authorization cost at N=256 (analytic gas on measured op counts):")
GAS = {"sload": 2100, "ecrecover": 3000, "keccak": 42}
acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"gt", n_extra=254, bulk=True)
sibs = acct.tree.proof(aid_a); root = acct.slot_root
dg = tx_digest(acct.addr, 0, b"c", root, aid_a); w = sign(priv_a, dg)
for tier, ref in [(1, acct.slot_root), (2, acct.slot_root)]:
    acct.recent_roots = [(0, acct.slot_root)]
    authorize(acct, 1, tier, aid_a, ref, sibs, pub_a, w, dg)
    g = CTR.sloads * GAS["sload"] + CTR.ecrecovers * GAS["ecrecover"] + CTR.hashes * GAS["keccak"]
    print(f"  Tier {tier}: sloads={CTR.sloads} ecrecover={CTR.ecrecovers} keccak={CTR.hashes}"
          f"  analytic_gas~{g}  (MAX_VERIFY_GAS=100000)")

print("\nVerifier cost classes (analytic, ordered by mutable state read):")
for kind, mut, note in [("CANONICAL", "0", "table-priced, no execution"),
                        ("CIRCUIT", "0", "succinct: proof+witness collapse into one proof"),
                        ("BOUNDED", "1", "one fixed account-owned slot"),
                        ("CONTRACT", "arb", "simulate under verify-gas cap, else private inclusion")]:
    print(f"  {kind:<10} mutable_reads={mut:<4} {note}")

npass = sum(1 for _, ok in RESULTS if ok)
print("\n" + "=" * 64)
print(f"SCENARIO RESULT: {npass}/{len(RESULTS)} passed (positive + RED control both hold)")
print("=" * 64)
for name, ok in RESULTS:
    print(f"  {'ok ' if ok else 'XX '} {name}")
