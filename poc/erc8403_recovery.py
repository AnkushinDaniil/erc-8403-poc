"""
ERC-8403 recovery conformance suite: committed-root reconstruction equals
semantic authority reconstruction.

Runs on the shared reference model (erc8403_model.py). The leaf commits every
outcome-relevant field (authority_id, kind, cls, expiry, keccak(predicate)),
matching the Solidity leafOf, so a foreign wallet that rebuilds the committed
set from chain leaves plus the declared interpretation scheme reproduces not
only the root but also what each authority is allowed to do (changeSet).
Each case has a positive control and a RED control; the RED controls replay
the pre-fix encoding (cls outside the leaf) and show the collision it caused.
"""
import sys
from erc8403_model import (
    k256, H, leaf_value, leaf_of_auth, SparseTree, Authority, keypair, build_account,
)

PASSES, WALLS = [], []

def check(name, pos, red_desc, red):
    ok = bool(pos) and bool(red); PASSES.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    print(f"        positive: {'accepts valid' if pos else 'REJECTED VALID (bug)'}")
    print(f"        RED ({red_desc}): {'rejected as expected' if red else 'ACCEPTED BAD (bug)'}")

def wall(name, shown, note):
    WALLS.append((name, shown)); print(f"[WALL] {name}\n        demonstrated: {shown}\n        {note}")

CLS_INT = {"ACT": 0, "AMEND": 1}
CLS_STR = {0: "ACT", 1: "AMEND"}

def old_leaf(a): return H(a.authority_id + a.predicate)

def change_set_allowed(cls): return cls == "AMEND"

def scheme_full(leaf, authority_id, predicate, kinds=(0,), clss=(0, 1), expiries=(0,)):
    for kind in kinds:
        for cls in clss:
            for expiry in expiries:
                if leaf_value(authority_id, predicate, kind, cls, expiry) == leaf:
                    return Authority(authority_id, predicate, CLS_STR[cls], kind, expiry)
    return None

def scheme_no_cls(leaf, authority_id, predicate, default_cls):
    if old_leaf(Authority(authority_id, predicate, default_cls)) == leaf:
        return Authority(authority_id, predicate, default_cls)
    return None

def foreign_rebuild(chain_leaves, preimages, scheme):
    tree = SparseTree(); decisions = {}
    for aid, leaf in chain_leaves.items():
        rec = scheme(leaf, aid, preimages[aid])
        if rec is None: return None, None
        tree.leaves[aid] = leaf_of_auth(rec); decisions[aid] = change_set_allowed(rec.cls)
    return tree.root(), decisions

print("=" * 64)
print("ERC-8403 POC  ·  RECOVERY conformance (committed root == semantic set)")
print("=" * 64)

aid = k256(b"rec1:id"); _, pub = keypair(b"rec1"); pred = b"KEY:" + pub
a_amend = Authority(aid, pred, "AMEND"); a_act = Authority(aid, pred, "ACT")
pos = leaf_of_auth(a_amend) != leaf_of_auth(a_act)
red = old_leaf(a_amend) == old_leaf(a_act)
print(f"        new leaf AMEND = {leaf_of_auth(a_amend).hex()}")
print(f"        new leaf ACT   = {leaf_of_auth(a_act).hex()}")
print(f"        old leaf AMEND = {old_leaf(a_amend).hex()}")
print(f"        old leaf ACT   = {old_leaf(a_act).hex()}")
check("REC-1 semantic reconstruction: cls is inside the leaf (same id+predicate, different cls => different leaf)",
      pos, "old encoding omits cls: AMEND and ACT leaves COLLIDE", red)

acct, (aid_a, _, pub_a), (aid_m, _, pub_m), _ = build_account(b"rec2")
original = {a: change_set_allowed(acct.authorities[a].cls) for a in acct.authorities}
chain_leaves = dict(acct.tree.leaves)
preimages = {a: acct.authorities[a].predicate for a in acct.authorities}
root_full, dec_full = foreign_rebuild(chain_leaves, preimages, scheme_full)
pos = (root_full == acct.slot_root) and (dec_full == original) and (dec_full[aid_m] is True) and (dec_full[aid_a] is False)
old_chain = {a: old_leaf(acct.authorities[a]) for a in acct.authorities}
red = False
for default_cls in ("ACT", "AMEND"):
    _, dec_old = foreign_rebuild(old_chain, preimages, lambda l, i, p: scheme_no_cls(l, i, p, default_cls))
    wrong = [a for a in original if dec_old[a] != original[a]]
    print(f"        no-cls scheme, default {default_cls:<5}: decisions {sorted(dec_old.values())} vs original {sorted(original.values())}; wrong for {len(wrong)} of {len(original)} authorities")
    red = red or (len(wrong) >= 1)
check("REC-2 cross-form agreement: foreign rebuild from chain leaves + declared scheme reproduces changeSet",
      pos, "scheme that drops cls flips the decision for at least one authority", red)

thr = Authority(k256(b"rec-wall:id"), b"THRESHOLD:2of3", "AMEND", 1, 0)
chain_thr = {thr.authority_id: leaf_of_auth(thr)}
root_undeclared, _ = foreign_rebuild(chain_thr, {thr.authority_id: thr.predicate}, scheme_full)
root_declared, dec_declared = foreign_rebuild(chain_thr, {thr.authority_id: thr.predicate},
                                              lambda l, i, p: scheme_full(l, i, p, kinds=(0, 1)))
wall("REC-wall interpretation scheme is declared out-of-band",
     f"rebuild with kind domain {{0}} recovers nothing = {root_undeclared is None}; with declared {{0,1}} recovers root and AMEND = {root_declared is not None and dec_declared[thr.authority_id] is True}",
     "the leaf commits the fields, not their meaning: kind/cls/expiry domains are a convention the verifier and wallet share, not data recoverable from the root.")

print("\n" + "=" * 64)
npass = sum(1 for _, ok in PASSES if ok)
print(f"RECOVERY CONFORMANCE: {npass}/{len(PASSES)} pass ; WALLS/BOUNDARY: {len(WALLS)}/{len(WALLS)} demonstrated.")
print("=" * 64)
for name, ok in PASSES: print(f"  {'ok ' if ok else 'XX '} {name}")
for name, _ in WALLS: print(f"  wall {name}")
sys.exit(0 if npass == len(PASSES) else 1)
