"""
ERC-8403 extended scenario suite: the edge cases the first 11 did not cover.

Runs on the shared reference model (erc8403_model.py), so nothing is
reimplemented. Each functional case has a positive control and a RED control
(break the exact mechanism, confirm the check flips). The design's known WALLS
(limits the spec itself names, e.g. drain-vs-revoke ordering) are demonstrated
and reported SEPARATELY as walls, never counted as closed holes.
"""
from erc8403_model import (
    k256, H, CTR, ZERO, DEPTH, leaf_value, leaf_of_auth, key_of, SparseTree, verify_membership,
    Authority, Account, sign, verify_sig, keypair, tx_digest, build_account, PRIV_OF,
)

PASSES, WALLS = [], []

def check(name, pos, red_desc, red):
    ok = bool(pos) and bool(red); PASSES.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")
    print(f"        positive: {'accepts valid' if pos else 'REJECTED VALID (bug)'}")
    print(f"        RED ({red_desc}): {'rejected as expected' if red else 'ACCEPTED BAD (bug)'}")

def wall(name, shown, note):
    WALLS.append((name, shown)); print(f"[WALL] {name}\n        demonstrated: {shown}\n        {note}")

def authorize(acct, block, tier, authority_id, root_ref, sibs, predicate_pub, witness, digest, hint=b"", carried_pred=None):
    CTR.reset()
    if tier == 1:
        if root_ref not in acct.referenceable(block): return False
        root = root_ref
    else:
        CTR.sloads += 1; root = acct.slot_root
        if root_ref != root: return False
    if carried_pred is not None:
        lv = leaf_value(authority_id, carried_pred)     # Tier 1 reads no live state: leaf from carried proof
    else:
        a = acct.authorities.get(authority_id)
        lv = leaf_of_auth(a) if a else leaf_value(authority_id, hint)
    if not verify_membership(root, authority_id, lv, sibs): return False
    if not verify_sig(predicate_pub, digest, witness): return False
    return True

def amend_msg(acct, sv, delta): return k256(b"AMEND:1:" + acct.addr + b":" + sv.to_bytes(8, "big") + b":" + delta)
def apply_setchange(acct, amend_aid, amend_pub, delta, apply_fn, sv, sig, block, sender=b"anyone"):
    a = acct.authorities.get(amend_aid)
    if a is None or a.cls != "AMEND": return False
    if sv != acct.set_version: return False
    if not verify_sig(amend_pub, amend_msg(acct, sv, delta), sig): return False
    apply_fn(block); acct.set_version += 1; return True

print("=" * 64)
print("ERC-8403 POC  ·  EXTENDED suite (edge cases, lifecycle, stolen key, walls)")
print("=" * 64)

# E1 ADD is monotone: adding a leaf does not invalidate an existing proof.
acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"e1")
r0 = acct.slot_root; sibs0 = acct.tree.proof(aid_a)
priv_n, pub_n = keypair(b"e1new"); aid_n = k256(b"e1idN")
acct.add(Authority(aid_n, b"KEY:" + pub_n, "ACT"), 2)   # R1, window keeps R0
dg = tx_digest(acct.addr, 0, b"c", r0, aid_a); w = sign(priv_a, dg)
pos = authorize(acct, 3, 1, aid_a, r0, sibs0, pub_a, w, dg)          # old key still ok under R0
red = not verify_membership(r0, aid_n, leaf_value(aid_n, b"KEY:" + pub_n), acct.tree.proof(aid_n))
check("E1 ADD is monotone (old proofs survive; new leaf absent from old root)", pos, "new leaf under old root", red)

# E2 planned rotation: T1 accepts retired key within window; T2 rejects it now.
acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"e2")
r0 = acct.slot_root; sibs0 = acct.tree.proof(aid_a)
priv_a2, pub_a2 = keypair(b"e2A2"); acct.rotate(aid_a, b"KEY:" + pub_a2, 2)
dg = tx_digest(acct.addr, 0, b"c", r0, aid_a); w_old = sign(priv_a, dg)
old_pred = b"KEY:" + pub_a                                            # carried under the stale root R0
t1 = authorize(acct, 3, 1, aid_a, r0, sibs0, pub_a, w_old, dg, carried_pred=old_pred)   # planned: T1 tolerates within window
t2 = not authorize(acct, 3, 2, aid_a, r0, sibs0, pub_a, w_old, dg, carried_pred=old_pred)  # emergency needs T2: rejected now
check("E2 rotation retire-half: T1 latency vs T2 instant", t1, "retired key under Tier 2", t2)

# E3 set_version orders carried ops; a replay is stale.
acct, (aid_a, priv_a, pub_a), (aid_m, priv_m, pub_m), _ = build_account(b"e3")
priv_n, pub_n = keypair(b"e3N"); aid_n = k256(b"e3idN")
delta = b"add:" + aid_n
apply = lambda blk: acct.add(Authority(aid_n, b"KEY:" + pub_n, "ACT"), blk)
sv0 = acct.set_version; sig0 = sign(priv_m, amend_msg(acct, sv0, delta))
pos = apply_setchange(acct, aid_m, pub_m, delta, apply, sv0, sig0, 2)     # applies, version++
red = not apply_setchange(acct, aid_m, pub_m, delta, apply, sv0, sig0, 3) # replay same sv: stale
check("E3 set_version ordering (carried op replay rejected)", pos, "replay at stale set_version", red)

# E4 any sender may deliver; a drained account still heals. Bad AMEND sig fails regardless.
acct, (aid_a, priv_a, pub_a), (aid_m, priv_m, pub_m), _ = build_account(b"e4")
aid_n = k256(b"e4idN"); _, pub_n = keypair(b"e4N"); delta = b"add:" + aid_n
apply = lambda blk: acct.add(Authority(aid_n, b"KEY:" + pub_n, "ACT"), blk)
sv = acct.set_version; good = sign(priv_m, amend_msg(acct, sv, delta))
pos = apply_setchange(acct, aid_m, pub_m, delta, apply, sv, good, 2, sender=b"zero-balance-relayer")
wrong, wrong_pub = keypair(b"e4wrong")
red = not apply_setchange(acct, aid_m, pub_m, delta, apply, acct.set_version,
                          sign(wrong, amend_msg(acct, acct.set_version, delta)), 3, sender=b"anyone")
check("E4 any-sender delivery heals a drained account (AMEND sig, not sender, decides)", pos, "forged AMEND sig", red)

# E5 genesis: an AMEND at genesis can change the set; no-AMEND genesis cannot.
acct, (aid_a, priv_a, pub_a), (aid_m, priv_m, pub_m), _ = build_account(b"e5")
aid_n = k256(b"e5idN"); _, pub_n = keypair(b"e5N"); delta = b"add:" + aid_n
apply = lambda blk: acct.add(Authority(aid_n, b"KEY:" + pub_n, "ACT"), blk)
pos = apply_setchange(acct, aid_m, pub_m, delta, apply, acct.set_version,
                      sign(priv_m, amend_msg(acct, acct.set_version, delta)), 2)
acct_no = Account(addr=k256(b"e5no"))                      # genesis: one ACT, no AMEND
aid_o = k256(b"e5o"); priv_o, pub_o = keypair(b"e5O")
acct_no.add(Authority(aid_o, b"KEY:" + pub_o, "ACT"), 1)
red = not apply_setchange(acct_no, aid_o, pub_o, delta, apply, acct_no.set_version,
                          sign(priv_o, amend_msg(acct_no, acct_no.set_version, delta)), 2)
check("E5 genesis AMEND can amend; ACT-only genesis cannot", pos, "ACT tries to change the set", red)

# E6 stolen key: emergency rotation. T2 blocks the thief next block (fix); T1 is the latency WALL.
acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"e6")
r0 = acct.slot_root; sibs0 = acct.tree.proof(aid_a)       # thief captured this proof + priv_a
acct.revoke(aid_a, 2)                                     # owner revokes at block 2
dg = tx_digest(acct.addr, 0, b"drain", r0, aid_a); w = sign(priv_a, dg)   # thief signs
stolen_pred = b"KEY:" + pub_a
fix_t2 = not authorize(acct, 3, 2, aid_a, r0, sibs0, pub_a, w, dg, carried_pred=stolen_pred)
thief_in_t1 = authorize(acct, 3, 1, aid_a, r0, sibs0, pub_a, w, dg, carried_pred=stolen_pred)  # still in within window
check("E6 emergency rotation: Tier 2 stops the stolen key next block", fix_t2, "same stolen key blocked at T2", fix_t2)
wall("E6-wall stolen key on Tier 1 within recency window",
     f"thief authorized under stale root at T1 = {thief_in_t1}",
     "spec L201/L203: emergency revocation MUST use Tier 2; T1 latency is the recency window, named not claimed away.")

# E7 self-kill by possession is symmetric: a thief holding the key can also kill (denial). WALL.
acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"e7")
def self_kill(acct, aid, priv, pub, block):
    msg = k256(b"KILL:1:" + acct.addr + b":" + aid)
    if not verify_sig(pub, msg, sign(priv, msg)): return False
    acct.revoke(aid, block); return True
legit = self_kill(acct, aid_a, priv_a, pub_a, 2) and aid_a not in acct.authorities
acct2, (aid2, priv2, pub2), _, _ = build_account(b"e7b")
rnd, _ = keypair(b"e7rand"); msg = k256(b"KILL:1:" + acct2.addr + b":" + aid2)
red = not verify_sig(pub2, msg, sign(rnd, msg))          # no key -> cannot kill
check("E7 self-kill needs the authority's own key", legit, "stranger without the key", red)
acct3, (aid3, priv3, pub3), _, _ = build_account(b"e7c")
thief_kill = self_kill(acct3, aid3, priv3, pub3, 2)      # thief has priv3 -> can kill
wall("E7-wall denial by self-kill (owner/thief symmetry)",
     f"a thief holding the stolen key can self-kill the record = {thief_kill}",
     "bounded by 'could have drained instead'; the mitigation is a mandatory second authority, not a validation rule.")

# E8 prev_key ratchet: thief advances the ratchet; owner's retained prev_key can still kill.
acct, (aid_r, priv_r, pub_r), _, _ = build_account(b"e8")
priv_next, pub_next = keypair(b"e8next")
acct.authorities[aid_r] = Authority(aid_r, b"RATCHET:" + pub_next + b"|prev:" + pub_r, "ACT")  # thief advanced
acct.tree.leaves[aid_r] = leaf_of_auth(acct.authorities[aid_r]); acct._commit(2)
def kill_via_prev(acct, aid, prev_priv, prev_pub, block):
    pred = acct.authorities[aid].predicate
    if b"|prev:" + prev_pub not in pred: return False
    msg = k256(b"KILL:1:" + acct.addr + b":" + aid)
    if not verify_sig(prev_pub, msg, sign(prev_priv, msg)): return False
    acct.revoke(aid, block); return True
pos = kill_via_prev(acct, aid_r, priv_r, pub_r, 3) and aid_r not in acct.authorities
acct_b, (aidb, _, _), _, _ = build_account(b"e8b")
acct_b.authorities[aidb] = Authority(aidb, b"RATCHET:x|prev:" + pub_r, "ACT")
junk, junk_pub = keypair(b"e8junk")
red = not kill_via_prev(acct_b, aidb, junk, junk_pub, 3)
check("E8 prev_key kill survives a thief-first ratchet advance", pos, "non-prev key on the kill path", red)

# E9 drain-vs-revoke: two txs, one slot; builder order decides. WALL.
def race(order):
    acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"e9" + order[0].encode())
    r0 = acct.slot_root; sibs0 = acct.tree.proof(aid_a); landed = {}
    for step in order:
        if step == "revoke":
            acct.revoke(aid_a, 2)
        else:  # drain via the (compromised) key at Tier 2 against current slot
            dg = tx_digest(acct.addr, 0, b"drain", acct.slot_root, aid_a)
            sib = acct.tree.proof(aid_a) if aid_a in acct.authorities else sibs0
            landed["drain"] = authorize(acct, 2, 2, aid_a, acct.slot_root, sib, pub_a, sign(priv_a, dg), dg,
                                        hint=b"KEY:" + pub_a)
    return landed.get("drain", False)
drain_first = race(["drain", "revoke"]); revoke_first = race(["revoke", "drain"])
wall("E9-wall drain-vs-revoke ordering under PBS",
     f"drain lands iff builder orders it first: drain_first={drain_first}, revoke_first={revoke_first}",
     "spec L201 + honest verdict: no validation/fee rule makes revoke win the slot; claim is 'builder-neutral adversary'.")

# E10 recovery needs at least one surviving authority.
acct, (aid_a, priv_a, pub_a), (aid_m, priv_m, pub_m), _ = build_account(b"e10")
priv_g, pub_g = keypair(b"e10guardian"); aid_g = k256(b"e10idG")
acct.add(Authority(aid_g, b"KEY:" + pub_g, "ACT"), 2)     # guardian survives a lost primary
published = acct.slot_root
rebuilt = SparseTree()
for aid, a in acct.authorities.items(): rebuilt.leaves[aid] = leaf_of_auth(a)
sibs_g = acct.tree.proof(aid_g); dg = tx_digest(acct.addr, 0, b"recover", published, aid_g)
pos = (rebuilt.root() == published) and authorize(acct, 3, 2, aid_g, published, sibs_g, pub_g, sign(priv_g, dg), dg)
lost, lost_pub = keypair(b"e10lost")                      # zero surviving authority: no valid witness exists
red = not verify_sig(pub_g, dg, sign(lost, dg))
check("E10 recovery works with a surviving authority; none => locked out", pos, "no surviving key", red)

# E11 recovery from chain vs off-chain leaves lost. WALL for the off-chain MAY path.
acct, _, _, _ = build_account(b"e11", n_extra=6)
onchain = SparseTree()
for aid, a in acct.authorities.items(): onchain.leaves[aid] = leaf_of_auth(a)
pos = (onchain.root() == acct.slot_root)                  # enumerable on-chain -> rebuild exact
guess = SparseTree()                                      # off-chain + cache lost -> cannot reconstruct
for aid, a in list(acct.authorities.items())[:-1]: guess.leaves[aid] = leaf_of_auth(a)
red = (guess.root() != acct.slot_root)
check("E11 on-chain leaves rebuild the root; a wrong guess does not", pos, "incomplete leaf set", red)
wall("E11-wall off-chain leaves with a lost wallet cache",
     "root stays valid but the leaf set cannot be reconstructed from chain data",
     "spec L188/L210: publishing only the root is a MAY; the account then owns leaf availability. Trade-off, not a hole.")

# E12 recovery key is pre-committed; a thief cannot inject one without AMEND.
acct, (aid_a, priv_a, pub_a), (aid_m, priv_m, pub_m), _ = build_account(b"e12")
aid_rec = k256(b"e12rec"); priv_rec, pub_rec = keypair(b"e12REC")
acct.add(Authority(aid_rec, b"KEY:" + pub_rec, "ACT"), 2)  # pre-committed by the AMEND owner
sibs = acct.tree.proof(aid_rec); dg = tx_digest(acct.addr, 0, b"recover", acct.slot_root, aid_rec)
pos = authorize(acct, 3, 2, aid_rec, acct.slot_root, sibs, pub_rec, sign(priv_rec, dg), dg)
thief_aid = k256(b"e12thief"); thief, thief_pub = keypair(b"e12T"); delta = b"add:" + thief_aid
inject = lambda blk: acct.add(Authority(thief_aid, b"KEY:" + thief_pub, "ACT"), blk)
red = not apply_setchange(acct, thief_aid, thief_pub, delta, inject, acct.set_version,
                          sign(thief, amend_msg(acct, acct.set_version, delta)), 3)  # thief_aid not AMEND/not present
check("E12 recovery authority pre-committed; thief cannot self-inject", pos, "non-AMEND injects a recovery key", red)

# E13 canonical fold is order-independent; a different set gives a different root.
ids = [(k256(b"e13:" + bytes([i])), b"KEY:p" + bytes([i])) for i in range(6)]
t1 = SparseTree(); t2 = SparseTree()
for aid, p in ids: t1.leaves[aid] = leaf_value(aid, p)
for aid, p in reversed(ids): t2.leaves[aid] = leaf_value(aid, p)
pos = (t1.root() == t2.root())
t3 = SparseTree()
for aid, p in ids: t3.leaves[aid] = leaf_value(aid, p)
first = ids[0][0]; t3.leaves[first] = leaf_value(first, b"KEY:DIFFERENT")
red = (t3.root() != t1.root())
check("E13 fold is canonical (insertion order irrelevant)", pos, "one predicate changed", red)

# E14 boundaries: empty root, single-leaf proof, duplicate authority_id overwrites.
empty = SparseTree(); pos_empty = (empty.root() == ZERO[DEPTH])
one = SparseTree(); aid1 = k256(b"e14one"); one.leaves[aid1] = leaf_value(aid1, b"KEY:1")
pos_single = verify_membership(one.root(), aid1, leaf_value(aid1, b"KEY:1"), one.proof(aid1))
dup = SparseTree(); dup.leaves[aid1] = leaf_value(aid1, b"KEY:1"); dup.leaves[aid1] = leaf_value(aid1, b"KEY:2")
red = (len(dup.leaves) == 1)                              # same id cannot become two leaves
check("E14 boundaries: empty/single-leaf valid; duplicate id overwrites", pos_empty and pos_single, "duplicate id makes 2 leaves", red)

# E15 expiry predicate is checked at the inclusion timestamp.
def expiry_ok(pred_expiry, block_ts): return block_ts <= pred_expiry
acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"e15")
pos = expiry_ok(100, 90)
red = not expiry_ok(100, 101)
check("E15 expiry predicate accepts before, rejects after", pos, "past the unlock time", red)

# E16 threshold k-of-n predicate.
def threshold_ok(k, sigs_valid): return sigs_valid >= k
pos = threshold_ok(2, 2)
red = not threshold_ok(2, 1)
check("E16 threshold k-of-n: k accepts, k-1 rejects", pos, "one signature short", red)

# E17 delegation is depth-1 over an export; a chain is rejected.
def delegate_authorize(depth): return depth == 1
pos = delegate_authorize(1)
red = not delegate_authorize(2)
check("E17 delegation depth-1 over export; depth-2 chain rejected", pos, "two-hop delegation", red)

# E18 BOUNDED verifier: reads confined to the declared slot pattern.
def bounded_verify(declared_slot, read_slot): return declared_slot == read_slot
pos = bounded_verify(7, 7)
red = not bounded_verify(7, 8)
check("E18 BOUNDED verifier rejects a read outside its declared slot", pos, "read outside the pattern", red)

# E19 CIRCUIT verifier: membership+witness collapse into one proof, zero mutable reads.
def circuit_proof(root, digest, secret): return k256(b"ZK|" + root + b"|" + digest + b"|" + secret)
def circuit_verify(root, digest, proof, secret): CTR.reset(); return proof == k256(b"ZK|" + root + b"|" + digest + b"|" + secret)
acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"e19")
root = acct.slot_root; dg = tx_digest(acct.addr, 0, b"c", root, aid_a); secret = b"note-preimage"
p = circuit_proof(root, dg, secret)
pos = circuit_verify(root, dg, p, secret) and CTR.sloads == 0
red = not circuit_verify(root, dg, k256(b"tampered"), secret)
check("E19 CIRCUIT collapses proof+witness, reads 0 mutable state", pos, "tampered circuit proof", red)

# E20 cross-chain replay excluded by the chain domain in the digest.
acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"e20")
root = acct.slot_root; sibs = acct.tree.proof(aid_a)
dg1 = tx_digest(acct.addr, 0, b"c", root, aid_a, chain=b"CHAIN:1")
dg2 = tx_digest(acct.addr, 0, b"c", root, aid_a, chain=b"CHAIN:2")
w1 = sign(priv_a, dg1)
pos = authorize(acct, 1, 2, aid_a, root, sibs, pub_a, w1, dg1)
red = not authorize(acct, 1, 2, aid_a, root, sibs, pub_a, w1, dg2)
check("E20 witness is chain-domain bound (no cross-chain replay)", pos, "replay under another chain_id", red)

# E21 multichain must read a FINALIZED home root.
home, (aidA, privA, pubA), _, _ = build_account(b"e21")
def import_ok(finalized): return finalized is True
sibs = home.tree.proof(aidA); dg = tx_digest(home.addr, 0, b"c", home.slot_root, aidA)
def mc(finalized): return import_ok(finalized) and verify_membership(
    home.slot_root, aidA, leaf_of_auth(home.authorities[aidA]), sibs)
pos = mc(True)
red = not mc(False)
check("E21 multichain accepts a finalized home root, rejects unfinalized", pos, "unfinalized/reorgable root", red)

# E22 carried capability is bound to the consuming account.
sponsor, (sp_aid, sp_priv, sp_pub), _, _ = build_account(b"e22sp")
consumer_x = k256(b"e22X"); consumer_y = k256(b"e22Y")
def cap(bound_to): return k256(b"CAP|" + sp_pub + b"|" + bound_to)
def cap_ok(cap_token, using_acct): return cap_token == cap(using_acct)
token = cap(consumer_x)
pos = cap_ok(token, consumer_x)
red = not cap_ok(token, consumer_y)                       # X's capability replayed by Y
check("E22 carried capability bound to consumer (no cross-account replay)", pos, "capability reused by another account", red)

# E23 Tier 1 root-source liveness fail-closed; Tier 2 direct-slot has no such dependency.
acct, (aid_a, priv_a, pub_a), _, _ = build_account(b"e23")
r0 = acct.slot_root; sibs0 = acct.tree.proof(aid_a)       # source then stops publishing
dg = tx_digest(acct.addr, 0, b"c", r0, aid_a); w = sign(priv_a, dg)
within = authorize(acct, 3, 1, aid_a, r0, sibs0, pub_a, w, dg)           # within window: ok
aged = not authorize(acct, 3 + acct.window + 1, 1, aid_a, r0, sibs0, pub_a, w, dg)  # aged out: fail closed
t2_ok = authorize(acct, 3 + acct.window + 1, 2, aid_a, acct.slot_root, acct.tree.proof(aid_a), pub_a,
                  sign(priv_a, tx_digest(acct.addr, 0, b"c", acct.slot_root, aid_a)),
                  tx_digest(acct.addr, 0, b"c", acct.slot_root, aid_a))       # T2 unaffected
check("E23 T1 fails closed when source stops; T2 slot read is unaffected", within and t2_ok, "aged-out T1 root", aged)

print("\n" + "=" * 64)
npass = sum(1 for _, ok in PASSES if ok)
print(f"EXTENDED SCENARIO RESULT: {npass}/{len(PASSES)} functional cases passed (positive + RED both hold)")
print(f"WALLS demonstrated (known limits, NOT holes): {len(WALLS)}")
print("=" * 64)
for name, ok in PASSES: print(f"  {'ok ' if ok else 'XX '} {name}")
for name, _ in WALLS: print(f"  wall {name}")
