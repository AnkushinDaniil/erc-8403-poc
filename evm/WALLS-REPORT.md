# ERC-8403 walls: the four known limits, demonstrated on real EVM

Each is a *limit*, not a hole: the test shows the wall is real AND its stated mitigation
holds. Run on revm (real ecrecover/keccak) via `test/Walls.t.sol`. 4/4 pass.

## W1: drain-vs-revoke ordering under PBS  (spec L201)
- Same drain tx: lands when ordered before the revoke, fails when ordered after. Outcome
  is purely order-determined.
- Wall: no validation or fee rule reorders the revoke ahead of the drain; a PBS builder
  picks the order.
- Mitigation: none at the validation/fee layer. Revocation security is claimed only
  "against a builder-neutral adversary." Symmetric with every account model.

## W2: denial by self-kill (owner/thief symmetry)
- A thief holding the stolen key self-kills authority X with the identical call the owner
  would make; X can no longer act (grief).
- Wall: possession of the record's own key is the only check, by design (self-kill needs
  no AMEND). Bounded by "the thief could have drained instead."
- Mitigation: a mandatory second authority; after X is killed, authority M still
  authorizes, so the account is not bricked.

## W3: Tier-1 revocation latency = the recency window  (spec L71, L201, L203)
- After revoke (live root = R1 without X): Tier 2 (own-slot read) rejects the stale root
  R0 in the same block, instant. Tier 1 (root-bound) still verifies R0, because it checks
  whatever root the tx names; only the external recency window evicts it later.
- Wall: Tier-1 revocation is latent up to the referencing mechanism's window.
- Mitigation: emergency revocation MUST use Tier 2. (The window's eviction itself is the
  8272/mempool layer, not modelled here; the core root-bound-vs-slot-bound property is.)

## W4: off-chain leaves + lost cache (data availability)  (spec L188, L210, L212)
- On-chain enumerable leaves: the sibling is rebuilt and authorize succeeds, recovery is a
  re-read. Lost cache: an empty or guessed sibling yields no valid proof.
- Wall: a committed root is a hiding commitment; it verifies a proof but cannot reconstruct
  the leaves. Publishing only the root is a MAY, and the account then owns leaf availability.
- Mitigation: keep the tree enumerable on-chain, so recovery from any node is a re-read.

## Provenance / honest scope
- Real EVM (revm), real secp256k1 ecrecover and keccak; not a Python model.
- W1 ordering is demonstrated deterministically (two orders), not under a live competitive
  builder; the property shown, order decides and nothing forces revoke-first, is the point.
- W3's window *eviction* is the 8272 recent-root / mempool layer (no 8272 on the solo lab);
  the tier-1-vs-tier-2 root-source contrast that makes the window matter is shown live.
- Solo-client throughout; cross-client (ethrex) still pending public devnet restore.
