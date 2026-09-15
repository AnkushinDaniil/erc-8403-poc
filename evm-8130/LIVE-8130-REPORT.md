# ERC-8403 Read form on the live EIP-8130 Keystore

This layer runs the ERC-8403 authorization check, in its Read form, against the
real base/eip-8130 Keystore, unmodified. The Read form is: establish membership
by reading the acting authority's record directly from account-owned keystore
state, then verify a witness over the transaction. EIP-8130's `authenticateActor`
is that check at proof-path length zero.

## What ran (measured on live code, 2026-09-15)

Source: github.com/base/eip-8130 at commit `812317be00d6829e217e0cc92f75be362fde0711`.
Driver: the repository's own `KeystoreTest` harness plus `test/ERC8403ReadForm8130.t.sol`.
Runner: `./run_8130_live.sh` (clones the pinned source, drops the test in, runs it).

Result: 3 tests, 256 fuzz runs each, all pass.

- `test_readForm_positive_and_red`: a valid secp256k1 witness authorizes and
  returns the acting `actorId` with admin scope; a key that is not committed to
  the account is rejected.
- `test_readForm_accountKeyed_isolation`: an authority proven for account A does
  not authorize account B.
- `test_readForm_revoke_instant`: a second actor authorizes while live; after a
  revoke it is rejected at once, with no recency window. This is the Tier 2
  instant-revocation property.

Positive control and rejection control each drive the real `Keystore.authenticateActor`
path, not a model of it.

## Authority-write gate (read from source, not memory)

Every write to an actor record is authorized by that account's own admin
authority and keyed by the account:

- Storage is `mapping(bytes32 actorId => mapping(address account => ActorRecord))`
  (`src/Keystore.sol:413`). The account is the inner mapping key by design; the
  source comment at line 412 states this is "to pass ERC-7562 storage access
  rules for ERC-4337 compatibility". The record is therefore an account-associated
  slot in the ERC-7562 sense.
- Config changes go through `applySignedAccountChanges(account, batch)`, which
  authorizes the batch via `authenticateActor(account, digest, batch.signature)`
  and requires admin scope. `createAccount` writes only the CREATE2-derived
  address it commits, and `importAccount` is gated on `msg.sender`.
- No privileged, admin, or migration path writes another account's record.

Consequence for unification: because the canonical-authenticator read set is one
account-associated slot, a validated transaction is invalidated only by that
account's own config change or nonce (the sole-invalidator property). This is the
property a code-is-authority client (EIP-8141) would need to read the record under
an authority-scoped storage rule.

Carve-out (also read from source): `DelegateAuthenticator.authenticate` resolves
by calling `KEYSTORE.authenticateActor(delegate, ...)`, which reads the *delegate*
account's record, a single cross-account read (depth 1, nested actor must be the
delegate account's admin, recursion rejected). This is the one path outside strict
per-account association, and EIP-8130 already classes stateful and cross-account
authenticators under its permissive acceptance policy with invalidation tracking.
The canonical (non-Delegate) subset keeps the sole-invalidator property.

## Honest scope

- This exercises EIP-8130's `authenticateActor` step (its signature-authentication
  entry) against the real Keystore. It does not run a full 0x79 transaction through
  a live 8130 node's mempool admission.
- It does not run an EIP-8141 VERIFY frame reading 8130 keystore state. That path
  needs the proposed 8141 storage-access rule change and a frames client that
  implements it; it remains a proposal, not a measured result here.
