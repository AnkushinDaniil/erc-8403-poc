# ERC-8403 — isolated real-EVM Loop-2 (Foundry / revm)

Isolated from the (offline) public ethrex frame-tx devnet. Engine: Foundry 1.8.1,
solc 0.8.36, `via_ir` + optimizer. Executes the ERC-8403 authorization logic as a real
Solidity contract on a real EVM: real secp256k1 `ecrecover`, real keccak, canonical
commutative Merkle. Every scenario has a positive control and a RED control (mutate the
exact mechanism, confirm the check flips).

## Scope (honest)
- IN: the on-chain authorization check (the EIP-8141 VERIFY-frame logic) and the
  ACT/AMEND lifecycle guard, run byte-accurate on real EVM.
- OUT (consensus layer, needs a live frames client — public devnet is down): the 0x06
  frame envelope, `RECENTROOTREFLOAD`, mempool admission, T1 recency-window timing,
  drain-vs-revoke ordering under PBS, cross-client byte-for-byte agreement.

## Result: 14/14 real-EVM tests pass (positive + RED both hold)
S1 home act (Tier 2) · S2 proof⊥witness independence · S4 isolation · S5 rotate ·
S6 canonical fold (order-independent root) · S8 witness binds the call set ·
S9 self-kill by possession · S10 ACT/AMEND split · S11 fail-closed unknown authority ·
E14 Tier-2 floor rejects a stale root · E15 expiry predicate · E16 threshold k-of-n ·
E20 chain-domain replay · E22 carried capability bound to the consumer.

## Measured (real EVM gas, this run)
- authorize(): 3,153–19,369 gas (avg 10,510) — deep inside MAX_VERIFY_GAS = 100,000.
- verifyMembership: 1,712 · leafOf: 1,254 · changeSet: 352 · selfKill: 38,781 (with SSTORE)
  · setSlotRoot: 66,249 (cold SSTORE).

## Provenance
Gas = real EVM (revm) for the contract logic, NOT the frame-tx protocol overhead.
Cross-client and consensus-layer end-to-end remain a Loop-2 item for when a frames
client/devnet is reachable.

Artifacts: src/ERC8403Verifier.sol, test/ERC8403.t.sol, this file.
