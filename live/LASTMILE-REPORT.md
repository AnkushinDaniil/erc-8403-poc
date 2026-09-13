# ERC-8403 last-mile: opcode-level account verifier on a live frames client

Isolated solo Nethermind `frames-clean` (chainId 81410, NethDev sealer, no CL, no public net).
Scope: the composition Foundry/Python could not reach — the 8403 authorization check compiled to
account bytecode and run inside a real EIP-8141 `VERIFY` frame on a live client, driven by real
signed 0x06 frame-tx envelopes. Membership depth kept small (single-leaf + one 2-leaf tree); the
canonical fold at scale is already proven in the Foundry (14/14) and Python (33) suites.

## The verifier (Yul, `verbatim` frame opcodes)
Account runtime (97 bytes) baked into genesis at `0x…CAfE8403/8402/8404`, committed root in slot 0.
In the VERIFY frame it: `TXPARAM(0x0A)` current frame idx -> `FRAMEDATALOAD` authority_id / predicate /
sibling -> `SIGPARAM(0x00)` resolved witness signer -> require signer==predicate (witness binds action)
-> leaf=keccak(aid||pred), membership vs slot-0 root (Tier-2 direct SLOAD of tx.sender storage, the
banned-opcode rules permit it) -> `APPROVE(EXECUTION_AND_PAYMENT)` on success, else revert (fail-closed).

## Results (each case = a real signed 0x06 tx, live)
Positive:
- P1 single-leaf self-verify + 0.5 ETH SENDER transfer: MINED, status 1, VER -0.5 / R +0.5. VERIFY frame exec gas 2383.
- P2 two-leaf membership (real sibling path): MINED, status 1.
Attacks (all correctly rejected/invalidated):
- A1 wrong witness key, A2 wrong authority_id, A3 wrong predicate, A4 tampered sibling,
  A6 isolation (auth vs foreign root), A7 wrong sibling on 2-leaf, A10 malformed short frame data
  -> validation-prefix frame reverted, tx invalid.
- A5 replay to different calls, A11 cross-account sig replay -> SECP256K1 signer != recovered (digest binds calls + sender).
- A9 non-frame eth_call to the account -> halts (frame-only, no bypass).
- A8 MAX_VERIFY_GAS wall: enforced. NM admission ceiling measured ≈300000 (last-admitted VERIFY limit
  296,875 + ~3,125 sig intrinsic); >≈297,656 rejected with "validation prefix exceeds MAX_VERIFY_GAS".
  Draft spec nominal is 100,000 — build/chainspec runs a higher headroom (consistent with the
  floor-vs-headroom model in ethereum/EIPs#12301).

## Provenance / honest scope
- Real EVM + real client: gas, ecrecover, keccak, opcode dispatch all live on Nethermind.
- Solo-client, NOT cross-client: public ethrex frames devnet is offline, so byte-for-byte agreement
  vs ethrex is still pending devnet restore.
- Genesis alloc funded my own keys and baked the verifier accounts; this is an isolated lab chain.
