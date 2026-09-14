# ERC-8403 reference POC: measurements and simulation

Runnable reference implementations and test harnesses for **ERC-8403 Account Authority
Lifecycle**, the model-neutral add / rotate / revoke lifecycle for native
account-abstraction authorities, bound to EIP-8141 frame transactions and EIP-8130
keystore accounts.

- Spec (draft): https://github.com/ethereum/ERCs/pull/1979
- Discussion: https://ethereum-magicians.org/t/erc-8403-account-authority-lifecycle/29570

Three layers, each with its own provenance label:

**1. `poc/`: Python reference model.** Canonical key-addressed Merkle fold, the two
authorization tiers, the lifecycle, recovery, isolation, multichain, and the verifier
cost classes. 33 scenarios (11 core + 22 extended) plus 4 walls, each with a positive
control and a RED control. `run-report-full.txt` is the captured run.

**2. `evm/`: real-EVM verifier (Foundry / revm).** The ERC-8403 authorization step as a
Solidity contract with real `ecrecover` / `keccak`. 14 scenarios + 4 walls (`Walls.t.sol`).
Gas measured. See `RUN-REPORT.md`, `WALLS-REPORT.md`.

**3. `live/`: live frames-client.** The same check compiled to account bytecode (Yul +
EIP-8141 frame opcodes) and executed inside a real `VERIFY` frame on Nethermind, driven by
signed `0x06` frame-tx envelopes. Positive path + attack matrix. See `LASTMILE-REPORT.md`.

## Results (measured)

| item | value | provenance |
|---|---|---|
| `authorize()` (membership proof + ecrecover, the VERIFY-frame primitive) | 3,153-19,369 gas (avg 10,510) | measured (revm) |
| `verifyMembership` | 1,712 gas | measured (revm) |
| single-leaf VERIFY frame, live | 2,383 exec gas | measured (Nethermind) |
| `MAX_VERIFY_GAS` | 100,000 nominal / ~300,000 admitted | spec draft / measured (Nethermind) |
| scenarios | 33 python + 18 foundry + 13 live, each with a RED control | reproduced |
| walls | 4/4 demonstrated with their mitigation | reproduced |

## The four walls (known limits, not holes)

- **Drain-vs-revoke under PBS:** order-determined; no validation/fee mitigation. Revocation
  security is claimed only against a builder-neutral adversary.
- **Denial by self-kill:** possession of the record's key is the only check; mitigated by a
  mandatory second authority, bounded by "could have drained instead".
- **Tier-1 revocation latency:** bounded by the referencing mechanism's recency window;
  Tier-2 (own-slot read) revokes next-block.
- **Off-chain leaves + lost cache:** a hiding commitment cannot reconstruct its leaves; keep
  the tree enumerable on-chain so recovery is a re-read.

Each is demonstrated with its mitigation in `poc/` (analytic) and `evm/test/Walls.t.sol`
(real EVM). 4/4 pass.

## Honest scope / provenance

- **Solo-client, not cross-client.** The public ethrex frames devnet was offline during this
  run, so byte-for-byte agreement against ethrex is still pending devnet restore.
- Python-layer gas is **analytic** (a cost model over measured op counts). Foundry and
  live-client gas is **measured** on revm / Nethermind.
- **`MAX_VERIFY_GAS`**: the spec draft nominal is 100,000; the local Nethermind build admitted
  a validation prefix up to ~300,000 (measured), consistent with the floor-vs-headroom model
  in ethereum/EIPs#12301.
- Private keys in `live/` are the standard **anvil / hardhat deterministic test keys**
  (public, not secrets).
- The solo chain's chainspec is derived from the ethrex frames bundle and is **not
  redistributed here**; fetch it from `faucet.frames.ethrex.xyz` to reproduce layer 3.

## Run

One command runs both reproducible layers (bootstraps a venv and forge-std on first run):

```
./run_all.sh
```

Or run them directly:
- Python: `pip install -r poc/requirements.txt` then `python3 poc/erc8403_poc.py && python3 poc/erc8403_poc_ext.py`
- Foundry: `cd evm && forge test -vv` (needs `forge-std` in `evm/lib/`)

Layer 3 (`live/`) needs a running EIP-8141 frames client and is not run by `run_all.sh`.

Design-stage research artifact. Not audited; not for production.
