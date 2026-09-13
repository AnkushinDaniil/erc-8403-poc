// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

/// Reference on-chain realization of the ERC-8403 authorization step (the EIP-8141
/// VERIFY-frame check) and the ACT/AMEND lifecycle guard, for execution on a real EVM.
/// It models the authority axis only: membership of the acting authority under the
/// account's committed root, plus a witness that binds the action to that authority.
/// Frame envelopes, RECENTROOTREFLOAD and mempool admission are the consensus layer and
/// are out of this contract's scope.
contract ERC8403Verifier {
    uint8 constant KIND_KEY = 0;
    uint8 constant KIND_THRESHOLD = 1;
    uint8 constant CLS_ACT = 0;
    uint8 constant CLS_AMEND = 1;

    bytes32 public slotRoot;
    uint64 public floorSlot;
    mapping(bytes32 => bool) public killed;

    function setSlotRoot(bytes32 root, uint64 slot) external {
        require(slot >= floorSlot, "floor");
        slotRoot = root;
        floorSlot = slot;
    }

    function leafOf(
        bytes32 authorityId,
        uint8 kind,
        uint8 cls,
        uint64 expiry,
        bytes memory data
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(authorityId, kind, cls, expiry, keccak256(data)));
    }

    /// Canonical, position-free commutative Merkle fold: leaf order is not the writer's
    /// choice, so the same set yields the same root unconditionally.
    function verifyMembership(bytes32 root, bytes32 leaf, bytes32[] memory proof)
        public
        pure
        returns (bool)
    {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 s = proof[i];
            h = h <= s ? keccak256(abi.encodePacked(h, s)) : keccak256(abi.encodePacked(s, h));
        }
        return h == root;
    }

    function authDigest(
        uint64 nonce,
        bytes32 callsHash,
        bytes32 rootRef,
        bytes32 authorityId
    ) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), nonce, callsHash, rootRef, authorityId));
    }

    struct Auth {
        bytes32 authorityId;
        uint8 kind;
        uint8 cls;
        uint64 expiry;
        bytes data; // KEY: abi.encode(address); THRESHOLD: abi.encode(uint256 k, address[])
    }

    /// The VERIFY-frame check. tier 1 proves against the transaction-named root; tier 2
    /// reads the account's own slot and rejects a root reference other than the live slot.
    /// Returns true only when both the membership proof and the witness verify (fail-closed).
    function authorize(
        uint8 tier,
        bytes32 rootRef,
        uint64 nonce,
        bytes32 callsHash,
        Auth calldata a,
        bytes32[] calldata proof,
        bytes calldata witness
    ) external view returns (bool) {
        bytes32 root;
        if (tier == 2) {
            if (rootRef != slotRoot) return false;
            root = slotRoot;
        } else {
            root = rootRef;
        }

        bytes32 leaf = leafOf(a.authorityId, a.kind, a.cls, a.expiry, a.data);
        if (!verifyMembership(root, leaf, proof)) return false;
        if (killed[a.authorityId]) return false;
        if (a.expiry != 0 && block.timestamp > a.expiry) return false;

        bytes32 digest = authDigest(nonce, callsHash, rootRef, a.authorityId);
        return _witnessOk(a, digest, witness);
    }

    function _witnessOk(Auth calldata a, bytes32 digest, bytes calldata witness)
        internal
        pure
        returns (bool)
    {
        if (a.kind == KIND_KEY) {
            address signer = abi.decode(a.data, (address));
            (uint8 v, bytes32 r, bytes32 s) = abi.decode(witness, (uint8, bytes32, bytes32));
            return ecrecover(digest, v, r, s) == signer && signer != address(0);
        }
        if (a.kind == KIND_THRESHOLD) {
            (uint256 k, address[] memory signers) = abi.decode(a.data, (uint256, address[]));
            (uint8[] memory vs, bytes32[] memory rs, bytes32[] memory ss) =
                abi.decode(witness, (uint8[], bytes32[], bytes32[]));
            uint256 got;
            uint256 seen;
            for (uint256 i = 0; i < vs.length; i++) {
                address rec = ecrecover(digest, vs[i], rs[i], ss[i]);
                for (uint256 j = 0; j < signers.length; j++) {
                    if (signers[j] == rec && (seen & (1 << j)) == 0) {
                        seen |= (1 << j);
                        got++;
                        break;
                    }
                }
            }
            return got >= k;
        }
        return false;
    }

    /// A set change (add, replace, remove-other) MUST be authorized by an AMEND-class
    /// authority; an ACT-only authority MUST NOT change the set.
    function changeSet(Auth calldata actor) external pure returns (bool) {
        require(actor.cls == CLS_AMEND, "ACT cannot amend");
        return true;
    }

    /// Any authority may remove itself by a witness under its own key over a KILL message,
    /// with no AMEND authority. Owner/thief symmetry is deliberate: whoever holds the key
    /// can kill; the mitigation is a mandatory second authority, not a validation rule.
    function selfKill(bytes32 authorityId, address signer, bytes calldata witness) external {
        bytes32 msgHash = keccak256(abi.encode("KILL", block.chainid, address(this), authorityId));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(witness, (uint8, bytes32, bytes32));
        require(ecrecover(msgHash, v, r, s) == signer && signer != address(0), "bad kill sig");
        killed[authorityId] = true;
    }
}
