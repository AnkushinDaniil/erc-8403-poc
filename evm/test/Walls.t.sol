// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/ERC8403Verifier.sol";

contract WallsTest is Test {
    ERC8403Verifier v;

    uint256 constant KX = 0xA11CE;
    uint256 constant KM = 0xB0B;
    uint256 constant KD = 0xDEAD;

    address AX;
    address AM;
    address AD;
    bytes32 idX = keccak256("id_X");
    bytes32 idM = keccak256("id_M");
    bytes32 idD = keccak256("id_D");
    bytes32 leafX;
    bytes32 leafM;
    bytes32 leafD;
    bytes32 R0;
    bytes32 R1;

    function setUp() public {
        v = new ERC8403Verifier();
        AX = vm.addr(KX);
        AM = vm.addr(KM);
        AD = vm.addr(KD);
        leafX = v.leafOf(idX, 0, 0, 0, abi.encode(AX));
        leafM = v.leafOf(idM, 0, 1, 0, abi.encode(AM));
        leafD = v.leafOf(idD, 0, 0, 0, abi.encode(AD));
        R0 = _commit(leafX, leafM);
        R1 = _commit(leafM, leafD);
        v.setSlotRoot(R0, 1);
    }

    function _commit(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a <= b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _auth(bytes32 id, uint8 cls, address key) internal pure returns (ERC8403Verifier.Auth memory a) {
        a.authorityId = id;
        a.kind = 0;
        a.cls = cls;
        a.expiry = 0;
        a.data = abi.encode(key);
    }

    function _sig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encode(vv, r, s);
    }

    function _drainOk(uint8 tier, bytes32 rootRef, bytes32 sibling) internal view returns (bool) {
        ERC8403Verifier.Auth memory a = _auth(idX, 0, AX);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;
        bytes32 dg = v.authDigest(0, keccak256("drain(all)"), rootRef, idX);
        return v.authorize(tier, rootRef, 0, keccak256("drain(all)"), a, proof, _sig(KX, dg));
    }

    // WALL 1 - drain-vs-revoke ordering under PBS (spec L201; honest verdict).
    // The revoke and the drain are two operations; whichever the builder orders first wins.
    // No validation or fee rule reorders the revoke ahead of the drain.
    function test_W1_drainVsRevoke_orderDecides() public {
        // Order A: drain lands while the old root is still committed.
        bool drainFirst = _drainOk(2, R0, leafM);

        // Order B: fresh account, revoke first (raise the floor to R1 without X), then the same drain.
        ERC8403Verifier v2 = new ERC8403Verifier();
        v = v2;
        leafX = v.leafOf(idX, 0, 0, 0, abi.encode(AX));
        leafM = v.leafOf(idM, 0, 1, 0, abi.encode(AM));
        leafD = v.leafOf(idD, 0, 0, 0, abi.encode(AD));
        R0 = _commit(leafX, leafM);
        R1 = _commit(leafM, leafD);
        v.setSlotRoot(R0, 1);
        v.setSlotRoot(R1, 2); // revoke: new committed root excludes X
        bool drainAfterRevoke = _drainOk(2, R0, leafM); // stale root reference

        assertTrue(drainFirst, "order A: drain lands when ordered first");
        assertFalse(drainAfterRevoke, "order B: same drain fails when revoke is ordered first");
        emit log_string("WALL W1: outcome is purely order-determined; PBS builder picks the order.");
        emit log_string("  mitigation: none at validation/fee layer; claim revocation vs a builder-neutral adversary.");
    }

    // WALL 2 - denial by self-kill (owner/thief symmetry).
    // Possession of the record's key is the only check, so a thief can kill the record (grief).
    function test_W2_selfKill_symmetry() public {
        // thief holds the stolen key KX and kills authority X - identical to what the owner would do.
        bytes32 killMsg = keccak256(abi.encode("KILL", block.chainid, address(v), idX));
        v.selfKill(idX, AX, _sig(KX, killMsg));
        assertTrue(v.killed(idX), "thief-key self-kill removes X (grief succeeds)");

        // X can no longer act (denial).
        assertFalse(_drainOk(2, R0, leafM), "killed authority X no longer authorizes");

        // mitigation: a mandatory second authority keeps the account alive.
        ERC8403Verifier.Auth memory m = _auth(idM, 1, AM);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leafX;
        bytes32 dg = v.authDigest(0, keccak256("act"), R0, idM);
        assertTrue(v.authorize(2, R0, 0, keccak256("act"), m, proof, _sig(KM, dg)), "second authority M still authorizes");
        emit log_string("WALL W2: whoever holds the key can self-kill; bounded by 'could have drained instead'.");
        emit log_string("  mitigation: a mandatory second authority, not a validation rule.");
    }

    // WALL 3 - Tier-1 revocation latency = the recency window (spec L71, L201, L203).
    // Tier 1 verifies against whatever root the tx names, so a revoked leaf's old root still
    // passes until the external mechanism ages it out. Tier 2 reads the live slot and stops it now.
    function test_W3_tier1_recencyWindow_vs_tier2_instant() public {
        v.setSlotRoot(R1, 2); // revoke X: live committed root is now R1 (no X)

        // Tier 2 (own-slot): the stale root R0 is rejected in the same block - instant revocation.
        assertFalse(_drainOk(2, R0, leafM), "tier2: stale root rejected instantly");

        // Tier 1 (root-bound): the same stale root R0 still verifies - it is only stopped once the
        // recency window evicts it. This is the wall: revocation latency up to the window.
        assertTrue(_drainOk(1, R0, leafM), "tier1: stale root R0 still verifies within the window");

        emit log_string("WALL W3: Tier-1 revocation latency is the recency window (L71/L203).");
        emit log_string("  mitigation: emergency revocation MUST use Tier 2 (own-slot, next-block).");
    }

    // WALL 4 - off-chain leaves + lost cache (spec L188, L210, L212).
    // A committed root is a hiding commitment: it verifies a proof but cannot reconstruct the
    // leaves. With the leaves on-chain, recovery is a re-read; off-chain with a lost cache, no
    // membership proof can be built and the authority cannot act even though the root stays valid.
    function test_W4_dataAvailability_lostCache() public view {
        // Enumerable on-chain: rebuild the sibling and authorize - recovery is a re-read.
        assertTrue(_drainOk(2, R0, leafM), "on-chain leaves: proof rebuilt, authorize succeeds");

        // Lost cache: without the sibling leaf, no valid proof exists.
        assertFalse(_drainOk(2, R0, bytes32(0)), "lost cache: empty sibling -> no valid proof");
        assertFalse(_drainOk(2, R0, keccak256("guess")), "lost cache: guessed sibling -> no valid proof");
        // The root alone cannot yield the sibling (hiding commitment); only the leaf set can.
    }
}
