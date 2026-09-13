// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC8403Verifier} from "../src/ERC8403Verifier.sol";

contract ERC8403Test is Test {
    ERC8403Verifier v;

    uint8 constant KEY = 0;
    uint8 constant THRESH = 1;
    uint8 constant ACT = 0;
    uint8 constant AMEND = 1;

    function setUp() public {
        v = new ERC8403Verifier();
    }

    function _h(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a <= b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _root(bytes32[] memory leaves) internal pure returns (bytes32) {
        bytes32[] memory level = leaves;
        while (level.length > 1) {
            uint256 n = (level.length + 1) / 2;
            bytes32[] memory next = new bytes32[](n);
            for (uint256 i = 0; i < n; i++) {
                next[i] = (2 * i + 1 < level.length) ? _h(level[2 * i], level[2 * i + 1]) : level[2 * i];
            }
            level = next;
        }
        return level.length == 1 ? level[0] : bytes32(0);
    }

    function _proof(bytes32[] memory leaves, uint256 idx) internal pure returns (bytes32[] memory) {
        bytes32[] memory tmp = new bytes32[](32);
        uint256 cnt;
        bytes32[] memory level = leaves;
        uint256 index = idx;
        while (level.length > 1) {
            uint256 sib = index ^ 1;
            if (sib < level.length) tmp[cnt++] = level[sib];
            uint256 n = (level.length + 1) / 2;
            bytes32[] memory next = new bytes32[](n);
            for (uint256 i = 0; i < n; i++) {
                next[i] = (2 * i + 1 < level.length) ? _h(level[2 * i], level[2 * i + 1]) : level[2 * i];
            }
            level = next;
            index /= 2;
        }
        bytes32[] memory out = new bytes32[](cnt);
        for (uint256 i = 0; i < cnt; i++) out[i] = tmp[i];
        return out;
    }

    function _keyAuth(bytes32 aid, uint8 cls, uint64 expiry, address signer)
        internal
        pure
        returns (ERC8403Verifier.Auth memory a)
    {
        a.authorityId = aid;
        a.kind = KEY;
        a.cls = cls;
        a.expiry = expiry;
        a.data = abi.encode(signer);
    }

    function _leaf(ERC8403Verifier.Auth memory a) internal view returns (bytes32) {
        return v.leafOf(a.authorityId, a.kind, a.cls, a.expiry, a.data);
    }

    // Build a 4-leaf set with the acting authority at index 0.
    function _set4(bytes32 actingLeaf) internal pure returns (bytes32[] memory s) {
        s = new bytes32[](4);
        s[0] = actingLeaf;
        s[1] = keccak256("filler-1");
        s[2] = keccak256("filler-2");
        s[3] = keccak256("filler-3");
    }

    function _sig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encode(vv, r, s);
    }

    // S1 home act (Tier 2): valid witness authorizes; wrong witness rejected.
    function test_S1_homeActTier2() public {
        uint256 pk = 0xA11CE;
        ERC8403Verifier.Auth memory a = _keyAuth(keccak256("id_A"), ACT, 0, vm.addr(pk));
        bytes32[] memory set = _set4(_leaf(a));
        bytes32 root = _root(set);
        v.setSlotRoot(root, 10);
        bytes32[] memory proof = _proof(set, 0);
        bytes32 ch = keccak256("transfer(bob,1)");
        bytes32 dg = v.authDigest(0, ch, root, a.authorityId);

        assertTrue(v.authorize(2, root, 0, ch, a, proof, _sig(pk, dg)), "positive");
        assertFalse(v.authorize(2, root, 0, ch, a, proof, _sig(0xBEEF, dg)), "RED wrong key");
    }

    // S2 membership and witness are independent: a valid witness with a broken proof fails.
    function test_S2_proofWitnessIndependence() public {
        uint256 pk = 0xA11CE;
        ERC8403Verifier.Auth memory a = _keyAuth(keccak256("id_A"), ACT, 0, vm.addr(pk));
        bytes32[] memory set = _set4(_leaf(a));
        bytes32 root = _root(set);
        v.setSlotRoot(root, 10);
        bytes32[] memory proof = _proof(set, 0);
        bytes32 ch = keccak256("c");
        bytes memory w = _sig(pk, v.authDigest(0, ch, root, a.authorityId));

        assertTrue(v.authorize(2, root, 0, ch, a, proof, w), "positive");
        proof[0] = keccak256("garbage");
        assertFalse(v.authorize(2, root, 0, ch, a, proof, w), "RED broken proof");
    }

    // S4 isolation: A's proof does not verify under B's root.
    function test_S4_isolation() public {
        uint256 pk = 0xA11CE;
        ERC8403Verifier.Auth memory a = _keyAuth(keccak256("id_A"), ACT, 0, vm.addr(pk));
        bytes32[] memory setA = _set4(_leaf(a));
        bytes32 rootA = _root(setA);
        bytes32 rootB = keccak256("account-B-root");
        v.setSlotRoot(rootA, 10);
        bytes32[] memory proof = _proof(setA, 0);
        bytes32 ch = keccak256("c");

        assertTrue(v.authorize(1, rootA, 0, ch, a, proof, _sig(pk, v.authDigest(0, ch, rootA, a.authorityId))), "positive");
        assertFalse(v.authorize(1, rootB, 0, ch, a, proof, _sig(pk, v.authDigest(0, ch, rootB, a.authorityId))), "RED foreign root");
    }

    // S5 rotate binds a new key to the same slot; the old predicate no longer verifies.
    function test_S5_rotate() public {
        uint256 pk1 = 0xA11CE;
        uint256 pk2 = 0xB0B;
        bytes32 aid = keccak256("id_A");
        ERC8403Verifier.Auth memory oldA = _keyAuth(aid, ACT, 0, vm.addr(pk1));
        ERC8403Verifier.Auth memory newA = _keyAuth(aid, ACT, 0, vm.addr(pk2));
        bytes32[] memory setNew = _set4(_leaf(newA));
        bytes32 root = _root(setNew);
        v.setSlotRoot(root, 20);
        bytes32[] memory proof = _proof(setNew, 0);
        bytes32 ch = keccak256("c");

        assertTrue(v.authorize(2, root, 1, ch, newA, proof, _sig(pk2, v.authDigest(1, ch, root, aid))), "positive new key");
        assertFalse(v.authorize(2, root, 1, ch, oldA, proof, _sig(pk1, v.authDigest(1, ch, root, aid))), "RED old predicate");
    }

    // S6/E13 canonical fold: insertion order is irrelevant; the same set yields the same root.
    function test_S6_canonicalFold() public {
        bytes32 l0 = keccak256("a");
        bytes32 l1 = keccak256("b");
        bytes32 l2 = keccak256("c");
        bytes32 l3 = keccak256("d");
        bytes32[] memory o1 = new bytes32[](4);
        (o1[0], o1[1], o1[2], o1[3]) = (l0, l1, l2, l3);
        bytes32[] memory o2 = new bytes32[](4);
        (o2[0], o2[1], o2[2], o2[3]) = (l2, l0, l3, l1);
        // sort both to the canonical position-free order before folding
        assertTrue(v.verifyMembership(_root(_sorted(o1)), l0, _proof(_sorted(o1), _idx(_sorted(o1), l0))), "positive membership");
        assertEq(_root(_sorted(o1)), _root(_sorted(o2)), "same set same root");
        bytes32[] memory changed = new bytes32[](4);
        (changed[0], changed[1], changed[2], changed[3]) = (l0, l1, l2, keccak256("d-CHANGED"));
        assertTrue(_root(_sorted(o1)) != _root(_sorted(changed)), "RED changed leaf");
    }

    // S8 witness binds the full call set: a witness over one call set fails against another.
    function test_S8_witnessBindsCalls() public {
        uint256 pk = 0xA11CE;
        ERC8403Verifier.Auth memory a = _keyAuth(keccak256("id_A"), ACT, 0, vm.addr(pk));
        bytes32[] memory set = _set4(_leaf(a));
        bytes32 root = _root(set);
        v.setSlotRoot(root, 10);
        bytes32[] memory proof = _proof(set, 0);
        bytes32 ch1 = keccak256("transfer(bob,1)");
        bytes32 ch2 = keccak256("transfer(eve,1000)");
        bytes memory w1 = _sig(pk, v.authDigest(0, ch1, root, a.authorityId));

        assertTrue(v.authorize(2, root, 0, ch1, a, proof, w1), "positive");
        assertFalse(v.authorize(2, root, 0, ch2, a, proof, w1), "RED replay to other calls");
    }

    // E20 witness is chain-domain bound: it does not replay under another chain id.
    function test_E20_chainDomain() public {
        uint256 pk = 0xA11CE;
        ERC8403Verifier.Auth memory a = _keyAuth(keccak256("id_A"), ACT, 0, vm.addr(pk));
        bytes32[] memory set = _set4(_leaf(a));
        bytes32 root = _root(set);
        v.setSlotRoot(root, 10);
        bytes32[] memory proof = _proof(set, 0);
        bytes32 ch = keccak256("c");

        vm.chainId(1);
        bytes memory w = _sig(pk, v.authDigest(0, ch, root, a.authorityId));
        assertTrue(v.authorize(2, root, 0, ch, a, proof, w), "positive chain 1");
        vm.chainId(2);
        assertFalse(v.authorize(2, root, 0, ch, a, proof, w), "RED replay chain 2");
    }

    // S9 self-kill by possession: own key removes the authority; a stranger cannot.
    function test_S9_selfKill() public {
        uint256 pk = 0xA11CE;
        bytes32 aid = keccak256("id_A");
        address signer = vm.addr(pk);
        ERC8403Verifier.Auth memory a = _keyAuth(aid, ACT, 0, signer);
        bytes32[] memory set = _set4(_leaf(a));
        bytes32 root = _root(set);
        v.setSlotRoot(root, 10);
        bytes32[] memory proof = _proof(set, 0);
        bytes32 ch = keccak256("c");
        assertTrue(v.authorize(2, root, 0, ch, a, proof, _sig(pk, v.authDigest(0, ch, root, aid))), "pre-kill authorized");

        bytes32 killMsg = keccak256(abi.encode("KILL", block.chainid, address(v), aid));
        v.selfKill(aid, signer, _sig(pk, killMsg));
        assertFalse(v.authorize(2, root, 0, ch, a, proof, _sig(pk, v.authDigest(0, ch, root, aid))), "RED authorized after kill");

        vm.expectRevert(bytes("bad kill sig"));
        v.selfKill(keccak256("id_B"), signer, _sig(0xBEEF, keccak256(abi.encode("KILL", block.chainid, address(v), keccak256("id_B")))));
    }

    // S10 ACT/AMEND split: AMEND may change the set; ACT-only may not.
    function test_S10_actAmendSplit() public {
        ERC8403Verifier.Auth memory amend = _keyAuth(keccak256("id_M"), AMEND, 0, address(1));
        ERC8403Verifier.Auth memory act = _keyAuth(keccak256("id_A"), ACT, 0, address(2));
        assertTrue(v.changeSet(amend), "positive AMEND");
        vm.expectRevert(bytes("ACT cannot amend"));
        v.changeSet(act);
    }

    // S11 fail-closed: an authority never in the set cannot authorize.
    function test_S11_failClosedUnknown() public {
        uint256 pk = 0xA11CE;
        ERC8403Verifier.Auth memory a = _keyAuth(keccak256("id_A"), ACT, 0, vm.addr(pk));
        bytes32[] memory set = _set4(_leaf(a));
        bytes32 root = _root(set);
        v.setSlotRoot(root, 10);
        bytes32 ch = keccak256("c");
        assertTrue(v.authorize(2, root, 0, ch, a, _proof(set, 0), _sig(pk, v.authDigest(0, ch, root, a.authorityId))), "positive");

        ERC8403Verifier.Auth memory unknown = _keyAuth(keccak256("never"), ACT, 0, vm.addr(pk));
        bytes32[] memory empty = new bytes32[](0);
        assertFalse(v.authorize(2, root, 0, ch, unknown, empty, _sig(pk, v.authDigest(0, ch, root, unknown.authorityId))), "RED unknown authority");
    }

    // E15 expiry predicate: accepts before the unlock time, rejects after.
    function test_E15_expiry() public {
        uint256 pk = 0xA11CE;
        uint64 expiry = uint64(block.timestamp + 1000);
        ERC8403Verifier.Auth memory a = _keyAuth(keccak256("id_A"), ACT, expiry, vm.addr(pk));
        bytes32[] memory set = _set4(_leaf(a));
        bytes32 root = _root(set);
        v.setSlotRoot(root, 10);
        bytes32[] memory proof = _proof(set, 0);
        bytes32 ch = keccak256("c");
        bytes memory w = _sig(pk, v.authDigest(0, ch, root, a.authorityId));

        assertTrue(v.authorize(2, root, 0, ch, a, proof, w), "positive before expiry");
        vm.warp(block.timestamp + 2000);
        assertFalse(v.authorize(2, root, 0, ch, a, proof, w), "RED past expiry");
    }

    // E16 threshold k-of-n: k signatures accept, k-1 reject.
    function test_E16_threshold() public {
        uint256 pk1 = 0x1;
        uint256 pk2 = 0x2;
        uint256 pk3 = 0x3;
        address[] memory signers = new address[](3);
        (signers[0], signers[1], signers[2]) = (vm.addr(pk1), vm.addr(pk2), vm.addr(pk3));
        ERC8403Verifier.Auth memory a;
        a.authorityId = keccak256("id_T");
        a.kind = THRESH;
        a.cls = ACT;
        a.expiry = 0;
        a.data = abi.encode(uint256(2), signers);
        bytes32[] memory set = _set4(_leaf(a));
        bytes32 root = _root(set);
        v.setSlotRoot(root, 10);
        bytes32[] memory proof = _proof(set, 0);
        bytes32 ch = keccak256("c");
        bytes32 dg = v.authDigest(0, ch, root, a.authorityId);

        assertTrue(v.authorize(2, root, 0, ch, a, proof, _thresholdWitness(dg, pk1, pk2)), "positive 2-of-3");
        assertFalse(v.authorize(2, root, 0, ch, a, proof, _thresholdWitnessOne(dg, pk1)), "RED 1-of-3");
    }

    // E14/Tier2 floor: after the account raises its slot root, a stale root reference is rejected.
    function test_E14_tier2FloorRejectsStaleRoot() public {
        uint256 pk = 0xA11CE;
        ERC8403Verifier.Auth memory a = _keyAuth(keccak256("id_A"), ACT, 0, vm.addr(pk));
        bytes32[] memory set = _set4(_leaf(a));
        bytes32 root = _root(set);
        v.setSlotRoot(root, 10);
        bytes32[] memory proof = _proof(set, 0);
        bytes32 ch = keccak256("c");
        assertTrue(v.authorize(2, root, 0, ch, a, proof, _sig(pk, v.authDigest(0, ch, root, a.authorityId))), "positive current root");

        bytes32 newRoot = keccak256("rotated-root");
        v.setSlotRoot(newRoot, 11);
        assertFalse(v.authorize(2, root, 0, ch, a, proof, _sig(pk, v.authDigest(0, ch, root, a.authorityId))), "RED stale root under Tier 2");
    }

    // E22 carried capability bound to the consumer: a witness for one account fails on another.
    function test_E22_capabilityBinding() public {
        ERC8403Verifier vB = new ERC8403Verifier();
        uint256 pk = 0xCA9;
        ERC8403Verifier.Auth memory a = _keyAuth(keccak256("cap"), ACT, 0, vm.addr(pk));
        bytes32[] memory set = _set4(_leaf(a));
        bytes32 root = _root(set);
        v.setSlotRoot(root, 10);
        vB.setSlotRoot(root, 10);
        bytes32[] memory proof = _proof(set, 0);
        bytes32 ch = keccak256("c");
        bytes memory w = _sig(pk, v.authDigest(0, ch, root, a.authorityId)); // signed for consumer v

        assertTrue(v.authorize(2, root, 0, ch, a, proof, w), "positive on grantee A");
        assertFalse(vB.authorize(2, root, 0, ch, a, proof, w), "RED same capability on account B");
    }

    // --- helpers for arrays / threshold witnesses ---

    function _sorted(bytes32[] memory arr) internal pure returns (bytes32[] memory) {
        bytes32[] memory a = arr;
        for (uint256 i = 0; i < a.length; i++) {
            for (uint256 j = i + 1; j < a.length; j++) {
                if (a[j] < a[i]) (a[i], a[j]) = (a[j], a[i]);
            }
        }
        return a;
    }

    function _idx(bytes32[] memory arr, bytes32 x) internal pure returns (uint256) {
        for (uint256 i = 0; i < arr.length; i++) if (arr[i] == x) return i;
        revert("not found");
    }

    function _thresholdWitness(bytes32 dg, uint256 pkA, uint256 pkB) internal pure returns (bytes memory) {
        uint8[] memory vs = new uint8[](2);
        bytes32[] memory rs = new bytes32[](2);
        bytes32[] memory ss = new bytes32[](2);
        (vs[0], rs[0], ss[0]) = vm.sign(pkA, dg);
        (vs[1], rs[1], ss[1]) = vm.sign(pkB, dg);
        return abi.encode(vs, rs, ss);
    }

    function _thresholdWitnessOne(bytes32 dg, uint256 pkA) internal pure returns (bytes memory) {
        uint8[] memory vs = new uint8[](1);
        bytes32[] memory rs = new bytes32[](1);
        bytes32[] memory ss = new bytes32[](1);
        (vs[0], rs[0], ss[0]) = vm.sign(pkA, dg);
        return abi.encode(vs, rs, ss);
    }
}
