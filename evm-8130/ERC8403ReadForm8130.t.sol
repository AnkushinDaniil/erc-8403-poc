// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.36;

import {Keystore} from "../src/Keystore.sol";
import {KeystoreTest} from "./lib/KeystoreTest.sol";

contract ERC8403ReadForm8130 is KeystoreTest {
    function test_readForm_positive_and_red(uint256 pkSeed, bytes32 hash) public {
        uint256 pk = _boundK1Pk(pkSeed);
        (address account, bytes32 actorId) = _createK1Account(pk);

        (bytes32 got, uint16 scope) = keystore.authenticateActor(account, hash, _buildK1Auth(pk, hash));
        assertEq(got, actorId);
        assertEq(scope, uint16(0));

        uint256 other = _boundK1Pk(uint256(keccak256(abi.encode(pkSeed, "other"))));
        vm.assume(vm.addr(other) != vm.addr(pk));
        vm.expectRevert();
        keystore.authenticateActor(account, hash, _buildK1Auth(other, hash));
    }

    function test_readForm_accountKeyed_isolation(uint256 aSeed, uint256 bSeed, bytes32 hash) public {
        uint256 pkA = _boundK1Pk(aSeed);
        uint256 pkB = _boundK1Pk(uint256(keccak256(abi.encode(bSeed, "iso"))));
        vm.assume(vm.addr(pkA) != vm.addr(pkB));
        (address accountA,) = _createK1AccountWithSalt(pkA, bytes32(uint256(1)));
        (address accountB,) = _createK1AccountWithSalt(pkB, bytes32(uint256(2)));
        vm.assume(accountA != accountB);

        vm.expectRevert();
        keystore.authenticateActor(accountB, hash, _buildK1Auth(pkA, hash));
    }

    function test_readForm_revoke_instant(uint256 pkSeed, bytes32 hash) public {
        uint256 pk = _boundK1Pk(pkSeed);
        (address account,) = _createK1Account(pk);
        uint256 pk2 = _boundK1Pk(uint256(keccak256(abi.encode(pkSeed, "second"))));
        vm.assume(vm.addr(pk2) != vm.addr(pk));
        vm.assume(vm.addr(pk2) != account);
        bytes32 actorB = bytes32(uint256(uint160(vm.addr(pk2))));

        _authorizeActor(account, pk, actorB, address(k1Authenticator));
        (bytes32 got,) = keystore.authenticateActor(account, hash, _buildK1Auth(pk2, hash));
        assertEq(got, actorB);

        _revokeActor(account, pk, actorB);
        vm.expectRevert();
        keystore.authenticateActor(account, hash, _buildK1Auth(pk2, hash));
    }
}
