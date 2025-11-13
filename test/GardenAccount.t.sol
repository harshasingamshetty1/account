// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./Base.t.sol";
import {GardenAccount} from "../src/GardenAccount.sol";
import {IthacaAccount} from "../src/IthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";

contract GardenAccountTest is BaseTest {
    using LibBytes for *;

    GardenAccount gardenAccount;
    PassKey adminKey;
    PassKey nonSuperAdminKey;
    address testAddress1;
    address testAddress2;

    function setUp() public override {
        super.setUp();

        // Deploy GardenAccount with super admin key
        adminKey = _randomSecp256k1PassKey();
        adminKey.k.isSuperAdmin = true;

        gardenAccount = new GardenAccount(address(oc), adminKey.k);

        // Create a non-super admin key for testing unauthorized access
        nonSuperAdminKey = _randomSecp256k1PassKey();
        nonSuperAdminKey.k.isSuperAdmin = false;

        // Authorize the non-super admin key through execute (using adminKey signature)
        ERC7821.Call[] memory authCalls = new ERC7821.Call[](1);
        authCalls[0].data = abi.encodeWithSelector(IthacaAccount.authorize.selector, nonSuperAdminKey.k);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(authCalls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        bytes memory executionData = abi.encode(authCalls, opData);

        address adminAddr = vm.addr(adminKey.privateKey);
        vm.prank(adminAddr);
        gardenAccount.execute(authCalls, opData);

        // Setup test addresses
        testAddress1 = _randomUniqueHashedAddress();
        testAddress2 = _randomUniqueHashedAddress();
    }

    // ============ Super Admin Verification ============

    function testAdminKeyIsSetAsSuperAdmin() public {
        // Get the admin key from the account
        bytes32 adminKeyHash = _hash(adminKey.k);
        IthacaAccount.Key memory retrievedKey = gardenAccount.getKey(adminKeyHash);
        
        assertTrue(retrievedKey.isSuperAdmin, "Admin key should be marked as super admin");
        assertEq(uint8(retrievedKey.keyType), uint8(adminKey.k.keyType), "Key type should match");
        assertEq(keccak256(retrievedKey.publicKey), keccak256(adminKey.k.publicKey), "Public key should match");
    }

    function testNonSuperAdminKeyIsNotSuperAdmin() public {
        bytes32 nonAdminKeyHash = nonSuperAdminKey.keyHash;
        IthacaAccount.Key memory retrievedKey = gardenAccount.getKey(nonAdminKeyHash);
        
        assert(!retrievedKey.isSuperAdmin);
    }

    // ============ Super Admin Success Cases ============

    function testSuperAdminCanWhitelistAddress() public {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data = abi.encodeWithSelector(
            GardenAccount.whitelistAddress.selector,
            testAddress1
        );

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        bytes memory executionData = abi.encode(calls, opData);

        gardenAccount.execute(calls, opData);

        assertTrue(gardenAccount.whitelistedAddresses(testAddress1), "Address should be whitelisted");
        assertEq(gardenAccount.whitelistingTimestamps(testAddress1), block.timestamp, "Timestamp should be set");
    }

    function testSuperAdminCanRemoveWhitelistedAddress() public {
        // First whitelist the address
        ERC7821.Call[] memory whitelistCalls = new ERC7821.Call[](1);
        whitelistCalls[0].data = abi.encodeWithSelector(
            GardenAccount.whitelistAddress.selector,
            testAddress1
        );

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(whitelistCalls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        bytes memory executionData = abi.encode(whitelistCalls, opData);

        gardenAccount.execute(whitelistCalls, opData);

        // Now remove the whitelisted address
        ERC7821.Call[] memory removeCalls = new ERC7821.Call[](1);
        removeCalls[0].data = abi.encodeWithSelector(
            GardenAccount.removeWhitelistedAddress.selector,
            testAddress1
        );

        nonce = gardenAccount.getNonce(0);
        signature = _sig(adminKey, gardenAccount.computeDigest(removeCalls, nonce));
        opData = abi.encodePacked(nonce, signature);
        executionData = abi.encode(removeCalls, opData);

        gardenAccount.execute(removeCalls, opData);

        assert(!gardenAccount.whitelistedAddresses(testAddress1));
        assertEq(gardenAccount.whitelistingTimestamps(testAddress1), 0, "Timestamp should be reset");
    }

    function testSuperAdminCanChangeCooldownPeriod() public {
        uint256 newCooldownPeriod = 7 days;

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data = abi.encodeWithSelector(
            GardenAccount.changeCooldownPeriod.selector,
            newCooldownPeriod
        );

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        bytes memory executionData = abi.encode(calls, opData);

        gardenAccount.execute(calls, opData);

        assertEq(gardenAccount.cooldownPeriod(), newCooldownPeriod, "Cooldown period should be updated");
    }

    function testSuperAdminCanWhitelistMultipleAddresses() public {
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0].data = abi.encodeWithSelector(
            GardenAccount.whitelistAddress.selector,
            testAddress1
        );
        calls[1].data = abi.encodeWithSelector(
            GardenAccount.whitelistAddress.selector,
            testAddress2
        );

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        bytes memory executionData = abi.encode(calls, opData);

        gardenAccount.execute(calls, opData);

        assertTrue(gardenAccount.whitelistedAddresses(testAddress1), "Address1 should be whitelisted");
        assertTrue(gardenAccount.whitelistedAddresses(testAddress2), "Address2 should be whitelisted");
    }

    function testSuperAdminCanCombineWhitelistAndCooldownChanges() public {
        uint256 newCooldownPeriod = 3 days;

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0].data = abi.encodeWithSelector(
            GardenAccount.whitelistAddress.selector,
            testAddress1
        );
        calls[1].data = abi.encodeWithSelector(
            GardenAccount.changeCooldownPeriod.selector,
            newCooldownPeriod
        );

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        bytes memory executionData = abi.encode(calls, opData);

        gardenAccount.execute(calls, opData);

        assertTrue(gardenAccount.whitelistedAddresses(testAddress1), "Address should be whitelisted");
        assertEq(gardenAccount.cooldownPeriod(), newCooldownPeriod, "Cooldown period should be updated");
    }

    // ============ Non-Super Admin Revert Cases ============

    function testNonSuperAdminCannotWhitelistAddress() public {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data = abi.encodeWithSelector(
            GardenAccount.whitelistAddress.selector,
            testAddress1
        );

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(nonSuperAdminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        bytes memory executionData = abi.encode(calls, opData);

        vm.expectRevert();
        gardenAccount.execute(calls, opData);

        assertFalse(gardenAccount.whitelistedAddresses(testAddress1), "Address should not be whitelisted");
    }

    function testNonSuperAdminCannotRemoveWhitelistedAddress() public {
        // First, super admin whitelists the address
        ERC7821.Call[] memory whitelistCalls = new ERC7821.Call[](1);
        whitelistCalls[0].data = abi.encodeWithSelector(
            GardenAccount.whitelistAddress.selector,
            testAddress1
        );

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(whitelistCalls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        bytes memory executionData = abi.encode(whitelistCalls, opData);

        gardenAccount.execute(whitelistCalls, opData);

        // Now non-super admin tries to remove it
        ERC7821.Call[] memory removeCalls = new ERC7821.Call[](1);
        removeCalls[0].data = abi.encodeWithSelector(
            GardenAccount.removeWhitelistedAddress.selector,
            testAddress1
        );

        nonce = gardenAccount.getNonce(0);
        signature = _sig(nonSuperAdminKey, gardenAccount.computeDigest(removeCalls, nonce));
        opData = abi.encodePacked(nonce, signature);
        executionData = abi.encode(removeCalls, opData);

        vm.expectRevert();
        gardenAccount.execute(removeCalls, opData);

        assertTrue(gardenAccount.whitelistedAddresses(testAddress1), "Address should still be whitelisted");
    }

    function testNonSuperAdminCannotChangeCooldownPeriod() public {
        uint256 originalCooldownPeriod = gardenAccount.cooldownPeriod();
        uint256 newCooldownPeriod = 7 days;

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data = abi.encodeWithSelector(
            GardenAccount.changeCooldownPeriod.selector,
            newCooldownPeriod
        );

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(nonSuperAdminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        bytes memory executionData = abi.encode(calls, opData);

        vm.expectRevert();
        gardenAccount.execute(calls, opData);

        assertEq(gardenAccount.cooldownPeriod(), originalCooldownPeriod, "Cooldown period should not change");
    }

    function testUnauthorizedKeyCannotWhitelistAddress() public {
        PassKey memory unauthorizedKey = _randomSecp256k1PassKey();
        unauthorizedKey.k.isSuperAdmin = false;

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data = abi.encodeWithSelector(
            GardenAccount.whitelistAddress.selector,
            testAddress1
        );

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(unauthorizedKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        bytes memory executionData = abi.encode(calls, opData);

        vm.expectRevert();
        gardenAccount.execute(calls, opData);

        assertFalse(gardenAccount.whitelistedAddresses(testAddress1), "Address should not be whitelisted");
    }

    function testDirectCallToWhitelistAddressReverts() public {
        address randomCaller = _randomUniqueHashedAddress();
        vm.prank(randomCaller);
        vm.expectRevert();
        gardenAccount.whitelistAddress(testAddress1);
    }

    function testDirectCallToRemoveWhitelistedAddressReverts() public {
        address randomCaller = _randomUniqueHashedAddress();
        vm.prank(randomCaller);
        vm.expectRevert();
        gardenAccount.removeWhitelistedAddress(testAddress1);
    }

    function testDirectCallToChangeCooldownPeriodReverts() public {
        address randomCaller = _randomUniqueHashedAddress();
        vm.prank(randomCaller);
        vm.expectRevert();
        gardenAccount.changeCooldownPeriod(7 days);
    }

    function testExternalAddressCannotWhitelistAddress() public {
        address externalAddress = _randomUniqueHashedAddress();
        vm.deal(externalAddress, 1 ether);
        
        vm.prank(externalAddress);
        vm.expectRevert();
        gardenAccount.whitelistAddress(testAddress1);
    }

    function testExternalAddressCannotChangeCooldownPeriod() public {
        address externalAddress = _randomUniqueHashedAddress();
        vm.deal(externalAddress, 1 ether);
        
        vm.prank(externalAddress);
        vm.expectRevert();
        gardenAccount.changeCooldownPeriod(7 days);
    }

    // ============ Fuzz Tests ============

    function testFuzzSuperAdminCanWhitelistAnyAddress(address addr) public {
        vm.assume(addr != address(0));
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data = abi.encodeWithSelector(
            GardenAccount.whitelistAddress.selector,
            addr
        );

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        bytes memory executionData = abi.encode(calls, opData);

        gardenAccount.execute(calls, opData);

        assertTrue(gardenAccount.whitelistedAddresses(addr), "Address should be whitelisted");
    }

    function testFuzzSuperAdminCanSetAnyCooldownPeriod(uint256 newCooldown) public {
        // Bound to reasonable values to avoid overflow issues
        newCooldown = bound(newCooldown, 1, 365 days);

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data = abi.encodeWithSelector(
            GardenAccount.changeCooldownPeriod.selector,
            newCooldown
        );

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        bytes memory executionData = abi.encode(calls, opData);

        gardenAccount.execute(calls, opData);

        assertEq(gardenAccount.cooldownPeriod(), newCooldown, "Cooldown period should be updated");
    }

    function testFuzzNonSuperAdminCannotWhitelistAnyAddress(bytes32 seed, address addr) public {
        // Create a random non-super admin key
        PassKey memory randomKey = _randomSecp256k1PassKey();
        randomKey.k.isSuperAdmin = false;

        // Authorize the random key through execute (using adminKey signature)
        ERC7821.Call[] memory authCalls = new ERC7821.Call[](1);
        authCalls[0].data = abi.encodeWithSelector(IthacaAccount.authorize.selector, randomKey.k);

        uint256 authNonce = gardenAccount.getNonce(0);
        bytes memory authSignature = _sig(adminKey, gardenAccount.computeDigest(authCalls, authNonce));
        bytes memory authOpData = abi.encodePacked(authNonce, authSignature);
        bytes memory authExecutionData = abi.encode(authCalls, authOpData);

        gardenAccount.execute(authCalls, authOpData);

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data = abi.encodeWithSelector(
            GardenAccount.whitelistAddress.selector,
            addr
        );

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(randomKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        bytes memory executionData = abi.encode(calls, opData);

        vm.expectRevert();
        gardenAccount.execute(calls, opData);

        assertFalse(gardenAccount.whitelistedAddresses(addr), "Address should not be whitelisted");
    }
}
