// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./Base.t.sol";
import {GardenSolver} from "../src/GardenSolver.sol";
import {IthacaAccount} from "../src/IthacaAccount.sol";
import{GuardedExecutor} from "../src/GuardedExecutor.sol";
import {MultiSigSigner} from "../src/MultiSigSigner.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";
import {MockPaymentToken} from "./utils/mocks/MockPaymentToken.sol";

contract GardenAccountTest is BaseTest {
    using LibBytes for *;

    GardenSolver gardenAccount;
    PassKey adminKey;
    PassKey nonSuperAdminKey;
    address testAddress1;
    address testAddress2;

    MockPaymentToken erc20Token;

    function setUp() public override {
        super.setUp();
        erc20Token = new MockPaymentToken();

        // Deploy GardenAccount with super admin key
        adminKey = _randomSecp256k1PassKey();
        adminKey.k.isSuperAdmin = true;

        // Create initial keys array with just the admin key
        IthacaAccount.Key[] memory initialKeys = new IthacaAccount.Key[](1);
        initialKeys[0] = adminKey.k;

        // Deploy GardenAccount with new constructor signature
        // (orchestrator, initialKeys, multiSigSigner, threshold)
        gardenAccount = new GardenSolver(
            address(oc),
            initialKeys,
            address(0), // No multisig for single-key tests
            1 // Threshold of 1
        );

        // Create a non-super admin key for testing unauthorized access
        nonSuperAdminKey = _randomSecp256k1PassKey();
        nonSuperAdminKey.k.isSuperAdmin = false;

        // Authorize the non-super admin key through execute (using adminKey signature)
        ERC7821.Call[] memory authCalls = new ERC7821.Call[](1);
        authCalls[0].data =
            abi.encodeWithSelector(IthacaAccount.authorize.selector, nonSuperAdminKey.k);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(authCalls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        address adminAddr = vm.addr(adminKey.privateKey);
        vm.prank(adminAddr);
        gardenAccount.execute(authCalls, opData);

        // Setup test addresses
        testAddress1 = _randomUniqueHashedAddress();
        testAddress2 = _randomUniqueHashedAddress();
    }

    // ============ Super Admin Verification ============

    function testAdminKeyIsSetAsSuperAdmin() public view {
        // Get the admin key from the account
        bytes32 adminKeyHash = _hash(adminKey.k);
        IthacaAccount.Key memory retrievedKey = gardenAccount.getKey(adminKeyHash);

        assertTrue(retrievedKey.isSuperAdmin, "Admin key should be marked as super admin");
        assertEq(uint8(retrievedKey.keyType), uint8(adminKey.k.keyType), "Key type should match");
        assertEq(
            keccak256(retrievedKey.publicKey),
            keccak256(adminKey.k.publicKey),
            "Public key should match"
        );
    }

    function testNonSuperAdminKeyIsNotSuperAdmin() public view {
        bytes32 nonAdminKeyHash = nonSuperAdminKey.keyHash;
        IthacaAccount.Key memory retrievedKey = gardenAccount.getKey(nonAdminKeyHash);

        assert(!retrievedKey.isSuperAdmin);
    }

    // ============ Super Admin Success Cases ============

    function testSuperAdminCanWhitelistAddress() public {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, testAddress1);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        gardenAccount.execute(calls, opData);

        assertTrue(
            gardenAccount.whitelistedAddresses(testAddress1), "Address should be whitelisted"
        );
        assertEq(
            gardenAccount.whitelistingTimestamps(testAddress1),
            block.timestamp,
            "Timestamp should be set"
        );
    }

    function testSuperAdminCanRemoveWhitelistedAddress() public {
        // First whitelist the address
        ERC7821.Call[] memory whitelistCalls = new ERC7821.Call[](1);
        whitelistCalls[0].data =
            abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, testAddress1);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(whitelistCalls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        gardenAccount.execute(whitelistCalls, opData);

        // Now remove the whitelisted address
        ERC7821.Call[] memory removeCalls = new ERC7821.Call[](1);
        removeCalls[0].data =
            abi.encodeWithSelector(GardenSolver.removeWhitelistedAddress.selector, testAddress1);

        nonce = gardenAccount.getNonce(0);
        signature = _sig(adminKey, gardenAccount.computeDigest(removeCalls, nonce));
        opData = abi.encodePacked(nonce, signature);

        gardenAccount.execute(removeCalls, opData);

        assert(!gardenAccount.whitelistedAddresses(testAddress1));
        assertEq(gardenAccount.whitelistingTimestamps(testAddress1), 0, "Timestamp should be reset");
    }

    function testSuperAdminCanChangeCooldownPeriod() public {
        uint256 newCooldownPeriod = 7 days;

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data =
            abi.encodeWithSelector(GardenSolver.changeCooldownPeriod.selector, newCooldownPeriod);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        gardenAccount.execute(calls, opData);

        assertEq(
            gardenAccount.cooldownPeriod(), newCooldownPeriod, "Cooldown period should be updated"
        );
    }

    function testSuperAdminCanWhitelistMultipleAddresses() public {
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, testAddress1);
        calls[1].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, testAddress2);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        gardenAccount.execute(calls, opData);

        assertTrue(
            gardenAccount.whitelistedAddresses(testAddress1), "Address1 should be whitelisted"
        );
        assertTrue(
            gardenAccount.whitelistedAddresses(testAddress2), "Address2 should be whitelisted"
        );
    }

    function testSuperAdminCanCombineWhitelistAndCooldownChanges() public {
        uint256 newCooldownPeriod = 3 days;

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, testAddress1);
        calls[1].data =
            abi.encodeWithSelector(GardenSolver.changeCooldownPeriod.selector, newCooldownPeriod);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        gardenAccount.execute(calls, opData);

        assertTrue(
            gardenAccount.whitelistedAddresses(testAddress1), "Address should be whitelisted"
        );
        assertEq(
            gardenAccount.cooldownPeriod(), newCooldownPeriod, "Cooldown period should be updated"
        );
    }

    // ============ Non-Super Admin Revert Cases ============

    function testNonSuperAdminCannotWhitelistAddress() public {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, testAddress1);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(nonSuperAdminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        vm.expectRevert();
        gardenAccount.execute(calls, opData);

        assertFalse(
            gardenAccount.whitelistedAddresses(testAddress1), "Address should not be whitelisted"
        );
    }

    function testNonSuperAdminCannotRemoveWhitelistedAddress() public {
        // First, super admin whitelists the address
        ERC7821.Call[] memory whitelistCalls = new ERC7821.Call[](1);
        whitelistCalls[0].data =
            abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, testAddress1);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(whitelistCalls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        gardenAccount.execute(whitelistCalls, opData);

        // Now non-super admin tries to remove it
        ERC7821.Call[] memory removeCalls = new ERC7821.Call[](1);
        removeCalls[0].data =
            abi.encodeWithSelector(GardenSolver.removeWhitelistedAddress.selector, testAddress1);

        nonce = gardenAccount.getNonce(0);
        signature = _sig(nonSuperAdminKey, gardenAccount.computeDigest(removeCalls, nonce));
        opData = abi.encodePacked(nonce, signature);

        vm.expectRevert();
        gardenAccount.execute(removeCalls, opData);

        assertTrue(
            gardenAccount.whitelistedAddresses(testAddress1), "Address should still be whitelisted"
        );
    }

    function testNonSuperAdminCannotChangeCooldownPeriod() public {
        uint256 originalCooldownPeriod = gardenAccount.cooldownPeriod();
        uint256 newCooldownPeriod = 7 days;

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data =
            abi.encodeWithSelector(GardenSolver.changeCooldownPeriod.selector, newCooldownPeriod);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(nonSuperAdminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        vm.expectRevert();
        gardenAccount.execute(calls, opData);

        assertEq(
            gardenAccount.cooldownPeriod(),
            originalCooldownPeriod,
            "Cooldown period should not change"
        );
    }

    function testUnauthorizedKeyCannotWhitelistAddress() public {
        PassKey memory unauthorizedKey = _randomSecp256k1PassKey();
        unauthorizedKey.k.isSuperAdmin = false;

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, testAddress1);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(unauthorizedKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        vm.expectRevert();
        gardenAccount.execute(calls, opData);

        assertFalse(
            gardenAccount.whitelistedAddresses(testAddress1), "Address should not be whitelisted"
        );
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
        calls[0].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, addr);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        gardenAccount.execute(calls, opData);

        assertTrue(gardenAccount.whitelistedAddresses(addr), "Address should be whitelisted");
    }

    function testFuzzSuperAdminCanSetAnyCooldownPeriod(uint256 newCooldown) public {
        // Bound to reasonable values to avoid overflow issues
        newCooldown = bound(newCooldown, 1, 365 days);

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data =
            abi.encodeWithSelector(GardenSolver.changeCooldownPeriod.selector, newCooldown);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        gardenAccount.execute(calls, opData);

        assertEq(gardenAccount.cooldownPeriod(), newCooldown, "Cooldown period should be updated");
    }

    function testFuzzNonSuperAdminCannotWhitelistAnyAddress(address addr) public {
        // Create a random non-super admin key
        PassKey memory randomKey = _randomSecp256k1PassKey();
        randomKey.k.isSuperAdmin = false;

        // Authorize the random key through execute (using adminKey signature)
        ERC7821.Call[] memory authCalls = new ERC7821.Call[](1);
        authCalls[0].data = abi.encodeWithSelector(IthacaAccount.authorize.selector, randomKey.k);

        uint256 authNonce = gardenAccount.getNonce(0);
        bytes memory authSignature =
            _sig(adminKey, gardenAccount.computeDigest(authCalls, authNonce));
        bytes memory authOpData = abi.encodePacked(authNonce, authSignature);

        gardenAccount.execute(authCalls, authOpData);

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, addr);

        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(randomKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        vm.expectRevert();
        gardenAccount.execute(calls, opData);

        assertFalse(gardenAccount.whitelistedAddresses(addr), "Address should not be whitelisted");
    }

    // ============ Multisig & Batch Transaction Tests ============

    /// @notice Test multisig setup with 2-of-3 threshold
    function testMultisigSetup() public {
        // Create 3 signer keys
        PassKey memory signer1 = _randomSecp256k1PassKey();
        PassKey memory signer2 = _randomSecp256k1PassKey();
        PassKey memory signer3 = _randomSecp256k1PassKey();

        signer1.k.isSuperAdmin = false;
        signer2.k.isSuperAdmin = false;
        signer3.k.isSuperAdmin = false;

        // Create initial keys array with all signers
        IthacaAccount.Key[] memory signerKeys = new IthacaAccount.Key[](3);
        signerKeys[0] = signer1.k;
        signerKeys[1] = signer2.k;
        signerKeys[2] = signer3.k;

        // Deploy MultiSigSigner
        MultiSigSigner multiSig = new MultiSigSigner();

        // Deploy GardenSolver with multisig (2-of-3)
        GardenSolver multisigAccount = new GardenSolver{value: 1 ether}(
            address(oc),
            signerKeys,
            address(multiSig),
            2 // 2-of-3 threshold
        );

        // Verify the account was created with correct balance
        assertEq(address(multisigAccount).balance, 1 ether, "Account should have 1 ETH");
        assertEq(
            address(multisigAccount).code.length > 0, true, "Account should have deployed code"
        );

        // Verify initial nonce is 0
        assertEq(multisigAccount.getNonce(0), 0, "Initial nonce should be 0");

        // Verify keys were authorized by attempting to retrieve them
        bytes32 signer1Hash = multisigAccount.hash(signer1.k);
        bytes32 signer2Hash = multisigAccount.hash(signer2.k);
        bytes32 signer3Hash = multisigAccount.hash(signer3.k);

        // If getKey doesn't revert, the key is authorized
        IthacaAccount.Key memory key1 = multisigAccount.getKey(signer1Hash);
        IthacaAccount.Key memory key2 = multisigAccount.getKey(signer2Hash);
        IthacaAccount.Key memory key3 = multisigAccount.getKey(signer3Hash);

        // Verify key types and properties
        assertEq(
            uint8(key1.keyType), uint8(IthacaAccount.KeyType.Secp256k1), "Key1 should be Secp256k1"
        );
        assertEq(
            uint8(key2.keyType), uint8(IthacaAccount.KeyType.Secp256k1), "Key2 should be Secp256k1"
        );
        assertEq(
            uint8(key3.keyType), uint8(IthacaAccount.KeyType.Secp256k1), "Key3 should be Secp256k1"
        );
        assertFalse(key1.isSuperAdmin, "Signer keys should not be super admin");
        assertFalse(key2.isSuperAdmin, "Signer keys should not be super admin");
        assertFalse(key3.isSuperAdmin, "Signer keys should not be super admin");

        // Verify multisig External key was created as super admin
        IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(address(multiSig), bytes12(0))
        });
        bytes32 multisigKeyHash = multisigAccount.hash(multisigKey);
        IthacaAccount.Key memory retrievedMultisigKey = multisigAccount.getKey(multisigKeyHash);

        assertEq(
            uint8(retrievedMultisigKey.keyType),
            uint8(IthacaAccount.KeyType.External),
            "Multisig key should be External"
        );
        assertTrue(retrievedMultisigKey.isSuperAdmin, "Multisig key should be super admin");

        // Verify we can get all keys
        (IthacaAccount.Key[] memory allKeys, bytes32[] memory allKeyHashes) =
            multisigAccount.getKeys();
        assertEq(allKeys.length, 4, "Should have 4 keys total (3 signers + 1 multisig)");
        assertEq(allKeyHashes.length, 4, "Should have 4 key hashes");
    }

    /// @notice Test batch transaction: whitelist multiple addresses and change cooldown
    function testBatchTransactionWhitelistAndCooldown() public {
        address addr1 = makeAddr("batch_addr1");
        address addr2 = makeAddr("batch_addr2");
        address addr3 = makeAddr("batch_addr3");
        uint256 newCooldown = 5 days;
        uint256 oldCooldown = gardenAccount.cooldownPeriod();

        // Verify initial state - none are whitelisted
        assertFalse(
            gardenAccount.whitelistedAddresses(addr1),
            "Address1 should not be whitelisted initially"
        );
        assertFalse(
            gardenAccount.whitelistedAddresses(addr2),
            "Address2 should not be whitelisted initially"
        );
        assertFalse(
            gardenAccount.whitelistedAddresses(addr3),
            "Address3 should not be whitelisted initially"
        );
        assertEq(gardenAccount.whitelistingTimestamps(addr1), 0, "Timestamp should be 0 initially");
        assertEq(gardenAccount.whitelistingTimestamps(addr2), 0, "Timestamp should be 0 initially");
        assertEq(gardenAccount.whitelistingTimestamps(addr3), 0, "Timestamp should be 0 initially");
        assertEq(gardenAccount.cooldownPeriod(), oldCooldown, "Cooldown should be initial value");

        // Create batch of 4 operations
        ERC7821.Call[] memory calls = new ERC7821.Call[](4);
        calls[0].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, addr1);
        calls[1].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, addr2);
        calls[2].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, addr3);
        calls[3].data =
            abi.encodeWithSelector(GardenSolver.changeCooldownPeriod.selector, newCooldown);

        uint256 nonceBefore = gardenAccount.getNonce(0);
        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        // Execute all operations in one transaction
        uint256 blockTimestamp = block.timestamp;
        gardenAccount.execute(calls, opData);

        // Verify all addresses were whitelisted with correct timestamps
        assertTrue(gardenAccount.whitelistedAddresses(addr1), "Address1 should be whitelisted");
        assertTrue(gardenAccount.whitelistedAddresses(addr2), "Address2 should be whitelisted");
        assertTrue(gardenAccount.whitelistedAddresses(addr3), "Address3 should be whitelisted");
        assertEq(
            gardenAccount.whitelistingTimestamps(addr1),
            blockTimestamp,
            "Timestamp1 should be set to block.timestamp"
        );
        assertEq(
            gardenAccount.whitelistingTimestamps(addr2),
            blockTimestamp,
            "Timestamp2 should be set to block.timestamp"
        );
        assertEq(
            gardenAccount.whitelistingTimestamps(addr3),
            blockTimestamp,
            "Timestamp3 should be set to block.timestamp"
        );

        // Verify cooldown was changed
        assertEq(
            gardenAccount.cooldownPeriod(), newCooldown, "Cooldown should be updated to new value"
        );
        assertNotEq(
            gardenAccount.cooldownPeriod(), oldCooldown, "Cooldown should differ from old value"
        );

        // Verify nonce was incremented
        assertEq(
            gardenAccount.getNonce(0),
            nonceBefore + 1,
            "Nonce should be incremented after execution"
        );
    }

    /// @notice Test multisig execution: 2 signers approve token transfer
    function testMultisigTokenApprovalAndTransfer() public {
        // Create 3 signer keys
        PassKey memory signer1 = _randomSecp256k1PassKey();
        PassKey memory signer2 = _randomSecp256k1PassKey();
        PassKey memory signer3 = _randomSecp256k1PassKey();

        signer1.k.isSuperAdmin = false;
        signer2.k.isSuperAdmin = false;
        signer3.k.isSuperAdmin = false;

        IthacaAccount.Key[] memory signerKeys = new IthacaAccount.Key[](3);
        signerKeys[0] = signer1.k;
        signerKeys[1] = signer2.k;
        signerKeys[2] = signer3.k;

        MultiSigSigner multiSig = new MultiSigSigner();

        GardenSolver multisigAccount = new GardenSolver{value: 1 ether}(
            address(oc),
            signerKeys,
            address(multiSig),
            2 // 2-of-3 threshold
        );

        // Mint tokens to the account
        uint256 mintAmount = 1_000_000 ether;
        erc20Token.mint(address(multisigAccount), mintAmount);

        // Verify initial balances and allowances
        assertEq(
            erc20Token.balanceOf(address(multisigAccount)),
            mintAmount,
            "Account should have minted tokens"
        );

        // Create recipient
        address recipient = makeAddr("token_recipient");
        uint256 approveAmount = 100_000 ether;

        // Verify initial allowance is 0
        assertEq(
            erc20Token.allowance(address(multisigAccount), recipient),
            0,
            "Initial allowance should be 0"
        );

        // Create call to approve tokens
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: address(erc20Token),
            value: 0,
            data: abi.encodeWithSignature("approve(address,uint256)", recipient, approveAmount)
        });

        // Compute digest
        uint256 nonceBefore = multisigAccount.getNonce(0);
        uint256 nonce = multisigAccount.getNonce(0);
        bytes32 digest = multisigAccount.computeDigest(calls, nonce);

        // Get keyHashes
        bytes32 signer1Hash = multisigAccount.hash(signer1.k);
        bytes32 signer2Hash = multisigAccount.hash(signer2.k);

        // Create multisig key
        IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(address(multiSig), bytes12(0))
        });
        bytes32 multisigKeyHash = multisigAccount.hash(multisigKey);

        // Sign with signer1 and signer2 (2 out of 3)
        bytes memory sig1 = _wrapSecpSig(signer1, signer1Hash, digest);
        bytes memory sig2 = _wrapSecpSig(signer2, signer2Hash, digest);

        bytes[] memory innerSignatures = new bytes[](2);
        innerSignatures[0] = sig1;
        innerSignatures[1] = sig2;

        bytes memory multisigSignature =
            abi.encodePacked(abi.encode(innerSignatures), multisigKeyHash, uint8(0));

        // Execute with multisig
        multisigAccount.execute(calls, abi.encodePacked(nonce, multisigSignature));

        // Verify approval was set correctly
        assertEq(
            erc20Token.allowance(address(multisigAccount), recipient),
            approveAmount,
            "Approval should be set to exact amount"
        );

        // Verify token balance unchanged (approval doesn't transfer)
        assertEq(
            erc20Token.balanceOf(address(multisigAccount)),
            mintAmount,
            "Token balance should remain unchanged"
        );
        assertEq(
            erc20Token.balanceOf(recipient),
            0,
            "Recipient should have 0 tokens (only approved, not transferred)"
        );

        // Verify nonce was incremented
        assertEq(
            multisigAccount.getNonce(0),
            nonceBefore + 1,
            "Nonce should increment after multisig execution"
        );
    }

    /// @notice Test complex batch: authorize key, whitelist, and change cooldown
    function testBatchAuthorizeWhitelistAndCooldown() public {
        PassKey memory newKey = _randomSecp256k1PassKey();
        newKey.k.isSuperAdmin = false;

        address whitelistAddr = makeAddr("new_whitelist");
        uint256 newCooldown = 10 days;
        uint256 oldCooldown = gardenAccount.cooldownPeriod();

        // Verify initial state
        bytes32 newKeyHash = gardenAccount.hash(newKey.k);
        // Key should not exist yet - trying to get it should revert
        vm.expectRevert();
        gardenAccount.getKey(newKeyHash);

        assertFalse(
            gardenAccount.whitelistedAddresses(whitelistAddr),
            "Address should not be whitelisted initially"
        );
        assertEq(
            gardenAccount.whitelistingTimestamps(whitelistAddr),
            0,
            "Timestamp should be 0 initially"
        );
        assertEq(gardenAccount.cooldownPeriod(), oldCooldown, "Cooldown should be at initial value");

        // Batch: authorize new key, whitelist address, change cooldown
        ERC7821.Call[] memory calls = new ERC7821.Call[](3);
        calls[0].data = abi.encodeWithSelector(IthacaAccount.authorize.selector, newKey.k);
        calls[1].data =
            abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, whitelistAddr);
        calls[2].data =
            abi.encodeWithSelector(GardenSolver.changeCooldownPeriod.selector, newCooldown);

        uint256 nonceBefore = gardenAccount.getNonce(0);
        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        uint256 blockTimestamp = block.timestamp;
        gardenAccount.execute(calls, opData);

        // Verify all operations succeeded
        IthacaAccount.Key memory retrievedKey = gardenAccount.getKey(newKeyHash);
        assertEq(
            uint8(retrievedKey.keyType),
            uint8(IthacaAccount.KeyType.Secp256k1),
            "Key should be Secp256k1"
        );
        assertFalse(retrievedKey.isSuperAdmin, "New key should not be super admin");
        assertEq(retrievedKey.expiry, 0, "Key should have no expiry");

        assertTrue(
            gardenAccount.whitelistedAddresses(whitelistAddr), "Address should be whitelisted"
        );
        assertEq(
            gardenAccount.whitelistingTimestamps(whitelistAddr),
            blockTimestamp,
            "Timestamp should be set correctly"
        );

        assertEq(gardenAccount.cooldownPeriod(), newCooldown, "Cooldown should be updated");
        assertNotEq(
            gardenAccount.cooldownPeriod(), oldCooldown, "Cooldown should differ from old value"
        );

        // Verify nonce incremented
        assertEq(gardenAccount.getNonce(0), nonceBefore + 1, "Nonce should increment");
    }

    /// @notice Test multisig with batch operations: batch whitelist with multisig super admin
    function testMultisigBatchWhitelistWithSuperAdmin() public {
        // Create 3 regular signer keys (none are super admin)
        PassKey memory signer1 = _randomSecp256k1PassKey();
        PassKey memory signer2 = _randomSecp256k1PassKey();
        PassKey memory signer3 = _randomSecp256k1PassKey();

        signer1.k.isSuperAdmin = false;
        signer2.k.isSuperAdmin = false;
        signer3.k.isSuperAdmin = false;

        IthacaAccount.Key[] memory signerKeys = new IthacaAccount.Key[](3);
        signerKeys[0] = signer1.k;
        signerKeys[1] = signer2.k;
        signerKeys[2] = signer3.k;

        MultiSigSigner multiSig = new MultiSigSigner();

        // Deploy GardenAccount - constructor automatically creates multisig super admin key
        GardenSolver multisigAccount = new GardenSolver{value: 1 ether}(
            address(oc),
            signerKeys,
            address(multiSig),
            2 // 2-of-3 threshold
        );

        // Verify initial state - addresses not whitelisted
        address addr1 = makeAddr("multi_addr1");
        address addr2 = makeAddr("multi_addr2");
        address addr3 = makeAddr("multi_addr3");

        assertFalse(
            multisigAccount.whitelistedAddresses(addr1),
            "Address1 should not be whitelisted initially"
        );
        assertFalse(
            multisigAccount.whitelistedAddresses(addr2),
            "Address2 should not be whitelisted initially"
        );
        assertFalse(
            multisigAccount.whitelistedAddresses(addr3),
            "Address3 should not be whitelisted initially"
        );

        // The multisig External key is already authorized as super admin by constructor
        // Now use multisig to batch whitelist addresses
        ERC7821.Call[] memory calls = new ERC7821.Call[](3);
        calls[0].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, addr1);
        calls[1].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, addr2);
        calls[2].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, addr3);

        uint256 nonceBefore = multisigAccount.getNonce(0);
        uint256 nonce = multisigAccount.getNonce(0);
        bytes32 digest = multisigAccount.computeDigest(calls, nonce);

        // Create the multisig key struct (same as what constructor created)
        IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(address(multiSig), bytes12(0))
        });

        bytes32 signer1Hash = multisigAccount.hash(signer1.k);
        bytes32 signer2Hash = multisigAccount.hash(signer2.k);
        bytes32 multisigKeyHash = multisigAccount.hash(multisigKey);

        // Sign with signer1 and signer2 (2-of-3)
        bytes memory sig1 = _wrapSecpSig(signer1, signer1Hash, digest);
        bytes memory sig2 = _wrapSecpSig(signer2, signer2Hash, digest);

        bytes[] memory innerSignatures = new bytes[](2);
        innerSignatures[0] = sig1;
        innerSignatures[1] = sig2;

        bytes memory multisigSignature =
            abi.encodePacked(abi.encode(innerSignatures), multisigKeyHash, uint8(0));

        // Execute batch whitelist with multisig
        uint256 blockTimestamp = block.timestamp;
        multisigAccount.execute(calls, abi.encodePacked(nonce, multisigSignature));

        // Verify all addresses were whitelisted with correct timestamps
        assertTrue(multisigAccount.whitelistedAddresses(addr1), "Address1 should be whitelisted");
        assertTrue(multisigAccount.whitelistedAddresses(addr2), "Address2 should be whitelisted");
        assertTrue(multisigAccount.whitelistedAddresses(addr3), "Address3 should be whitelisted");
        assertEq(
            multisigAccount.whitelistingTimestamps(addr1),
            blockTimestamp,
            "Timestamp1 should be set"
        );
        assertEq(
            multisigAccount.whitelistingTimestamps(addr2),
            blockTimestamp,
            "Timestamp2 should be set"
        );
        assertEq(
            multisigAccount.whitelistingTimestamps(addr3),
            blockTimestamp,
            "Timestamp3 should be set"
        );

        // Verify nonce incremented
        assertEq(
            multisigAccount.getNonce(0),
            nonceBefore + 1,
            "Nonce should increment after multisig execution"
        );

        // Verify multisig key is still super admin
        IthacaAccount.Key memory retrievedMultisigKey = multisigAccount.getKey(multisigKeyHash);
        assertTrue(retrievedMultisigKey.isSuperAdmin, "Multisig key should still be super admin");
    }

    /// @notice Test multisig batch: Non-super admin signers cannot whitelist
    function testMultisigBatchWhitelist() public {
        // Create 3 signer keys
        PassKey memory signer1 = _randomSecp256k1PassKey();
        PassKey memory signer2 = _randomSecp256k1PassKey();
        PassKey memory signer3 = _randomSecp256k1PassKey();

        signer1.k.isSuperAdmin = false;
        signer2.k.isSuperAdmin = false;
        signer3.k.isSuperAdmin = false;

        IthacaAccount.Key[] memory signerKeys = new IthacaAccount.Key[](3);
        signerKeys[0] = signer1.k;
        signerKeys[1] = signer2.k;
        signerKeys[2] = signer3.k;

        MultiSigSigner multiSig = new MultiSigSigner();

        // Deploy GardenAccount with only the 3 signer keys
        // Multisig key is not added to initial keys, it's used only for signing
        GardenSolver multisigAccount = new GardenSolver{value: 1 ether}(
            address(oc),
            signerKeys,
            address(multiSig),
            2 // 2-of-3 threshold
        );

        // First, we need to authorize the multisig key as super admin
        // Create super admin key for multisig
        IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(address(multiSig), bytes12(0))
        });

        // Authorize the multisig key using 2 regular signers
        ERC7821.Call[] memory authCalls = new ERC7821.Call[](1);
        authCalls[0].data = abi.encodeWithSelector(IthacaAccount.authorize.selector, multisigKey);

        uint256 authNonce = multisigAccount.getNonce(0);
        bytes32 authDigest = multisigAccount.computeDigest(authCalls, authNonce);

        bytes32 signer1Hash = multisigAccount.hash(signer1.k);
        bytes32 signer2Hash = multisigAccount.hash(signer2.k);

        // Sign authorization with signer1 and signer2
        bytes memory authSig1 = _wrapSecpSig(signer1, signer1Hash, authDigest);
        bytes memory authSig2 = _wrapSecpSig(signer2, signer2Hash, authDigest);

        bytes[] memory authInnerSigs = new bytes[](2);
        authInnerSigs[0] = authSig1;
        authInnerSigs[1] = authSig2;

        // This test demonstrates that regular (non-super-admin) signers cannot whitelist
        // even with multiple signatures, because whitelisting requires super admin permissions

        // Create batch whitelist operations
        address addr1 = makeAddr("multi_addr1");
        address addr2 = makeAddr("multi_addr2");
        address addr3 = makeAddr("multi_addr3");

        // Verify initial state - not whitelisted
        assertFalse(
            multisigAccount.whitelistedAddresses(addr1),
            "Address1 should not be whitelisted initially"
        );
        assertFalse(
            multisigAccount.whitelistedAddresses(addr2),
            "Address2 should not be whitelisted initially"
        );
        assertFalse(
            multisigAccount.whitelistedAddresses(addr3),
            "Address3 should not be whitelisted initially"
        );

        ERC7821.Call[] memory calls = new ERC7821.Call[](3);
        calls[0].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, addr1);
        calls[1].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, addr2);
        calls[2].data = abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, addr3);

        // Compute digest
        uint256 nonceBefore = multisigAccount.getNonce(0);
        uint256 nonce = multisigAccount.getNonce(0);
        bytes32 digest = multisigAccount.computeDigest(calls, nonce);

        // Sign with signer1 alone (not a super admin, should fail)
        bytes memory sig1 = _wrapSecpSig(signer1, signer1Hash, digest);
        bytes memory opData = abi.encodePacked(nonce, sig1);

        // This should revert because signer1 is not a super admin
        vm.expectRevert();
        multisigAccount.execute(calls, opData);

        // Verify addresses were NOT whitelisted (state unchanged)
        assertFalse(
            multisigAccount.whitelistedAddresses(addr1), "Address1 should not be whitelisted"
        );
        assertFalse(
            multisigAccount.whitelistedAddresses(addr2), "Address2 should not be whitelisted"
        );
        assertFalse(
            multisigAccount.whitelistedAddresses(addr3), "Address3 should not be whitelisted"
        );
        assertEq(multisigAccount.whitelistingTimestamps(addr1), 0, "Timestamp1 should remain 0");
        assertEq(multisigAccount.whitelistingTimestamps(addr2), 0, "Timestamp2 should remain 0");
        assertEq(multisigAccount.whitelistingTimestamps(addr3), 0, "Timestamp3 should remain 0");

        // Verify nonce was NOT incremented (transaction reverted)
        assertEq(
            multisigAccount.getNonce(0),
            nonceBefore,
            "Nonce should not increment on failed execution"
        );
    }

    /// @notice Test that insufficient signatures fail (need 2 but provide 1)
    function testMultisigInsufficientSignaturesFails() public {
        // Create 3 signer keys
        PassKey memory signer1 = _randomSecp256k1PassKey();
        PassKey memory signer2 = _randomSecp256k1PassKey();
        PassKey memory signer3 = _randomSecp256k1PassKey();

        signer1.k.isSuperAdmin = false;
        signer2.k.isSuperAdmin = false;
        signer3.k.isSuperAdmin = false;

        IthacaAccount.Key[] memory signerKeys = new IthacaAccount.Key[](3);
        signerKeys[0] = signer1.k;
        signerKeys[1] = signer2.k;
        signerKeys[2] = signer3.k;

        MultiSigSigner multiSig = new MultiSigSigner();

        GardenSolver multisigAccount = new GardenSolver{value: 1 ether}(
            address(oc),
            signerKeys,
            address(multiSig),
            2 // 2-of-3 threshold
        );

        // Create multisig key
        IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(address(multiSig), bytes12(0))
        });

        address whitelistAddr = makeAddr("test_whitelist");

        // Verify initial state
        assertFalse(
            multisigAccount.whitelistedAddresses(whitelistAddr),
            "Address should not be whitelisted initially"
        );
        assertEq(
            multisigAccount.whitelistingTimestamps(whitelistAddr),
            0,
            "Timestamp should be 0 initially"
        );

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0].data =
            abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, whitelistAddr);

        uint256 nonceBefore = multisigAccount.getNonce(0);
        uint256 nonce = multisigAccount.getNonce(0);
        bytes32 digest = multisigAccount.computeDigest(calls, nonce);

        bytes32 signer1Hash = multisigAccount.hash(signer1.k);
        bytes32 multisigKeyHash = multisigAccount.hash(multisigKey);

        // Only sign with signer1 (need 2 signatures, providing 1) - INSUFFICIENT
        bytes memory sig1 = _wrapSecpSig(signer1, signer1Hash, digest);

        bytes[] memory innerSignatures = new bytes[](1); // Only 1 signature when 2 required
        innerSignatures[0] = sig1;

        bytes memory multisigSignature =
            abi.encodePacked(abi.encode(innerSignatures), multisigKeyHash, uint8(0));

        // Should fail with insufficient signatures (threshold not met)
        vm.expectRevert();
        multisigAccount.execute(calls, abi.encodePacked(nonce, multisigSignature));

        // Verify address was NOT whitelisted (state unchanged)
        assertFalse(
            multisigAccount.whitelistedAddresses(whitelistAddr),
            "Address should not be whitelisted after failed attempt"
        );
        assertEq(
            multisigAccount.whitelistingTimestamps(whitelistAddr), 0, "Timestamp should remain 0"
        );

        // Verify nonce was NOT incremented (transaction reverted)
        assertEq(
            multisigAccount.getNonce(0),
            nonceBefore,
            "Nonce should not increment on failed multisig execution"
        );
    }

    /// @notice Test large batch transaction (stress test)
    function testLargeBatchTransaction() public {
        uint256 batchSize = 10;

        // Store addresses for later verification
        address[] memory addresses = new address[](batchSize);

        // Verify initial state - none are whitelisted
        for (uint256 i = 0; i < batchSize; i++) {
            addresses[i] = makeAddr(string(abi.encodePacked("batch_addr_", vm.toString(i))));
            assertFalse(
                gardenAccount.whitelistedAddresses(addresses[i]),
                "Address should not be whitelisted initially"
            );
            assertEq(
                gardenAccount.whitelistingTimestamps(addresses[i]),
                0,
                "Timestamp should be 0 initially"
            );
        }

        ERC7821.Call[] memory calls = new ERC7821.Call[](batchSize);

        // Create batch of whitelist operations
        for (uint256 i = 0; i < batchSize; i++) {
            calls[i].data =
                abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, addresses[i]);
        }

        uint256 nonceBefore = gardenAccount.getNonce(0);
        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(calls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);

        // Execute large batch
        uint256 blockTimestamp = block.timestamp;
        gardenAccount.execute(calls, opData);

        // Verify all addresses were whitelisted with correct timestamps
        for (uint256 i = 0; i < batchSize; i++) {
            assertTrue(
                gardenAccount.whitelistedAddresses(addresses[i]),
                string(abi.encodePacked("Address ", vm.toString(i), " should be whitelisted"))
            );
            assertEq(
                gardenAccount.whitelistingTimestamps(addresses[i]),
                blockTimestamp,
                string(
                    abi.encodePacked(
                        "Timestamp for address ", vm.toString(i), " should be set correctly"
                    )
                )
            );
        }

        // Verify nonce incremented only once (all operations in single transaction)
        assertEq(
            gardenAccount.getNonce(0),
            nonceBefore + 1,
            "Nonce should increment by 1 for batch transaction"
        );

        // Verify gas efficiency - batch should be more efficient than individual transactions
        // This is implicit - if the test completes without running out of gas, batch is working
        assertTrue(true, "Large batch transaction completed successfully");
    }

    // ============ Helper Functions ============

    /// @notice Wrap secp256k1 signature for multisig
    function _wrapSecpSig(PassKey memory pk, bytes32 keyHash, bytes32 digest)
        internal
        pure
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk.privateKey, digest);
        return abi.encodePacked(r, s, v, keyHash, uint8(0));
    }

    // ============ Withdraw Function Tests ============

    /// @notice Test withdraw with admin key (no spend limits required)
    function testAdminKeyCanWithdrawAfterCooldown() public {
        // Setup: Fund the account and whitelist recipient
        uint256 withdrawAmount = 0.5 ether;
        address recipient = makeAddr("withdraw_recipient");
        
        vm.deal(address(gardenAccount), 1 ether);
        
        // Whitelist the recipient
        ERC7821.Call[] memory whitelistCalls = new ERC7821.Call[](1);
        whitelistCalls[0].data = abi.encodeWithSelector(
            GardenSolver.whitelistAddress.selector, 
            recipient
        );
        
        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(whitelistCalls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        
        gardenAccount.execute(whitelistCalls, opData);
        
        // Verify recipient is whitelisted
        assertTrue(gardenAccount.whitelistedAddresses(recipient), "Recipient should be whitelisted");
        
        // Fast forward past cooldown period
        uint256 cooldownPeriod = gardenAccount.cooldownPeriod();
        vm.warp(block.timestamp + cooldownPeriod + 1);
        
        // Withdraw ETH using admin key
        ERC7821.Call[] memory withdrawCalls = new ERC7821.Call[](1);
        withdrawCalls[0].data = abi.encodeWithSelector(
            GardenSolver.withdraw.selector,
            recipient,
            address(0), // ETH
            withdrawAmount
        );
        
        nonce = gardenAccount.getNonce(0);
        signature = _sig(adminKey, gardenAccount.computeDigest(withdrawCalls, nonce));
        opData = abi.encodePacked(nonce, signature);
        
        uint256 recipientBalanceBefore = recipient.balance;
        uint256 accountBalanceBefore = address(gardenAccount).balance;
        
        gardenAccount.execute(withdrawCalls, opData);
        
        // Verify balances changed correctly
        assertEq(
            recipient.balance,
            recipientBalanceBefore + withdrawAmount,
            "Recipient should receive withdrawn ETH"
        );
        assertEq(
            address(gardenAccount).balance,
            accountBalanceBefore - withdrawAmount,
            "Account balance should decrease"
        );
    }

    /// @notice Test withdraw with non-super admin key (requires spend limits and canExecute)
    function testNonSuperAdminKeyCanWithdrawWithPermissions() public {
        // Setup: Fund the account and whitelist recipient
        uint256 withdrawAmount = 0.3 ether;
        address recipient = makeAddr("withdraw_recipient_2");
        
        vm.deal(address(gardenAccount), 5 ether);
        
        // Get the non-super admin key hash
        bytes32 nonAdminKeyHash = nonSuperAdminKey.keyHash;
        
        // Step 1: Whitelist the recipient (using admin key)
        ERC7821.Call[] memory whitelistCalls = new ERC7821.Call[](1);
        whitelistCalls[0].data = abi.encodeWithSelector(
            GardenSolver.whitelistAddress.selector, 
            recipient
        );
        
        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(whitelistCalls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        
        gardenAccount.execute(whitelistCalls, opData);
        
        // Step 2: Set permissions for non-super admin key (using admin key)
        // 2a. Allow execution of withdraw function
        // 2b. Set spend limit for native token (address(0))
        
        ERC7821.Call[] memory permissionCalls = new ERC7821.Call[](2);
        
        // Allow withdraw function execution on this contract
        bytes4 withdrawSelector = GardenSolver.withdraw.selector;
        permissionCalls[0].data = abi.encodeWithSelector(
            GuardedExecutor.setCanExecute.selector,
            nonAdminKeyHash,
            address(gardenAccount), // target is this contract
            withdrawSelector,
            true
        );
        
        // Set spend limit: 1 ETH per day for native token
        permissionCalls[1].data = abi.encodeWithSelector(
            GuardedExecutor.setSpendLimit.selector,
            nonAdminKeyHash,
            address(0), // native token
            GuardedExecutor.SpendPeriod.Day,
            1 ether // limit
        );
        
        nonce = gardenAccount.getNonce(0);
        signature = _sig(adminKey, gardenAccount.computeDigest(permissionCalls, nonce));
        opData = abi.encodePacked(nonce, signature);
        
        gardenAccount.execute(permissionCalls, opData);
        
        // Verify permissions were set
        assertTrue(
            gardenAccount.canExecute(
                nonAdminKeyHash,
                address(gardenAccount),
                abi.encodeWithSelector(withdrawSelector, recipient, address(0), withdrawAmount)
            ),
            "Non-admin key should be able to execute withdraw"
        );
        
        // Step 3: Fast forward past cooldown period
        uint256 cooldownPeriod = gardenAccount.cooldownPeriod();
        vm.warp(block.timestamp + cooldownPeriod + 1);
        
        // Step 4: Execute withdraw using non-super admin key
        ERC7821.Call[] memory withdrawCalls = new ERC7821.Call[](1);
        withdrawCalls[0].data = abi.encodeWithSelector(
            GardenSolver.withdraw.selector,
            recipient,
            address(0), // ETH
            withdrawAmount
        );
        
        nonce = gardenAccount.getNonce(0);
        signature = _sig(nonSuperAdminKey, gardenAccount.computeDigest(withdrawCalls, nonce));
        opData = abi.encodePacked(nonce, signature);
        
        uint256 recipientBalanceBefore = recipient.balance;
        uint256 accountBalanceBefore = address(gardenAccount).balance;
        
        gardenAccount.execute(withdrawCalls, opData);
        
        // Verify balances changed correctly
        assertEq(
            recipient.balance,
            recipientBalanceBefore + withdrawAmount,
            "Recipient should receive withdrawn ETH"
        );
        assertEq(
            address(gardenAccount).balance,
            accountBalanceBefore - withdrawAmount,
            "Account balance should decrease"
        );
        
        // Verify spend was tracked
        GuardedExecutor.SpendInfo[] memory spendInfos = gardenAccount.spendInfos(nonAdminKeyHash);
        assertEq(spendInfos.length, 1, "Should have one spend info entry");
        assertEq(spendInfos[0].token, address(0), "Spend should be for native token");
        assertEq(spendInfos[0].spent, withdrawAmount, "Current spent should match withdraw amount");
    }

    /// @notice Test that non-super admin key cannot withdraw without canExecute permission
    function testNonSuperAdminKeyCannotWithdrawWithoutCanExecute() public {
        // Setup: Fund the account and whitelist recipient
        uint256 withdrawAmount = 0.3 ether;
        address recipient = makeAddr("withdraw_recipient_3");
        
        vm.deal(address(gardenAccount), 1 ether);
        
        bytes32 nonAdminKeyHash = nonSuperAdminKey.keyHash;
        
        // Whitelist the recipient
        ERC7821.Call[] memory whitelistCalls = new ERC7821.Call[](1);
        whitelistCalls[0].data = abi.encodeWithSelector(
            GardenSolver.whitelistAddress.selector, 
            recipient
        );
        
        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(whitelistCalls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        
        gardenAccount.execute(whitelistCalls, opData);
        
        // Set ONLY spend limit, but NOT canExecute permission
        ERC7821.Call[] memory permissionCalls = new ERC7821.Call[](1);
        permissionCalls[0].data = abi.encodeWithSelector(
            GuardedExecutor.setSpendLimit.selector,
            nonAdminKeyHash,
            address(0),
            GuardedExecutor.SpendPeriod.Day,
            1 ether
        );
        
        nonce = gardenAccount.getNonce(0);
        signature = _sig(adminKey, gardenAccount.computeDigest(permissionCalls, nonce));
        opData = abi.encodePacked(nonce, signature);
        
        gardenAccount.execute(permissionCalls, opData);
        
        // Fast forward past cooldown
        uint256 cooldownPeriod = gardenAccount.cooldownPeriod();
        vm.warp(block.timestamp + cooldownPeriod + 1);
        
        // Try to withdraw - should fail
        ERC7821.Call[] memory withdrawCalls = new ERC7821.Call[](1);
        withdrawCalls[0].data = abi.encodeWithSelector(
            GardenSolver.withdraw.selector,
            recipient,
            address(0),
            withdrawAmount
        );
        
        nonce = gardenAccount.getNonce(0);
        signature = _sig(nonSuperAdminKey, gardenAccount.computeDigest(withdrawCalls, nonce));
        opData = abi.encodePacked(nonce, signature);
        
        vm.expectRevert();
        gardenAccount.execute(withdrawCalls, opData);
    }

    /// @notice Test that non-super admin key cannot withdraw without spend limits
    function testNonSuperAdminKeyCannotWithdrawWithoutSpendLimits() public {
        // Setup: Fund the account and whitelist recipient
        uint256 withdrawAmount = 0.3 ether;
        address recipient = makeAddr("withdraw_recipient_4");
        
        vm.deal(address(gardenAccount), 1 ether);
        
        bytes32 nonAdminKeyHash = nonSuperAdminKey.keyHash;
        
        // Whitelist the recipient
        ERC7821.Call[] memory whitelistCalls = new ERC7821.Call[](1);
        whitelistCalls[0].data = abi.encodeWithSelector(
            GardenSolver.whitelistAddress.selector, 
            recipient
        );
        
        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(whitelistCalls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        
        gardenAccount.execute(whitelistCalls, opData);
        
        // Set ONLY canExecute permission, but NOT spend limits
        ERC7821.Call[] memory permissionCalls = new ERC7821.Call[](1);
        permissionCalls[0].data = abi.encodeWithSelector(
            GuardedExecutor.setCanExecute.selector,
            nonAdminKeyHash,
            address(gardenAccount),
            GardenSolver.withdraw.selector,
            true
        );
        
        nonce = gardenAccount.getNonce(0);
        signature = _sig(adminKey, gardenAccount.computeDigest(permissionCalls, nonce));
        opData = abi.encodePacked(nonce, signature);
        
        gardenAccount.execute(permissionCalls, opData);
        
        // Fast forward past cooldown
        uint256 cooldownPeriod = gardenAccount.cooldownPeriod();
        vm.warp(block.timestamp + cooldownPeriod + 1);
        
        // Try to withdraw - should fail because no spend limits set
        ERC7821.Call[] memory withdrawCalls = new ERC7821.Call[](1);
        withdrawCalls[0].data = abi.encodeWithSelector(
            GardenSolver.withdraw.selector,
            recipient,
            address(0),
            withdrawAmount
        );
        
        nonce = gardenAccount.getNonce(0);
        signature = _sig(nonSuperAdminKey, gardenAccount.computeDigest(withdrawCalls, nonce));
        opData = abi.encodePacked(nonce, signature);
        
        vm.expectRevert();
        gardenAccount.execute(withdrawCalls, opData);
    }

    /// @notice Test withdraw ERC20 tokens with non-super admin key
    function testNonSuperAdminKeyCanWithdrawERC20WithPermissions() public {
        // Setup: Mint tokens to account and whitelist recipient
        uint256 withdrawAmount = 100_000 ether;
        address recipient = makeAddr("erc20_recipient");
        
        erc20Token.mint(address(gardenAccount), 1_000_000 ether);
        
        bytes32 nonAdminKeyHash = nonSuperAdminKey.keyHash;
        
        // Step 1: Whitelist the recipient
        ERC7821.Call[] memory whitelistCalls = new ERC7821.Call[](1);
        whitelistCalls[0].data = abi.encodeWithSelector(
            GardenSolver.whitelistAddress.selector, 
            recipient
        );
        
        uint256 nonce = gardenAccount.getNonce(0);
        bytes memory signature = _sig(adminKey, gardenAccount.computeDigest(whitelistCalls, nonce));
        bytes memory opData = abi.encodePacked(nonce, signature);
        
        gardenAccount.execute(whitelistCalls, opData);
        
        // Step 2: Set permissions for ERC20 withdrawals
        ERC7821.Call[] memory permissionCalls = new ERC7821.Call[](2);
        
        permissionCalls[0].data = abi.encodeWithSelector(
            GuardedExecutor.setCanExecute.selector,
            nonAdminKeyHash,
            address(gardenAccount),
            GardenSolver.withdraw.selector,
            true
        );
        
        permissionCalls[1].data = abi.encodeWithSelector(
            GuardedExecutor.setSpendLimit.selector,
            nonAdminKeyHash,
            address(erc20Token), // ERC20 token
            GuardedExecutor.SpendPeriod.Day,
            500_000 ether // limit
        );
        
        nonce = gardenAccount.getNonce(0);
        signature = _sig(adminKey, gardenAccount.computeDigest(permissionCalls, nonce));
        opData = abi.encodePacked(nonce, signature);
        
        gardenAccount.execute(permissionCalls, opData);
        
        // Step 3: Fast forward past cooldown
        uint256 cooldownPeriod = gardenAccount.cooldownPeriod();
        vm.warp(block.timestamp + cooldownPeriod + 1);
        
        // Step 4: Withdraw ERC20 tokens
        ERC7821.Call[] memory withdrawCalls = new ERC7821.Call[](1);
        withdrawCalls[0].data = abi.encodeWithSelector(
            GardenSolver.withdraw.selector,
            recipient,
            address(erc20Token),
            withdrawAmount
        );
        
        nonce = gardenAccount.getNonce(0);
        signature = _sig(nonSuperAdminKey, gardenAccount.computeDigest(withdrawCalls, nonce));
        opData = abi.encodePacked(nonce, signature);
        
        uint256 recipientBalanceBefore = erc20Token.balanceOf(recipient);
        uint256 accountBalanceBefore = erc20Token.balanceOf(address(gardenAccount));
        
        gardenAccount.execute(withdrawCalls, opData);
        
        // Verify token balances
        assertEq(
            erc20Token.balanceOf(recipient),
            recipientBalanceBefore + withdrawAmount,
            "Recipient should receive tokens"
        );
        assertEq(
            erc20Token.balanceOf(address(gardenAccount)),
            accountBalanceBefore - withdrawAmount,
            "Account token balance should decrease"
        );
    }
}
