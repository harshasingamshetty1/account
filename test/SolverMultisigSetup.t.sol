// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./Base.t.sol";
import {MultiSigSigner} from "../src/MultiSigSigner.sol";
import {IthacaAccount} from "../src/IthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";

/// @title SolverMultisigSetup
/// @notice Test demonstrating how to set up a Solver with multisig super admin
/// @dev This test proves that after destroying the original private key,
///      a multisig can still access all onlyThis functions like revoke()
contract SolverMultisigSetupTest is BaseTest {
    MultiSigSigner multiSigSigner;

    // Solver EOA
    DelegatedEOA solver;

    // Multisig signers (2 of 3)
    PassKey signer1;
    PassKey signer2;
    PassKey signer3;

    // Multisig super admin key
    IthacaAccount.Key multisigSuperAdminKey;
    bytes32 multisigKeyHash;

    // Regular bot key (for testing that it cannot call revoke)
    PassKey botKey;
    bytes32 botKeyHash;
    bytes4 public constant INITIATE_ON_BEHALF_SELECTOR = 0x13d4a787;

    function setUp() public override {
        super.setUp();

        // Deploy MultiSigSigner contract
        multiSigSigner = new MultiSigSigner();

        console.log("=== PHASE 1: Create Solver EOA and Delegate to IthacaAccount ===");

        // Create a fresh EOA for the solver
        (address solverAddress, uint256 solverPrivateKey) = makeAddrAndKey("solver");

        // Simulate EIP-7702 delegation using vm.etch
        // In production, this would be done via EIP-7702 transaction
        vm.etch(solverAddress, abi.encodePacked(hex"ef0100", address(account)));

        solver = DelegatedEOA({
            eoa: solverAddress, privateKey: solverPrivateKey, d: MockAccount(payable(solverAddress))
        });

        // Fund the solver with ETH and tokens
        vm.deal(solver.eoa, 100 ether);
        paymentToken.mint(solver.eoa, 1_000_000e6);

        console.log("Solver EOA:", solver.eoa);
        console.log("Solver ETH Balance:", solver.eoa.balance);
        console.log("Solver Token Balance:", paymentToken.balanceOf(solver.eoa));

        console.log("\n=== PHASE 2: Setup Multisig Signers ===");

        // Create 3 individual signer keys (these could be hardware wallets)
        signer1 = _randomPassKey();
        signer2 = _randomPassKey();
        signer3 = _randomPassKey();

        // Mark them as NOT super admins individually
        signer1.k.isSuperAdmin = false;
        signer2.k.isSuperAdmin = false;
        signer3.k.isSuperAdmin = false;

        console.log("Signer 1 KeyHash:", bytes32ToHex(signer1.keyHash));
        console.log("Signer 2 KeyHash:", bytes32ToHex(signer2.keyHash));
        console.log("Signer 3 KeyHash:", bytes32ToHex(signer3.keyHash));
    }

    /// @notice Test the complete flow: setup multisig, then use it to revoke a key
    function test_SolverWithMultisigSuperAdmin() public {
        console.log("\n=== PHASE 3: Authorize Individual Signers (Using Original Key) ===");

        // Using the original EOA key, authorize the 3 individual signer keys
        vm.startPrank(solver.eoa);

        bytes32 signer1Hash = solver.d.authorize(signer1.k);
        bytes32 signer2Hash = solver.d.authorize(signer2.k);
        bytes32 signer3Hash = solver.d.authorize(signer3.k);

        assertEq(signer1Hash, signer1.keyHash, "Signer 1 hash mismatch");
        assertEq(signer2Hash, signer2.keyHash, "Signer 2 hash mismatch");
        assertEq(signer3Hash, signer3.keyHash, "Signer 3 hash mismatch");

        console.log("[OK] All 3 signers authorized");

        vm.stopPrank();

        console.log("\n=== PHASE 4: Create Multisig Super Admin Key ===");

        // Create the multisig key with External type
        multisigSuperAdminKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true, // THIS is the super admin!
            publicKey: abi.encodePacked(address(multiSigSigner), bytes12(0))
        });

        // Authorize the multisig key (using original EOA key)
        vm.prank(solver.eoa);
        multisigKeyHash = solver.d.authorize(multisigSuperAdminKey);

        console.log("Multisig KeyHash:", bytes32ToHex(multisigKeyHash));
        // Verify it was authorized by checking we can retrieve it
        IthacaAccount.Key memory verifyKey = solver.d.getKey(multisigKeyHash);
        assertTrue(verifyKey.isSuperAdmin, "Multisig should be super admin");

        // Initialize the multisig config (2 of 3)
        // Important: initConfig must be called FROM the solver account!
        bytes32[] memory ownerKeyHashes = new bytes32[](3);
        ownerKeyHashes[0] = signer1.keyHash;
        ownerKeyHashes[1] = signer2.keyHash;
        ownerKeyHashes[2] = signer3.keyHash;

        vm.prank(solver.eoa);
        multiSigSigner.initConfig(multisigKeyHash, 2, ownerKeyHashes);

        (uint256 threshold, bytes32[] memory owners) =
            multiSigSigner.getConfig(solver.eoa, multisigKeyHash);
        assertEq(threshold, 2, "Threshold should be 2");
        assertEq(owners.length, 3, "Should have 3 owners");

        console.log("[OK] Multisig configured: 2 of 3");

        console.log("\n=== PHASE 5: Create a Bot Key to Test Revocation ===");

        // Create a regular bot key (NOT super admin)
        botKey = _randomPassKey();
        botKey.k.isSuperAdmin = false;
        botKey.k.expiry = uint40(block.timestamp + 30 days);

        vm.prank(solver.eoa);
        botKeyHash = solver.d.authorize(botKey.k);

        console.log("Bot KeyHash:", bytes32ToHex(botKeyHash));
        console.log("Bot Expiry:", botKey.k.expiry);

        // Verify bot key exists
        IthacaAccount.Key memory retrievedKey = solver.d.getKey(botKeyHash);
        assertEq(uint8(retrievedKey.keyType), uint8(botKey.k.keyType), "Bot key type mismatch");

        console.log("[OK] Bot key authorized");

        console.log("\n=== PHASE 6: DESTROY Original Private Key (Simulation) ===");
        console.log("[FIRE] Imagine we destroyed solver.privateKey here");
        console.log("[FIRE] From now on, ONLY the 2-of-3 multisig can call admin functions");

        console.log("\n=== PHASE 7: Test Multisig Can Revoke Keys ===");

        // Create a call to revoke the bot key
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: solver.eoa, // Call ourselves
            value: 0,
            data: abi.encodeWithSelector(IthacaAccount.revoke.selector, botKeyHash)
        });

        // Get nonce
        uint256 nonce = solver.d.getNonce(0);

        // Compute digest
        bytes32 digest = solver.d.computeDigest(calls, nonce);

        // Get signatures from 2 of 3 signers (signer1 and signer2)
        bytes[] memory innerSignatures = new bytes[](2);
        innerSignatures[0] = _sig(signer1, digest);
        innerSignatures[1] = _sig(signer2, digest);

        // Wrap the multisig signature
        bytes memory multisigSignature = abi.encodePacked(
            abi.encode(innerSignatures), // Inner signatures
            multisigKeyHash, // KeyHash
            uint8(0) // No prehash
        );

        console.log("Digest:", bytes32ToHex(digest));
        console.log("Multisig signature length:", multisigSignature.length);

        // Execute the revoke via multisig
        // Note: Anyone can submit this transaction, the security is in the signature!
        solver.d
            .execute(
                _ERC7821_BATCH_EXECUTION_MODE,
                abi.encode(calls, abi.encodePacked(nonce, multisigSignature))
            );

        console.log("[OK] Multisig successfully called revoke()!");

        // Verify the bot key was revoked
        vm.expectRevert(IthacaAccount.KeyDoesNotExist.selector);
        solver.d.getKey(botKeyHash);

        console.log("[OK] Bot key confirmed revoked");

        console.log("\n=== SUCCESS! Multisig has full admin access without original key! ===");
    }

    /// @notice Test that a regular key CANNOT call revoke() directly
    function test_RegularKeyCannotCallRevoke() public {
        console.log("\n=== Testing Regular Key Cannot Call Admin Functions ===");

        // Setup: authorize bot key
        botKey = _randomPassKey();
        botKey.k.isSuperAdmin = false;

        vm.prank(solver.eoa);
        botKeyHash = solver.d.authorize(botKey.k);

        // Create another key to try to revoke
        PassKey memory targetKey = _randomPassKey();
        vm.prank(solver.eoa);
        bytes32 targetKeyHash = solver.d.authorize(targetKey.k);

        // Try to revoke using bot key signature
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: solver.eoa,
            value: 0,
            data: abi.encodeWithSelector(IthacaAccount.revoke.selector, targetKeyHash)
        });

        uint256 nonce = solver.d.getNonce(0);
        bytes32 digest = solver.d.computeDigest(calls, nonce);
        bytes memory botSignature = abi.encodePacked(_sig(botKey, digest), botKeyHash, uint8(0));

        // This should REVERT because bot key is not super admin
        // and revoke() is a self-execute function
        vm.expectRevert();
        solver.d
            .execute(
                _ERC7821_BATCH_EXECUTION_MODE,
                abi.encode(calls, abi.encodePacked(nonce, botSignature))
            );

        console.log("[OK] Regular key correctly blocked from calling revoke()");
    }

    /// @notice Test multisig can also authorize new keys
    function test_MultisigCanAuthorizeNewKeys() public {
        // First set up multisig (reuse code from main test)
        _setupMultisig();

        console.log("\n=== Testing Multisig Can Authorize New Keys ===");

        // Create a new key to authorize
        PassKey memory newKey = _randomPassKey();
        newKey.k.isSuperAdmin = false;
        newKey.k.expiry = uint40(block.timestamp + 60 days);

        // Create a call to authorize the new key
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: solver.eoa,
            value: 0,
            data: abi.encodeWithSelector(IthacaAccount.authorize.selector, newKey.k)
        });

        uint256 nonce = solver.d.getNonce(0);
        bytes32 digest = solver.d.computeDigest(calls, nonce);

        // Get 2-of-3 signatures (signer2 and signer3 this time)
        bytes[] memory innerSignatures = new bytes[](2);
        innerSignatures[0] = _sig(signer2, digest);
        innerSignatures[1] = _sig(signer3, digest);

        bytes memory multisigSignature =
            abi.encodePacked(abi.encode(innerSignatures), multisigKeyHash, uint8(0));

        // Execute via multisig
        solver.d
            .execute(
                _ERC7821_BATCH_EXECUTION_MODE,
                abi.encode(calls, abi.encodePacked(nonce, multisigSignature))
            );

        // Verify the new key was authorized
        bytes32 expectedKeyHash = _hash(newKey.k);
        IthacaAccount.Key memory retrievedKey = solver.d.getKey(expectedKeyHash);
        assertEq(uint8(retrievedKey.keyType), uint8(newKey.k.keyType), "Key type mismatch");
        assertEq(retrievedKey.expiry, newKey.k.expiry, "Expiry mismatch");

        console.log("[OK] Multisig successfully authorized a new key!");
    }

    /// @notice Test that a restricted account can only call specific contract/function
    function test_RestrictedAccountCanOnlyCallSpecificContractAndFunction() public {
        console.log("\n=== Testing Restricted Account with Specific Permissions ===");

        // Create a new account/key
        PassKey memory restrictedKey = _randomPassKey();
        restrictedKey.k.isSuperAdmin = false;
        restrictedKey.k.expiry = uint40(block.timestamp + 30 days);

        // Authorize the new key using the original EOA key
        vm.prank(solver.eoa);
        bytes32 restrictedKeyHash = solver.d.authorize(restrictedKey.k);
        assertEq(restrictedKeyHash, restrictedKey.keyHash, "Restricted key hash mismatch");

        // Verify the key was stored
        IthacaAccount.Key memory verifyKey = solver.d.getKey(restrictedKeyHash);
        assertEq(uint8(verifyKey.keyType), uint8(restrictedKey.k.keyType), "Key type mismatch");

        console.log("Restricted KeyHash:", bytes32ToHex(restrictedKey.keyHash));
        console.log("[OK] Restricted key authorized and verified");

        // Define the allowed contract and function selector
        address allowedContract = address(this);
        bytes4 allowedFunctionSelector = this.targetFunction.selector;

        // Set permissions: allow the restricted key to call targetFunction on this contract
        _setCanExecute(restrictedKeyHash, allowedContract, allowedFunctionSelector, true);

        console.log("Allowed Contract:", allowedContract);
        console.log(
            "Allowed Function Selector:",
            bytes32ToHex(bytes32(uint256(uint32(allowedFunctionSelector)) << 224))
        );
        console.log("[OK] Permissions set: restricted key can call targetFunction on test contract");

        // Verify the permission was set correctly
        bool canExecute = solver.d
            .canExecute(
                restrictedKeyHash,
                allowedContract,
                abi.encodeWithSelector(allowedFunctionSelector, "test")
            );
        assertTrue(canExecute, "Restricted key should be able to execute allowed function");

        // Test 1: Verify the restricted key CAN call the allowed function
        console.log("\n=== Test 1: Restricted key calls allowed function ===");
        bytes memory testData = abi.encode("test data");
        delete targetFunctionPayloads;

        _executeCall(
            restrictedKey,
            restrictedKeyHash,
            allowedContract,
            abi.encodeWithSelector(allowedFunctionSelector, testData)
        );

        // Verify the call was executed
        assertEq(targetFunctionPayloads.length, 1, "targetFunction should have been called");
        assertEq(targetFunctionPayloads[0].by, solver.eoa, "Call should be from solver account");
        assertEq(targetFunctionPayloads[0].data, testData, "Call data should match");

        console.log("[OK] Restricted key successfully called allowed function!");

        // Test 2: Verify the restricted key CANNOT call a different function on the same contract
        console.log(
            "\n=== Test 2: Restricted key tries to call different function (should fail) ==="
        );
        bytes4 differentFunctionSelector = bytes4(keccak256("differentFunction(bytes)"));
        _testUnauthorizedCall(
            restrictedKey,
            restrictedKeyHash,
            allowedContract,
            abi.encodeWithSelector(differentFunctionSelector, testData)
        );
        console.log("[OK] Restricted key correctly blocked from calling different function");

        // Test 3: Verify the restricted key CANNOT call the allowed function on a different contract
        console.log(
            "\n=== Test 3: Restricted key tries to call allowed function on different contract (should fail) ==="
        );
        address differentContract = makeAddr("DifferentContract");
        _testUnauthorizedCall(
            restrictedKey,
            restrictedKeyHash,
            differentContract,
            abi.encodeWithSelector(allowedFunctionSelector, testData)
        );
        console.log(
            "[OK] Restricted key correctly blocked from calling function on different contract"
        );

        // Test 4: Verify the restricted key CANNOT call a different function on a different contract
        console.log(
            "\n=== Test 4: Restricted key tries to call different function on different contract (should fail) ==="
        );
        _testUnauthorizedCall(
            restrictedKey,
            restrictedKeyHash,
            differentContract,
            abi.encodeWithSelector(differentFunctionSelector, testData)
        );
        console.log(
            "[OK] Restricted key correctly blocked from calling different function on different contract"
        );

        console.log(
            "\n=== SUCCESS! Restricted account can only call the specific contract/function ==="
        );
    }

    /// @notice Helper to set canExecute permission
    function _setCanExecute(bytes32 keyHash, address target, bytes4 fnSel, bool can) internal {
        vm.prank(solver.eoa);
        solver.d.setCanExecute(keyHash, target, fnSel, can);
    }

    /// @notice Helper to execute a call with a restricted key
    function _executeCall(PassKey memory key, bytes32 keyHash, address target, bytes memory data)
        internal
    {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({to: target, value: 0, data: data});

        uint256 nonce = solver.d.getNonce(0);
        bytes32 digest = solver.d.computeDigest(calls, nonce);
        bytes memory signature = abi.encodePacked(_sig(key, digest), keyHash, uint8(0));

        solver.d
            .execute(
                _ERC7821_BATCH_EXECUTION_MODE, abi.encode(calls, abi.encodePacked(nonce, signature))
            );
    }

    /// @notice Helper to test that an unauthorized call reverts
    function _testUnauthorizedCall(
        PassKey memory key,
        bytes32 keyHash,
        address target,
        bytes memory data
    ) internal {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({to: target, value: 0, data: data});

        uint256 nonce = solver.d.getNonce(0);
        bytes32 digest = solver.d.computeDigest(calls, nonce);
        bytes memory signature = abi.encodePacked(_sig(key, digest), keyHash, uint8(0));

        vm.expectRevert(
            abi.encodeWithSelector(GuardedExecutor.UnauthorizedCall.selector, keyHash, target, data)
        );
        solver.d
            .execute(
                _ERC7821_BATCH_EXECUTION_MODE, abi.encode(calls, abi.encodePacked(nonce, signature))
            );
    }

    /// @notice Helper to set up multisig (for reuse in tests)
    function _setupMultisig() internal {
        // Create signers
        signer1 = _randomPassKey();
        signer2 = _randomPassKey();
        signer3 = _randomPassKey();

        signer1.k.isSuperAdmin = false;
        signer2.k.isSuperAdmin = false;
        signer3.k.isSuperAdmin = false;

        // Authorize signers
        vm.startPrank(solver.eoa);
        solver.d.authorize(signer1.k);
        solver.d.authorize(signer2.k);
        solver.d.authorize(signer3.k);

        // Create and authorize multisig
        multisigSuperAdminKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(address(multiSigSigner), bytes12(0))
        });

        multisigKeyHash = solver.d.authorize(multisigSuperAdminKey);
        vm.stopPrank();

        // Initialize multisig config
        bytes32[] memory ownerKeyHashes = new bytes32[](3);
        ownerKeyHashes[0] = signer1.keyHash;
        ownerKeyHashes[1] = signer2.keyHash;
        ownerKeyHashes[2] = signer3.keyHash;

        vm.prank(solver.eoa);
        multiSigSigner.initConfig(multisigKeyHash, 2, ownerKeyHashes);
    }

    /// @notice Helper to convert bytes32 to hex string for logging
    function bytes32ToHex(bytes32 data) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory result = new bytes(66);
        result[0] = "0";
        result[1] = "x";

        for (uint256 i = 0; i < 32; i++) {
            result[2 + i * 2] = hexChars[uint8(data[i] >> 4)];
            result[3 + i * 2] = hexChars[uint8(data[i] & 0x0f)];
        }

        return string(result);
    }
}
