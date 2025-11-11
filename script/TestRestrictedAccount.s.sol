// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {IthacaAccount} from "../src/IthacaAccount.sol";
import {Orchestrator} from "../src/Orchestrator.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";
import {GuardedExecutor} from "../src/IthacaAccount.sol";
import {LibEIP7702} from "solady/accounts/LibEIP7702.sol";

/// @notice Simple test contract to call
contract TestTarget {
    event FunctionCalled(address caller, bytes data);

    uint256 public callCount;

    function targetFunction(bytes memory data) public payable {
        callCount++;
        emit FunctionCalled(msg.sender, data);
    }

    function otherFunction(bytes memory data) public {
        callCount++;
        emit FunctionCalled(msg.sender, data);
    }
}

interface IHTLC {
    function initiate(address redeemer, uint256 timelock, uint256 amount, bytes32 secretHash)
        external;
}

/// @title TestRestrictedAccount
/// @notice Deploys and tests restricted account flow on Base Sepolia
/// @dev This script:
///      1. Deploys Orchestrator, IthacaAccount implementation
///      2. Sets up a Solver EOA with EIP-7702 delegation
///      3. Creates a restricted key
///      4. Sets permissions for specific contract/function
///      5. Tests that restricted key can only call allowed function
contract TestRestrictedAccount is Script {
    // Deployed contracts
    Orchestrator public orchestrator;
    IthacaAccount public ithacaAccountImpl;
    address public solverEOA;
    address public testContract; // Contract to test calls against

    // Keys
    IthacaAccount.Key public restrictedKey;
    bytes32 public restrictedKeyHash;
    uint256 public restrictedPrivateKey; // Store for signing

    // Mainnet executor account
    IthacaAccount.Key public mainnetExecutorKey;
    bytes32 public mainnetExecutorKeyHash;
    uint256 public mainnetExecutorPrivateKey;

    // Deployer account
    uint256 public deployerPrivateKey;
    address public deployer;

    // Solver EOA account
    uint256 public solverEOAPrivateKey;
    address public solverEOAAddress;

    // Test contract address and function selector
    address public allowedContract;
    bytes4 public allowedFunctionSelector;
    uint256 constant CHAIN_ID = 11155111; // Sepolia
    address constant ITHACA_IMPL = 0x6b40BC85123Bf9CC1c6FFAC34296D58473382108; // your Ithaca implementation

    function setUp() public {
        // Get deployer private key from environment or use default
        deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        deployer = vm.addr(deployerPrivateKey);

        // Generate solver EOA (deterministic)
        solverEOAPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        solverEOAAddress = vm.addr(solverEOAPrivateKey);

        console.log("\n========================================");
        console.log("SETUP: Generating Accounts");
        console.log("========================================\n");

        console.log("Deployer Address:", deployer);
        console.log("Solver EOA Address:", solverEOAAddress);

        // Set solverEOA since we manually delegated via cast send
        solverEOA = solverEOAAddress;

        // Set values from previous runs
        restrictedPrivateKey = uint256(keccak256("RESTRICTED_KEY_V1"));
        console.log("Restricted Private Key (hex):", restrictedPrivateKey);

        restrictedKeyHash = 0x3c05214ea15b85b7e48237aa72ff9fbf95b582eeba266365835bb2558366c5cd;
        allowedContract = 0x098Fd27df763E5361Da026412d1C8702AcB56c98;
        allowedFunctionSelector = bytes4(0x3c78f395);

        // uint256 eoaPrivateKey = vm.envUint("EOA_PRIVATE_KEY");
        // address eoaAddress = vm.addr(eoaPrivateKey);
        // uint256 eoaNonce = uint256(vm.getNonce(eoaAddress)); // or hardcode cast nonce ...
        // bytes32 messageHash = keccak256(abi.encode(CHAIN_ID, ITHACA_IMPL, eoaNonce));
        // bytes32 ethSignedHash =
        //     keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        // (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaPrivateKey, ethSignedHash);
        // uint8 yParity = v - 27; // Convert recovery id to y_parity (0 or 1)
        // bytes memory authTuple = abi.encode(CHAIN_ID, ITHACA_IMPL, eoaNonce, yParity, r, s);
        // bytes memory authorizationList = abi.encode(authTuple);

        // console2.log("EOA Address: %s", eoaAddress);
        // console2.log("Current Nonce: %s", eoaNonce);
        // console2.log("Authorization List (hex): %s", vm.toString(authorizationList));
        // console2.log("Authorization Tuple (hex): %s", vm.toString(authTuple));
    }

    function run() public {
        // Phase 1: Deploy Contracts
        // deployContracts();

        // Phase 2: Setup Solver with EIP-7702
        // setupSolverDelegation();

        // Phase 3: Create and authorize restricted key
        // createRestrictedKey(); // Already done - tx hash: 0xe194559c3379d8a70375006172a60d4e39f479d2d38f3c657bc8076f30d3c9e9

        // Phase 4: Set permissions
        // setPermissions();

        // // Phase 5: Test restricted account flow
        // testRestrictedAccount();

        // // Print summary
        // printSummary();

        // Phase 6: Set HTLC permissions
        // setHTLCPermissions();
        testHTLCInteraction();
    }

    function deployContracts() internal {
        console.log("\n========================================");
        console.log("PHASE 1: Deploying Contracts");
        console.log("========================================\n");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy Orchestrator
        console.log("Deploying Orchestrator...");
        orchestrator = new Orchestrator();
        console.log("Orchestrator deployed at:", address(orchestrator));

        // Deploy IthacaAccount implementation
        console.log("Deploying IthacaAccount implementation...");
        ithacaAccountImpl = new IthacaAccount(address(orchestrator));
        console.log("IthacaAccount deployed at:", address(ithacaAccountImpl));

        // Deploy test contract
        console.log("Deploying TestTarget contract...");
        TestTarget testTarget = new TestTarget();
        testContract = address(testTarget);
        allowedContract = testContract;
        allowedFunctionSelector = TestTarget.targetFunction.selector;
        console.log("TestTarget deployed at:", testContract);
        console.log("Target function selector:", vm.toString(allowedFunctionSelector));

        vm.stopBroadcast();

        console.log("\n[OK] All contracts deployed successfully!");
    }

    function setupSolverDelegation() internal {
        console.log("\n========================================");
        console.log("PHASE 2: Setup Solver with EIP-7702 Delegation");
        console.log("========================================\n");

        // Fund solver EOA if needed (check balance)
        uint256 balance = solverEOAAddress.balance;
        if (balance < 0.01 ether) {
            console.log("WARNING: Solver EOA has low balance:", balance);
            console.log("Please fund:", solverEOAAddress);
        }

        // Delegate solver EOA to IthacaAccount using EIP-7702
        console.log("Delegating solver EOA to IthacaAccount...");
        vm.startBroadcast(solverEOAPrivateKey);

        // Use vm.etch to set EIP-7702 delegation
        // In production, this would be done via EIP-7702 transaction
        bytes memory delegationCode = abi.encodePacked(hex"ef0100", address(ithacaAccountImpl));
        vm.etch(solverEOAAddress, delegationCode);

        solverEOA = solverEOAAddress;
        console.log("Solver EOA:", solverEOA);
        console.log("Delegated to:", address(ithacaAccountImpl));

        vm.stopBroadcast();

        console.log("[OK] Solver EOA delegated to IthacaAccount");
    }

    function createRestrictedKey() internal {
        console.log("\n========================================");
        console.log("PHASE 3: Create and Authorize Restricted Key");
        console.log("========================================\n");

        // Create a restricted key (secp256k1 for simplicity)
        restrictedPrivateKey = uint256(keccak256("RESTRICTED_KEY_V1"));
        address restrictedAddress = vm.addr(restrictedPrivateKey);

        restrictedKey = IthacaAccount.Key({
            expiry: uint40(block.timestamp + 30 days),
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(restrictedAddress)
        });

        restrictedKeyHash =
            keccak256(abi.encode(uint8(restrictedKey.keyType), keccak256(restrictedKey.publicKey)));

        console.log("Restricted Key Address:", restrictedAddress);
        console.log("Restricted KeyHash:", vm.toString(restrictedKeyHash));
        console.log("Expiry:", restrictedKey.expiry);

        // Authorize the key using solver EOA (bytes32(0) = EOA key)
        console.log("\nAuthorizing restricted key...");
        vm.startBroadcast(solverEOAPrivateKey);

        IthacaAccount account = IthacaAccount(payable(solverEOA));
        bytes32 authorizedHash = account.authorize(restrictedKey);
        require(authorizedHash == restrictedKeyHash, "Key hash mismatch");

        // Verify key was stored
        IthacaAccount.Key memory verifyKey = account.getKey(restrictedKeyHash);
        require(verifyKey.keyType == restrictedKey.keyType, "Key type mismatch");

        vm.stopBroadcast();

        console.log("[OK] Restricted key authorized and verified");
    }

    function setPermissions() internal {
        restrictedKeyHash = 0x3c05214ea15b85b7e48237aa72ff9fbf95b582eeba266365835bb2558366c5cd;
        allowedContract = 0x098Fd27df763E5361Da026412d1C8702AcB56c98;
        allowedFunctionSelector = bytes4(0x3c78f395);
        console.log("\n========================================");
        console.log("PHASE 4: Set Permissions");
        console.log("========================================\n");

        console.log("Setting permissions for restricted key:");
        console.log("  Contract:", allowedContract);
        console.log("  Function:", vm.toString(allowedFunctionSelector));

        vm.startBroadcast(solverEOAPrivateKey);

        IthacaAccount account = IthacaAccount(payable(solverEOA));
        account.setCanExecute(restrictedKeyHash, allowedContract, allowedFunctionSelector, true);

        // Verify permission was set
        bool canExecute = account.canExecute(
            restrictedKeyHash,
            allowedContract,
            abi.encodeWithSelector(allowedFunctionSelector, "test")
        );
        require(canExecute, "Permission not set correctly");

        vm.stopBroadcast();

        console.log("[OK] Permissions set: restricted key can call targetFunction on test contract");
    }

    function setHTLCPermissions() internal {
        restrictedKeyHash = 0x3c05214ea15b85b7e48237aa72ff9fbf95b582eeba266365835bb2558366c5cd;
        allowedContract = 0x917cfef972d667dC0FeC76806cB5623585B81493;
        allowedFunctionSelector = bytes4(0x97ffc7ae);
        console.log("\n========================================");
        console.log("PHASE 4: Set Permissions");
        console.log("========================================\n");

        console.log("Setting permissions for restricted key:");
        console.log("  Contract:", allowedContract);
        console.log("  Function:", vm.toString(allowedFunctionSelector));

        vm.startBroadcast(solverEOAPrivateKey);

        IthacaAccount account = IthacaAccount(payable(solverEOA));
        account.setCanExecute(restrictedKeyHash, allowedContract, allowedFunctionSelector, true);

        // Verify permission was set
        bool canExecute = account.canExecute(
            restrictedKeyHash,
            allowedContract,
            abi.encodeWithSelector(allowedFunctionSelector, makeAddr("HTLC"), 100, 100, bytes32(0))
        );
        require(canExecute, "Permission not set correctly");

        vm.stopBroadcast();

        console.log("[OK] Permissions set: restricted key can call targetFunction on test contract");
    }

    function testRestrictedAccount() internal {
        console.log("\n========================================");
        console.log("PHASE 5: Test Restricted Account Flow");
        console.log("========================================\n");

        // Test allowed call (requires broadcast)
        // vm.startBroadcast(solverEOAPrivateKey);
        // _testAllowedCall();
        // vm.stopBroadcast();

        // Test unauthorized calls (simulation only - no broadcast needed)
        _testUnauthorizedFunction();
        _testUnauthorizedContract();

        console.log("\n[OK] All tests passed!");
    }

    function testHTLCInteraction() internal {
        console.log("\n========================================");
        console.log("PHASE 5: Test Restricted Account Flow");
        console.log("========================================\n");

        // Test allowed call (requires broadcast)
        vm.startBroadcast(restrictedPrivateKey);
        _testAllowedHTLCCall();
        vm.stopBroadcast();

        // Test unauthorized calls (simulation only - no broadcast needed)
        // _testUnauthorizedFunction();
        // _testUnauthorizedContract();

        console.log("\n[OK] All tests passed!");
    }

    function _testAllowedCall() internal {
        console.log("Test 1: Restricted key calls allowed function...");
        IthacaAccount account = IthacaAccount(payable(solverEOA));
        TestTarget target = TestTarget(allowedContract);
        uint256 initialCallCount = target.callCount();

        bytes memory testData = abi.encode("test data");
        bytes memory callData = abi.encodeWithSelector(allowedFunctionSelector, testData);

        _executeCall(account, allowedContract, callData);

        require(target.callCount() == initialCallCount + 1, "Function was not called");
        console.log("[OK] Restricted key successfully called allowed function!");
    }

    function _testAllowedHTLCCall() internal {
        console.log("Test 1: Restricted key calls allowed HTLC function...");
        allowedContract = 0x917cfef972d667dC0FeC76806cB5623585B81493;
        IthacaAccount account = IthacaAccount(payable(solverEOA));

        // bytes memory testData =
        //     abi.encode(makeAddr("HTLC"), 100, 100, keccak256(abi.encode("secret")));
        bytes memory callData = abi.encodeWithSelector(
            IHTLC.initiate.selector, makeAddr("HTLC"), 100, 100, keccak256(abi.encode("secret_1"))
        );

        _executeCall(account, allowedContract, callData);
        console.log("[OK] Restricted key successfully called allowed HTLC function!");
    }

    function _testUnauthorizedFunction() internal {
        console.log("\nTest 2: Restricted key tries to call different function (should fail)...");
        IthacaAccount account = IthacaAccount(payable(solverEOA));
        bytes4 differentSelector = TestTarget.otherFunction.selector;
        bytes memory testData = abi.encode("test data");
        bytes memory callData = abi.encodeWithSelector(differentSelector, testData);

        bool failed = _tryExecuteCall(account, allowedContract, callData);
        require(failed, "Should have failed with UnauthorizedCall");
        console.log("[OK] Restricted key correctly blocked from calling different function");
    }

    function _testUnauthorizedContract() internal {
        console.log("\nTest 3: Restricted key tries to call on different contract (should fail)...");
        IthacaAccount account = IthacaAccount(payable(solverEOA));
        address differentContract = makeAddr("DifferentContract");
        bytes memory testData = abi.encode("test data");
        bytes memory callData = abi.encodeWithSelector(allowedFunctionSelector, testData);

        bool failed = _tryExecuteCall(account, differentContract, callData);
        require(failed, "Should have failed with UnauthorizedCall");
        console.log("[OK] Restricted key correctly blocked from calling on different contract");
    }

    function _executeCall(IthacaAccount account, address target, bytes memory data) internal {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({to: target, value: 0, data: data});

        uint256 nonce = account.getNonce(0);
        bytes32 digest = account.computeDigest(calls, nonce);
        bytes memory signature = _signDigest(digest);

        bytes32 executionMode = 0x0100000000007821000100000000000000000000000000000000000000000000;
        account.execute(executionMode, abi.encode(calls, abi.encodePacked(nonce, signature)));
    }

    function _tryExecuteCall(IthacaAccount account, address target, bytes memory data)
        internal
        returns (bool failed)
    {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({to: target, value: 0, data: data});

        uint256 nonce = account.getNonce(0);
        bytes32 digest = account.computeDigest(calls, nonce);
        bytes memory signature = _signDigest(digest);

        bytes32 executionMode = 0x0100000000007821000100000000000000000000000000000000000000000000;

        try account.execute(executionMode, abi.encode(calls, abi.encodePacked(nonce, signature))) {
            return false;
        } catch (bytes memory reason) {
            bytes4 errorSelector = bytes4(reason);
            return errorSelector == GuardedExecutor.UnauthorizedCall.selector;
        }
    }

    function _signDigest(bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(restrictedPrivateKey, digest);
        return abi.encodePacked(abi.encodePacked(r, s, v), restrictedKeyHash, uint8(0));
    }

    function printSummary() internal view {
        console.log("\n========================================");
        console.log("DEPLOYMENT SUMMARY");
        console.log("========================================\n");

        console.log("Deployed Contracts:");
        console.log("- Orchestrator:", address(orchestrator));
        console.log("- IthacaAccount:", address(ithacaAccountImpl));
        console.log("- TestTarget:", testContract);

        console.log("\nSolver Account:");
        console.log("- EOA Address:", solverEOA);
        console.log("- Delegated to:", address(ithacaAccountImpl));

        console.log("\nRestricted Key:");
        console.log("- KeyHash:", vm.toString(restrictedKeyHash));
        console.log("- Allowed Contract:", allowedContract);
        console.log("- Allowed Function:", vm.toString(allowedFunctionSelector));

        console.log("\nPrivate Keys (SAVE THESE!):");
        console.log("- Deployer:", vm.toString(deployerPrivateKey));
        console.log("- Solver EOA:", vm.toString(solverEOAPrivateKey));
        console.log("- Restricted Key:", vm.toString(restrictedPrivateKey));

        console.log("\n========================================");
        console.log("SUCCESS! Restricted account tested!");
        console.log("========================================\n");
    }
}
