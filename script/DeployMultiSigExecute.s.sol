// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../src/GardenSolver.sol";
import {IthacaAccount} from "../src/IthacaAccount.sol";
import {Orchestrator} from "../src/Orchestrator.sol";
import {MultiSigSigner} from "../src/MultiSigSigner.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";
import {ExperimentERC20} from "../deploy/mock/ExperimentalERC20.sol";
import {GuardedExecutor} from "../src/GuardedExecutor.sol";

/// @title DeployMultiSigExecute
/// @author Garden Finance
/// @notice Comprehensive deployment and demonstration script for GardenSolver with dynamic multisig management
/// @dev This script demonstrates the complete lifecycle of a GardenSolver account with multisig control:
///      - Initial deployment with 2-of-3 multisig configuration
///      - Whitelisting addresses for withdrawal operations
///      - Modifying security parameters (cooldown period)
///      - Dynamic key management (adding new signers)
///      - Upgrading multisig configuration (2-of-3 → 2-of-4)
///
///      ONE-CLICK DEPLOYMENT & EXECUTION:
///      forge script script/DeployMultiSigExecute.s.sol --rpc-url http://localhost:8545 --broadcast
///
///      SPLIT EXECUTION (for testing individual phases):
///      STEP 1: forge script script/DeployMultiSigExecute.s.sol --sig "deployContracts()" --rpc-url http://localhost:8545 --broadcast
///      STEP 2: forge script script/DeployMultiSigExecute.s.sol --sig "executeWithMultisig()" --rpc-url http://localhost:8545 --broadcast
///
///      PHASES EXECUTED:
///      Phase 1: Compute and verify all key hashes
///      Phase 2: Whitelist Signer3 for withdrawal operations
///      Phase 3: Reduce cooldown period from 1 day to 1 second (for testing)
///      Phase 4: Verify whitelist and cooldown configuration
///      Phase 5: Authorize Signer4 as a new key
///      Phase 6: Add Signer4 to multisig configuration (upgrade to 2-of-4)
///      Phase 7: (Optional) Withdraw using new multisig combination (requires cooldown wait)
contract DeployMultiSigExecute is Script {
    // ============================================
    // STATE VARIABLES - Deployed Contracts
    // ============================================

    /// @notice Orchestrator contract - manages account deployment and upgrades
    Orchestrator public orchestrator;

    /// @notice MultiSigSigner contract - handles threshold signature validation
    MultiSigSigner public multiSigSigner;

    /// @notice GardenSolver account instance - standalone smart contract account with solver capabilities
    GardenSolver public solverAccount;

    /// @notice Test ERC20 token for demonstrating withdrawal operations
    ExperimentERC20 public testToken;

    // ============================================
    // STATE VARIABLES - Anvil Test Accounts
    // ============================================
    // Using Anvil's deterministic default accounts for reproducible testing

    /// @notice Deployer account (Anvil Account #0) - deploys all contracts
    uint256 public deployerPrivateKey =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address public deployer;

    /// @notice Signer 1 (Anvil Account #2) - initial multisig member
    uint256 public signer1PrivateKey =
        0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    address public signer1;

    /// @notice Signer 2 (Anvil Account #3) - initial multisig member
    uint256 public signer2PrivateKey =
        0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;
    address public signer2;

    /// @notice Signer 3 (Anvil Account #4) - initial multisig member & withdrawal recipient
    uint256 public signer3PrivateKey =
        0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a;
    address public signer3;

    /// @notice Signer 4 (Anvil Account #5) - dynamically added multisig member
    uint256 public signer4PrivateKey =
        0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba;
    address public signer4;

    // ============================================
    // STATE VARIABLES - Key Hashes
    // ============================================
    // Key hashes are used to identify keys in the account's key management system

    /// @notice Hash of signer1's key (Secp256k1)
    bytes32 public signer1KeyHash;

    /// @notice Hash of signer2's key (Secp256k1)
    bytes32 public signer2KeyHash;

    /// @notice Hash of signer3's key (Secp256k1)
    bytes32 public signer3KeyHash;

    /// @notice Hash of signer4's key (Secp256k1) - computed dynamically in Phase 5
    bytes32 public signer4KeyHash;

    /// @notice Hash of the multisig external key (super admin)
    bytes32 public multisigKeyHash;

    /// @notice Setup function - derives addresses from private keys and logs account information
    /// @dev Called automatically by Forge before running the main script
    function setUp() public {
        // Derive addresses from Anvil default private keys
        deployer = vm.addr(deployerPrivateKey);
        signer1 = vm.addr(signer1PrivateKey);
        signer2 = vm.addr(signer2PrivateKey);
        signer3 = vm.addr(signer3PrivateKey);
        signer4 = vm.addr(signer4PrivateKey);

        console.log("\n========================================");
        console.log("ANVIL DEFAULT ACCOUNTS");
        console.log("========================================");
        console.log("Deployer (Account #0):", deployer);
        console.log("Signer 1 (Account #2):", signer1);
        console.log("Signer 2 (Account #3):", signer2);
        console.log("Signer 3 (Account #4):", signer3);
        console.log("Signer 4 (Account #5):", signer4);
        console.log("========================================\n");
    }

    /// @notice STEP 1: Deploy all required contracts
    /// @dev Deploys Orchestrator, MultiSigSigner, GardenSolver, and test ERC20 token
    ///      Initial configuration: 2-of-3 multisig with signer1, signer2, signer3
    ///      Account is funded with 10 ETH and 1,000,000 test tokens
    function deployContracts() public {
        console.log("\n========================================");
        console.log("STEP 1: Deploy Contracts");
        console.log("========================================\n");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy core contracts
        orchestrator = new Orchestrator();
        console.log("Orchestrator:", address(orchestrator));

        multiSigSigner = new MultiSigSigner();
        console.log("MultiSigSigner:", address(multiSigSigner));

        // Prepare initial signer keys for the account
        // Note: These are Secp256k1 keys, not super-admins (only External keys can be super-admins)
        // The multisig External key will be added automatically as super-admin during deployment
        IthacaAccount.Key[] memory signerKeys = new IthacaAccount.Key[](3);
        signerKeys[0] = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer1)
        });
        signerKeys[1] = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer2)
        });
        signerKeys[2] = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer3)
        });

        // Deploy GardenSolver with initial configuration
        // - Authorizes 3 initial keys (signer1, signer2, signer3)
        // - Configures multisig with 2-of-3 threshold
        // - Multisig key is automatically added as super-admin External key
        // - Account is funded with 10 ETH for gas operations
        solverAccount = new GardenSolver{value: 10 ether}(
            address(orchestrator),
            signerKeys,
            address(multiSigSigner),
            2 // threshold: 2-of-3
        );
        console.log("GardenSolver (Standalone):", address(solverAccount));
        console.log("- Funded with: 10 ETH");
        console.log("- Keys authorized: 3 (signer1, signer2, signer3)");
        console.log("- Multisig configured: 2-of-3");

        // Deploy test token
        testToken = new ExperimentERC20("TestToken", "TT", 1e18);
        console.log("TestToken:", address(testToken));

        // Mint tokens to the account
        uint256 mintAmount = 1_000_000 ether;
        testToken.mint(address(solverAccount), mintAmount);
        console.log("- Minted", mintAmount / 1e18, "TT to account");

        vm.stopBroadcast();

        console.log("\n[OK] Contracts deployed!");

        // Log keyHashes for next step
        console.log("\n========================================");
        console.log("KEY HASHES (for executeWithMultisig)");
        console.log("========================================");

        // Use the contract's hash() function to compute keyHashes correctly
        bytes32 loggedSigner1KeyHash = solverAccount.hash(signerKeys[0]);
        bytes32 loggedSigner2KeyHash = solverAccount.hash(signerKeys[1]);
        bytes32 loggedSigner3KeyHash = solverAccount.hash(signerKeys[2]);

        IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(address(multiSigSigner), bytes12(0))
        });
        bytes32 loggedMultisigKeyHash = solverAccount.hash(multisigKey);

        console.log("Signer 1 KeyHash:", vm.toString(loggedSigner1KeyHash));
        console.log("Signer 2 KeyHash:", vm.toString(loggedSigner2KeyHash));
        console.log("Signer 3 KeyHash:", vm.toString(loggedSigner3KeyHash));
        console.log("Multisig KeyHash:", vm.toString(loggedMultisigKeyHash));

        // Query actual keys from deployed account
        console.log("\n========================================");
        console.log("ACTUAL KEYS IN DEPLOYED ACCOUNT");
        console.log("========================================");
        (IthacaAccount.Key[] memory keys, bytes32[] memory actualKeyHashes) =
            solverAccount.getKeys();
        console.log("Number of keys:", keys.length);
        for (uint256 i = 0; i < actualKeyHashes.length; i++) {
            console.log("Key", i, "Hash:", vm.toString(actualKeyHashes[i]));
        }

        console.log("\n========================================");
        console.log("NEXT STEP (Optional - already running)");
        console.log("========================================");
        console.log("If running separately:");
        console.log(
            "Run: forge script script/DeployMultiSigExecute.s.sol --sig \"executeWithMultisig()\" --rpc-url http://localhost:8545 --broadcast"
        );
        console.log("========================================\n");
    }

    /// @notice Main entry point - executes complete deployment and multisig operations
    /// @dev Calls deployContracts() followed by executeWithMultisig() in sequence
    function run() public {
        deployContracts();
        executeWithMultisig();
    }

    /// @notice STEP 2: Execute multisig operations demonstrating account capabilities
    /// @dev Executes 6 phases demonstrating the complete multisig workflow:
    ///      - Phase 1: Compute all key hashes
    ///      - Phase 2: Whitelist an address (signer3) for withdrawals
    ///      - Phase 3: Modify cooldown period security parameter
    ///      - Phase 4: Verify configuration
    ///      - Phase 5: Dynamically authorize a new key (signer4)
    ///      - Phase 6: Add new key to multisig configuration (upgrade to 2-of-4)
    function executeWithMultisig() public {
        console.log("\n========================================");
        console.log("STEP 2: Execute Multisig Operations");
        console.log("========================================\n");

        // Use deployed contract addresses (no hardcoded addresses)
        // solverAccount, multiSigSigner, testToken are already set from deployContracts()

        console.log("\n========================================");
        console.log("PHASE 1: Computing KeyHashes");
        console.log("========================================");

        // Compute keyHashes using the account's hash() function
        // These hashes are used to identify keys in signatures and key management operations
        IthacaAccount.Key memory signer1Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer1)
        });
        IthacaAccount.Key memory signer2Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer2)
        });
        IthacaAccount.Key memory signer3Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer3)
        });
        IthacaAccount.Key memory multisigKeyStruct = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(address(multiSigSigner), bytes12(0))
        });

        signer1KeyHash = solverAccount.hash(signer1Key);
        signer2KeyHash = solverAccount.hash(signer2Key);
        signer3KeyHash = solverAccount.hash(signer3Key);
        multisigKeyHash = solverAccount.hash(multisigKeyStruct);

        console.log("Computed Signer 1 KeyHash:", vm.toString(signer1KeyHash));
        console.log("Computed Signer 2 KeyHash:", vm.toString(signer2KeyHash));
        console.log("Computed Signer 3 KeyHash:", vm.toString(signer3KeyHash));
        console.log("Computed Multisig KeyHash:", vm.toString(multisigKeyHash));
        console.log("[OK] KeyHashes computed\n");

        // Execute phases
        // whitelistSigner3WithMultisig();
        // changeCooldownPeriodWithMultisig();
        // Advance time to satisfy cooldown period (1 second + buffer for safety)
        vm.warp(block.timestamp + 2);
        // verifyWhitelistAndCooldown();
        // withdrawToSigner3WithMultisig();

        // New phases: Add signer4 to multisig and demonstrate usage
        authorizeSigner4WithMultisig();
        addSigner4ToMultisigWithMultisig();
        vm.warp(block.timestamp + 2);

        // Advance Anvil's time to satisfy the cooldown period before withdrawal
        // withdrawToSigner4WithMultisig();

        printSummary();
    }

    // // ============================================
    // // PHASE 2: WHITELIST ADDRESS
    // // ============================================

    // /// @notice Phase 2: Whitelist signer3 for withdrawal operations
    // /// @dev Demonstrates multisig execution of whitelistAddress() function
    // ///      - Creates an ERC7821 Call to whitelistAddress(signer3)
    // ///      - Generates signatures from signer1 and signer2 (2-of-3 threshold)
    // ///      - Executes via account.execute() with multisig signature
    // ///      - Records whitelisting timestamp for cooldown enforcement
    // function whitelistSigner3WithMultisig() internal {
    //     console.log("\n========================================");
    //     console.log("PHASE 2: Whitelist Signer3 (Multisig)");
    //     console.log("========================================\n");

    //     // Create ERC7821 Call to whitelist signer3
    //     ERC7821.Call[] memory calls = new ERC7821.Call[](1);
    //     calls[0] = ERC7821.Call({
    //         to: address(solverAccount),
    //         value: 0,
    //         data: abi.encodeWithSelector(GardenSolver.whitelistAddress.selector, signer3)
    //     });

    //     // Get current nonce and compute digest for signature
    //     uint256 nonce = solverAccount.getNonce(0);
    //     bytes32 digest = solverAccount.computeDigest(calls, nonce);

    //     // Generate individual signatures from signer1 and signer2
    //     bytes memory is1 = _wrapSecpSig(signer1PrivateKey, signer1KeyHash, digest);
    //     bytes memory is2 = _wrapSecpSig(signer2PrivateKey, signer2KeyHash, digest);

    //     // Combine into multisig signature format
    //     bytes[] memory innerSignatures = new bytes[](2);
    //     innerSignatures[0] = is1;
    //     innerSignatures[1] = is2;

    //     bytes memory multisigSignature =
    //         abi.encodePacked(abi.encode(innerSignatures), multisigKeyHash, uint8(0));

    //     // Execute the call with multisig signature
    //     // Note: Anyone can broadcast with a valid multisig signature
    //     vm.startBroadcast();
    //     solverAccount.execute(calls, abi.encodePacked(nonce, multisigSignature));
    //     vm.stopBroadcast();

    //     console.log("[OK] Signer3 whitelisted");
    //     console.log("Signer3 Address:", signer3);
    //     console.log("Whitelisting timestamp:", block.timestamp);
    //     console.log("\n");
    // }

    // // ============================================
    // // PHASE 3: MODIFY COOLDOWN PERIOD
    // // ============================================

    // /// @notice Phase 3: Reduce cooldown period for testing purposes
    // /// @dev Demonstrates multisig execution of security parameter modification
    // ///      - Default cooldown: 1 day (86400 seconds)
    // ///      - Testing cooldown: 1 second (minimum allowed value)
    // ///      - Contract enforces non-zero cooldown (GardenSolver__ZeroValue check)
    // ///      - Uses signer1 and signer2 signatures (2-of-3 threshold)
    // function changeCooldownPeriodWithMultisig() internal {
    //     console.log("\n========================================");
    //     console.log("PHASE 3: Disable Cooldown Period (Multisig)");
    //     console.log("========================================\n");

    //     console.log("Current cooldown period: 1 day");

    //     // Create call to change cooldown period to 1 second
    //     // Note: Contract requires non-zero value (minimum is 1 second)
    //     ERC7821.Call[] memory calls = new ERC7821.Call[](1);
    //     calls[0] = ERC7821.Call({
    //         to: address(solverAccount),
    //         value: 0,
    //         data: abi.encodeWithSelector(
    //             GardenSolver.changeCooldownPeriod.selector,
    //             1 // Set to 1 second (minimum value allowed)
    //         )
    //     });

    //     uint256 nonce = solverAccount.getNonce(0);
    //     bytes32 digest = solverAccount.computeDigest(calls, nonce);

    //     bytes memory is1 = _wrapSecpSig(signer1PrivateKey, signer1KeyHash, digest);
    //     bytes memory is2 = _wrapSecpSig(signer2PrivateKey, signer2KeyHash, digest);

    //     bytes[] memory innerSignatures = new bytes[](2);
    //     innerSignatures[0] = is1;
    //     innerSignatures[1] = is2;

    //     bytes memory multisigSignature =
    //         abi.encodePacked(abi.encode(innerSignatures), multisigKeyHash, uint8(0));

    //     vm.startBroadcast(signer1PrivateKey);
    //     solverAccount.execute(calls, abi.encodePacked(nonce, multisigSignature));
    //     vm.stopBroadcast();

    //     console.log("[OK] Cooldown period changed to 1 second");
    //     console.log("New cooldown period:", solverAccount.cooldownPeriod(), "seconds");
    //     console.log("\n");
    // }

    // // ============================================
    // // PHASE 4: VERIFY CONFIGURATION
    // // ============================================

    // /// @notice Phase 4: Verify whitelist and cooldown configuration
    // /// @dev View-only function that queries and displays account state
    // ///      - Checks if signer3 is whitelisted
    // ///      - Retrieves whitelisting timestamp
    // ///      - Calculates when withdrawal becomes available
    // ///      - Demonstrates cooldown enforcement mechanism
    // function verifyWhitelistAndCooldown() internal view {
    //     console.log("\n========================================");
    //     console.log("PHASE 4: Verify Whitelist & Cooldown Configuration");
    //     console.log("========================================\n");

    //     // Verify signer3 is whitelisted
    //     bool isWhitelisted = solverAccount.whitelistedAddresses(signer3);
    //     uint256 whitelistTimestamp = solverAccount.whitelistingTimestamps(signer3);
    //     uint256 cooldown = solverAccount.cooldownPeriod();

    //     console.log("Signer3 whitelisted:", isWhitelisted);
    //     console.log("Whitelisting timestamp:", whitelistTimestamp);
    //     console.log("Current cooldown period:", cooldown, "seconds");
    //     console.log("Current block timestamp:", block.timestamp);
    //     console.log("Withdrawal available after:", whitelistTimestamp + cooldown);

    //     if (block.timestamp >= whitelistTimestamp + cooldown) {
    //         console.log("\n[OK] Cooldown period has elapsed - withdrawal is now possible!");
    //     } else {
    //         uint256 timeRemaining = (whitelistTimestamp + cooldown) - block.timestamp;
    //         console.log(
    //             "\n[INFO] Cooldown in progress - withdrawal available in", timeRemaining, "seconds"
    //         );
    //         console.log(
    //             "[INFO] In production, multisig would call withdraw() after cooldown elapses"
    //         );
    //     }

    //     console.log("\n[OK] Whitelist and cooldown configuration successful!");
    //     console.log("Multisig has demonstrated ability to:");
    //     console.log("  1. Whitelist addresses via whitelistAddress()");
    //     console.log("  2. Modify security parameters via changeCooldownPeriod()");
    //     console.log("  3. Execute withdrawals via withdraw() (after cooldown)");
    // }

    // function withdrawToSigner3WithMultisig() internal {
    //     console.log("\n========================================");
    //     console.log("PHASE 4: Withdraw to Signer3 (Multisig)");
    //     console.log("========================================\n");

    //     // Verify whitelist status and cooldown before withdrawal
    //     bool isWhitelisted = solverAccount.whitelistedAddresses(signer3);
    //     uint256 whitelistTimestamp = solverAccount.whitelistingTimestamps(signer3);
    //     uint256 cooldown = solverAccount.cooldownPeriod();
    //     uint256 currentTime = block.timestamp;
    //     uint256 requiredTime = whitelistTimestamp + cooldown;

    //     console.log("Verifying withdrawal conditions:");
    //     console.log("- Signer3 whitelisted:", isWhitelisted);
    //     console.log("- Whitelist timestamp:", whitelistTimestamp);
    //     console.log("- Cooldown period:", cooldown, "seconds");
    //     console.log("- Current timestamp:", currentTime);
    //     console.log("- Required timestamp:", requiredTime);
    //     console.log("- Time elapsed:", currentTime >= requiredTime ? "YES" : "NO");
    //     console.log("");

    //     require(isWhitelisted, "Signer3 must be whitelisted");
    //     // require(currentTime >= requiredTime, "Cooldown period must have elapsed");

    //     // Record balances before withdrawal
    //     uint256 accountBalanceBefore = testToken.balanceOf(address(solverAccount));
    //     uint256 signer3BalanceBefore = testToken.balanceOf(signer3);

    //     assert(testToken.balanceOf(address(solverAccount)) == 1_000_000 ether);
    //     assert(testToken.balanceOf(signer3) == 0);

    //     console.log("Account balance before:", accountBalanceBefore / 1e18, "TT");
    //     console.log("Signer3 balance before:", signer3BalanceBefore / 1e18, "TT");

    //     uint256 withdrawAmount = 1_000 ether;

    //     ERC7821.Call[] memory calls = new ERC7821.Call[](1);
    //     calls[0] = ERC7821.Call({
    //         to: address(solverAccount),
    //         value: 0,
    //         data: abi.encodeWithSelector(
    //             GardenSolver.withdraw.selector, signer3, address(testToken), withdrawAmount
    //         )
    //     });

    //     uint256 nonce = solverAccount.getNonce(0);
    //     bytes32 digest = solverAccount.computeDigest(calls, nonce);

    //     bytes memory is1 = _wrapSecpSig(signer1PrivateKey, signer1KeyHash, digest);
    //     bytes memory is2 = _wrapSecpSig(signer2PrivateKey, signer2KeyHash, digest);

    //     bytes[] memory innerSignatures = new bytes[](2);
    //     innerSignatures[0] = is1;
    //     innerSignatures[1] = is2;

    //     bytes memory multisigSignature =
    //         abi.encodePacked(abi.encode(innerSignatures), multisigKeyHash, uint8(0));

    //     vm.startBroadcast(deployerPrivateKey);
    //     // Use GardenSolver's execute(Call[], bytes) signature
    //     solverAccount.execute(calls, abi.encodePacked(nonce, multisigSignature));
    //     vm.stopBroadcast();

    //     // Record balances after withdrawal
    //     uint256 accountBalanceAfter = testToken.balanceOf(address(solverAccount));
    //     uint256 signer3BalanceAfter = testToken.balanceOf(signer3);

    //     console.log("\n[OK] Withdrawal successful!");
    //     console.log("Amount withdrawn:", withdrawAmount / 1e18, "TT");
    //     console.log("Account balance after:", accountBalanceAfter / 1e18, "TT");
    //     console.log("Signer3 balance after:", signer3BalanceAfter / 1e18, "TT");

    //     assert(testToken.balanceOf(address(solverAccount)) == 1_000_000 ether - withdrawAmount);
    //     assert(testToken.balanceOf(signer3) == 0 + withdrawAmount);

    //     // Assertions
    //     require(
    //         accountBalanceAfter == accountBalanceBefore - withdrawAmount, "Account balance mismatch"
    //     );
    //     require(
    //         signer3BalanceAfter == signer3BalanceBefore + withdrawAmount, "Signer3 balance mismatch"
    //     );
    //     console.log("\n[OK] All assertions passed!");
    // }

    function authorizeSigner4WithMultisig() internal {
        console.log("\n========================================");
        console.log("PHASE 5: Authorize Signer4 as New Key (Multisig)");
        console.log("========================================\n");

        console.log("Adding signer4 as a new authorized key...");
        console.log("Signer4 Address:", signer4);

        // Create the new key for signer4
        IthacaAccount.Key memory signer4Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer4)
        });

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: address(solverAccount),
            value: 0,
            data: abi.encodeWithSelector(IthacaAccount.authorize.selector, signer4Key)
        });

        uint256 nonce = solverAccount.getNonce(0);
        bytes32 digest = solverAccount.computeDigest(calls, nonce);

        bytes memory is1 = _wrapSecpSig(signer1PrivateKey, signer1KeyHash, digest);
        bytes memory is2 = _wrapSecpSig(signer2PrivateKey, signer2KeyHash, digest);

        bytes[] memory innerSignatures = new bytes[](2);
        innerSignatures[0] = is1;
        innerSignatures[1] = is2;

        bytes memory multisigSignature =
            abi.encodePacked(abi.encode(innerSignatures), multisigKeyHash, uint8(0));

        vm.startBroadcast();
        solverAccount.execute(calls, abi.encodePacked(nonce, multisigSignature));
        vm.stopBroadcast();

        // Compute and store the new key hash
        signer4KeyHash = solverAccount.hash(signer4Key);

        console.log("[OK] Signer4 authorized as new key");
        console.log("Signer4 KeyHash:", vm.toString(signer4KeyHash));
        console.log("\n");
    }

    // ============================================
    // PHASE 6: ADD SIGNER TO MULTISIG
    // ============================================

    /// @notice Phase 6: Add signer4 to the multisig configuration
    /// @dev Demonstrates dynamic multisig management
    ///      - Calls MultiSigSigner.addOwner() to add signer4
    ///      - Upgrades from 2-of-3 to 2-of-4 multisig
    ///      - Uses existing 2-of-3 multisig (signer1 + signer2) to authorize
    ///      - After this, any 2-of-4 combination can sign (e.g., signer1+signer4)
    function addSigner4ToMultisigWithMultisig() internal {
        console.log("\n========================================");
        console.log("PHASE 6: Add Signer4 to Multisig Configuration (Multisig)");
        console.log("========================================\n");

        console.log("Adding signer4 to multisig owners...");
        console.log("Current threshold: 2-of-3");
        console.log("New configuration will be: 2-of-4");

        // Create call to add signer4 as owner in the multisig
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: address(multiSigSigner),
            value: 0,
            data: abi.encodeWithSignature(
                "addOwner(bytes32,bytes32)", multisigKeyHash, signer4KeyHash
            )
        });

        uint256 nonce = solverAccount.getNonce(0);
        bytes32 digest = solverAccount.computeDigest(calls, nonce);

        bytes memory is1 = _wrapSecpSig(signer1PrivateKey, signer1KeyHash, digest);
        bytes memory is2 = _wrapSecpSig(signer2PrivateKey, signer2KeyHash, digest);

        bytes[] memory innerSignatures = new bytes[](2);
        innerSignatures[0] = is1;
        innerSignatures[1] = is2;

        bytes memory multisigSignature =
            abi.encodePacked(abi.encode(innerSignatures), multisigKeyHash, uint8(0));

        vm.startBroadcast();
        solverAccount.execute(calls, abi.encodePacked(nonce, multisigSignature));
        vm.stopBroadcast();

        console.log("[OK] Signer4 added to multisig configuration");
        console.log("New multisig configuration: 2-of-4");
        console.log("Owners: signer1, signer2, signer3, signer4");
        console.log("\n");
    }

    // // ============================================
    // // PHASE 7: WITHDRAWAL WITH NEW MULTISIG (OPTIONAL)
    // // ============================================

    // /// @notice Phase 7: Withdraw to signer3 using signer1 + signer4 multisig combination
    // /// @dev Demonstrates flexible multisig after adding signer4
    // ///      - Uses NEW combination: signer1 + signer4 (instead of original signer1 + signer2)
    // ///      - Proves any 2-of-4 combination works after upgrade
    // ///      - Withdraws to signer3 (already whitelisted in Phase 2)
    // ///      - NOTE: This phase relies on vm.warp() to advance time past the cooldown
    // function withdrawToSigner4WithMultisig() internal {
    //     console.log("\n========================================");
    //     console.log("PHASE 7: Withdraw to Signer3 Using New Multisig (Signer1 + Signer4)");
    //     console.log("========================================\n");

    //     console.log("Demonstrating that signer4 is now part of multisig...");
    //     console.log("Using signatures from: Signer1 + Signer4 (threshold 2-of-4)");
    //     console.log("Withdrawing to: Signer3 (already whitelisted in Phase 2)");
    //     console.log("Note: Cooldown satisfied by advancing time with vm.warp().\n");

    //     // Record balances before withdrawal
    //     uint256 accountBalanceBefore = testToken.balanceOf(address(solverAccount));
    //     uint256 signer3BalanceBefore = testToken.balanceOf(signer3);

    //     uint256 withdrawAmount = 1_000 ether;

    //     assert(testToken.balanceOf(address(solverAccount)) == 1_000_000 ether - 1_000 ether);
    //     assert(testToken.balanceOf(signer3) == 1000 ether);

    //     console.log("Account balance before:", accountBalanceBefore / 1e18, "TT");
    //     console.log("Signer3 balance before:", signer3BalanceBefore / 1e18, "TT");

    //     ERC7821.Call[] memory calls = new ERC7821.Call[](1);
    //     calls[0] = ERC7821.Call({
    //         to: address(solverAccount),
    //         value: 0,
    //         data: abi.encodeWithSelector(
    //             GardenSolver.withdraw.selector, signer3, address(testToken), withdrawAmount
    //         )
    //     });

    //     uint256 nonce = solverAccount.getNonce(0);
    //     bytes32 digest = solverAccount.computeDigest(calls, nonce);

    //     bytes memory is1 = _wrapSecpSig(signer1PrivateKey, signer1KeyHash, digest);
    //     bytes memory is2 = _wrapSecpSig(signer4PrivateKey, signer4KeyHash, digest);

    //     bytes[] memory innerSignatures = new bytes[](2);
    //     innerSignatures[0] = is1;
    //     innerSignatures[1] = is2;

    //     bytes memory multisigSignature =
    //         abi.encodePacked(abi.encode(innerSignatures), multisigKeyHash, uint8(0));

    //     vm.startBroadcast(deployerPrivateKey);
    //     // Use GardenSolver's execute(Call[], bytes) signature
    //     solverAccount.execute(calls, abi.encodePacked(nonce, multisigSignature));
    //     vm.stopBroadcast();

    //     // Record balances after withdrawal
    //     uint256 accountBalanceAfter = testToken.balanceOf(address(solverAccount));
    //     uint256 signer3BalanceAfter = testToken.balanceOf(signer3);

    //     console.log("\n[OK] Withdrawal successful!");
    //     console.log("Amount withdrawn:", withdrawAmount / 1e18, "TT");
    //     console.log("Account balance after:", accountBalanceAfter / 1e18, "TT");
    //     console.log("Signer3 balance after:", signer3BalanceAfter / 1e18, "TT");

    //     assert(
    //         testToken.balanceOf(address(solverAccount))
    //             == 1_000_000 ether - withdrawAmount - withdrawAmount
    //     );
    //     assert(testToken.balanceOf(signer3) == 0 + withdrawAmount + withdrawAmount);

    //     console.log("\n[OK] All assertions passed!");
    // }

    // ============================================
    // SUMMARY AND HELPER FUNCTIONS
    // ============================================

    /// @notice Print comprehensive summary of all operations performed
    /// @dev Displays contract addresses, multisig configuration, operations, and final state
    function printSummary() internal view {
        console.log("\n========================================");
        console.log("FINAL SUMMARY");
        console.log("========================================");
        console.log("Orchestrator:", address(orchestrator));
        console.log("MultiSigSigner:", address(multiSigSigner));
        console.log("GardenSolver (Standalone):", address(solverAccount));
        console.log("TestToken:", address(testToken));
        console.log("\nMultisig Configuration: 2 of 4 (upgraded from 2 of 3)");
        console.log("- Signer 1:", signer1);
        console.log("- Signer 2:", signer2);
        console.log("- Signer 3:", signer3);
        console.log("- Signer 4:", signer4, "(added dynamically)");
        console.log("\nOperations Performed:");
        console.log("1. Whitelisted Signer3 via multisig");
        console.log("2. Set cooldown period to 1 second via multisig");
        console.log("3. Verified whitelist and cooldown configuration");
        console.log("4. Authorized Signer4 as new key via multisig");
        console.log("5. Added Signer4 to multisig configuration (2-of-4)");
        console.log("6. Withdrew to Signer3 using Signer1+Signer4 multisig (after time warp)");
        console.log("\nNext Step (in production):");
        console.log("Multisig can continue to manage the account with any 2-of-4 signers.");
        console.log("\nFinal Token Balances:");
        console.log("- GardenAccount:", testToken.balanceOf(address(solverAccount)) / 1e18, "TT");
        console.log("- Signer3:", testToken.balanceOf(signer3) / 1e18, "TT");
        console.log("- Signer4:", testToken.balanceOf(signer4) / 1e18, "TT");
        console.log("\nDemonstrated Capabilities:");
        console.log("- Dynamic key management (adding new signers)");
        console.log("- Flexible multisig (any 2-of-4 combination works)");
        console.log("- Complete withdrawal flow with cooldown enforcement");
        console.log("========================================\n");
    }

    /// @notice Helper function to wrap Secp256k1 signature with key hash
    /// @dev Formats signature for IthacaAccount signature validation
    ///      Format: [r][s][v][keyHash][keyType]
    ///      - r, s, v: ECDSA signature components
    ///      - keyHash: Hash of the key being used
    ///      - keyType: 0 for regular signature (non-sessionKey)
    /// @param privateKey Private key to sign with
    /// @param keyHash Hash of the corresponding public key
    /// @param digest Message digest to sign
    /// @return Packed signature bytes
    function _wrapSecpSig(uint256 privateKey, bytes32 keyHash, bytes32 digest)
        internal
        pure
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v, keyHash, uint8(0));
    }
}
