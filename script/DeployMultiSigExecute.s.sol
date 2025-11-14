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
/// @notice Deploy standalone GardenSolver with multisig control and authorized signer execution
/// @dev ONE-CLICK DEPLOYMENT & EXECUTION:
///      forge script script/DeployMultiSigExecute.s.sol --rpc-url http://localhost:8545 --broadcast
///
///      Or run in two steps:
///      STEP 1: forge script script/DeployMultiSigExecute.s.sol --sig "deployContracts()" --rpc-url http://localhost:8545 --broadcast
///      STEP 2: forge script script/DeployMultiSigExecute.s.sol --sig "executeWithMultisig()" --rpc-url http://localhost:8545 --broadcast
contract DeployMultiSigExecute is Script {
    // Deployed contracts
    Orchestrator public orchestrator;
    MultiSigSigner public multiSigSigner;
    GardenSolver public solverAccount; // Standalone smart contract account
    ExperimentERC20 public testToken;

    // Anvil default accounts (accounts 0-4)
    // Account #0: Deployer
    uint256 public deployerPrivateKey =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address public deployer;

    // Account #2: Signer 1
    uint256 public signer1PrivateKey =
        0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    address public signer1;

    // Account #3: Signer 2
    uint256 public signer2PrivateKey =
        0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;
    address public signer2;

    // Account #4: Signer 3
    uint256 public signer3PrivateKey =
        0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a;
    address public signer3;

    // Account #5: Signer 4 (to be added later)
    uint256 public signer4PrivateKey =
        0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba;
    address public signer4;

    // Keys
    bytes32 public signer1KeyHash;
    bytes32 public signer2KeyHash;
    bytes32 public signer3KeyHash;
    bytes32 public signer4KeyHash;
    bytes32 public multisigKeyHash;

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

    /// @notice STEP 1: Deploy all contracts
    function deployContracts() public {
        console.log("\n========================================");
        console.log("STEP 1: Deploy Contracts");
        console.log("========================================\n");

        vm.startBroadcast(deployerPrivateKey);

        orchestrator = new Orchestrator();
        console.log("Orchestrator:", address(orchestrator));

        multiSigSigner = new MultiSigSigner();
        console.log("MultiSigSigner:", address(multiSigSigner));

        // Prepare initial signer keys (non-super-admin)
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

        // Deploy GardenSolver with keys authorized and multisig configured (2-of-3)
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

    /// @notice Main entry: Deploy and setup complete standalone account in one click
    function run() public {
        deployContracts();
        executeWithMultisig();
    }

    /// @notice Execute multisig operations: grant permissions and transfer tokens
    function executeWithMultisig() public {
        console.log("\n========================================");
        console.log("STEP 2: Execute Multisig Operations");
        console.log("========================================\n");

        // Use deployed contract addresses (no hardcoded addresses)
        // solverAccount, multiSigSigner, testToken are already set from deployContracts()

        console.log("\n========================================");
        console.log("PHASE 1: Computing KeyHashes");
        console.log("========================================");

        // Compute keyHashes using the contract's hash() function
        IthacaAccount.Key memory signer1Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: true,
            publicKey: abi.encode(signer1)
        });
        IthacaAccount.Key memory signer2Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: true,
            publicKey: abi.encode(signer2)
        });
        IthacaAccount.Key memory signer3Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: true,
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
        grantSigner1PermissionsWithMultisig();
        addSigner4WithMultisig();
        printSummary();
    }

    function grantSigner1PermissionsWithMultisig() internal {
        console.log("\n========================================");
        console.log("PHASE 2: Grant signer1 Permissions (Multisig)");
        console.log("========================================\n");

        bytes4 transferSel = bytes4(keccak256("transfer(address,uint256)"));

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(solverAccount),
            value: 0,
            data: abi.encodeWithSelector(
                GuardedExecutor.setCanExecute.selector,
                signer1KeyHash,
                address(testToken),
                transferSel,
                true
            )
        });
        calls[1] = ERC7821.Call({
            to: address(solverAccount),
            value: 0,
            data: abi.encodeWithSelector(
                GuardedExecutor.setSpendLimit.selector,
                signer1KeyHash,
                address(testToken),
                GuardedExecutor.SpendPeriod.Forever,
                100_000 ether
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

        // Anyone can broadcast the transaction with the valid multisig signature
        vm.startBroadcast(deployerPrivateKey);
        // Use GardenSolver's execute(Call[], bytes) signature
        solverAccount.execute(calls, abi.encodePacked(nonce, multisigSignature));
        vm.stopBroadcast();

        console.log("[OK] signer1 granted canExecute + spend limit\n");
    }

    function addSigner4WithMultisig() internal {
        console.log("\n========================================");
        console.log("PHASE 3: Add Signer 4 via Multisig");
        console.log("========================================\n");

        // Create Key struct for signer4
        IthacaAccount.Key memory signer4Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer4)
        });

        // Compute signer4 keyHash
        signer4KeyHash = solverAccount.hash(signer4Key);

        // Grant signer4 some permissions as well
        bytes4 transferSel = bytes4(keccak256("transfer(address,uint256)"));

        ERC7821.Call[] memory calls = new ERC7821.Call[](3);
        // Call 0: Authorize signer4 key
        calls[0] = ERC7821.Call({
            to: address(solverAccount),
            value: 0,
            data: abi.encodeWithSignature(
                "authorize(bytes32,(uint40,uint8,bool,bytes))", signer4KeyHash, signer4Key
            )
        });
        // Call 1: Grant signer4 permission to transfer tokens
        calls[1] = ERC7821.Call({
            to: address(solverAccount),
            value: 0,
            data: abi.encodeWithSelector(
                GuardedExecutor.setCanExecute.selector,
                signer4KeyHash,
                address(testToken),
                transferSel,
                true
            )
        });
        // Call 2: Set spend limit for signer4
        calls[2] = ERC7821.Call({
            to: address(solverAccount),
            value: 0,
            data: abi.encodeWithSelector(
                GuardedExecutor.setSpendLimit.selector,
                signer4KeyHash,
                address(testToken),
                GuardedExecutor.SpendPeriod.Forever,
                50_000 ether
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

        vm.startBroadcast(deployerPrivateKey);
        // Use GardenSolver's execute(Call[], bytes) signature
        solverAccount.execute(calls, abi.encodePacked(nonce, multisigSignature));
        vm.stopBroadcast();

        console.log("[OK] Signer 4 authorized and granted permissions");
        console.log("Signer 4 KeyHash:", vm.toString(signer4KeyHash));
        console.log("Signer 4 Address:", signer4);
    }

    function signer1TransfersTokens() internal {
        console.log("\n========================================");
        console.log("PHASE 5: signer1 Executes Transfer");
        console.log("========================================\n");

        uint256 amount = 1_000 ether;

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: address(testToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", signer1, amount)
        });

        uint256 nonce = solverAccount.getNonce(0);
        bytes32 digest = solverAccount.computeDigest(calls, nonce);

        bytes memory signer1Wrapped = _wrapSecpSig(signer1PrivateKey, signer1KeyHash, digest);

        vm.startBroadcast(signer1PrivateKey);
        // Use GardenSolver's execute(Call[], bytes) signature
        solverAccount.execute(calls, abi.encodePacked(nonce, signer1Wrapped));
        vm.stopBroadcast();

        console.log("[OK] signer1 pulled", amount, "TT");
        console.log("New signer1 balance:", testToken.balanceOf(signer1));
    }

    function printSummary() internal view {
        console.log("\n========================================");
        console.log("FINAL SUMMARY");
        console.log("========================================");
        console.log("Orchestrator:", address(orchestrator));
        console.log("MultiSigSigner:", address(multiSigSigner));
        console.log("GardenSolver (Standalone):", address(solverAccount));
        console.log("TestToken:", address(testToken));
        console.log("\nMultisig: 2 of 3 (initial signers)");
        console.log("- Signer 1:", signer1);
        console.log("- Signer 2:", signer2);
        console.log("- Signer 3:", signer3);
        console.log("\nAdditional Authorized Signer:");
        console.log("- Signer 4:", signer4, "(not in multisig config)");
        console.log("\nToken Balances:");
        console.log("- Account:", testToken.balanceOf(address(solverAccount)) / 1e18, "TT");
        console.log("========================================\n");
    }

    function _wrapSecpSig(uint256 privateKey, bytes32 keyHash, bytes32 digest)
        internal
        pure
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v, keyHash, uint8(0));
    }
}
