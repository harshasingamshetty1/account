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
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title DeployTestExecuteInitiates
/// @notice Deploy standalone GardenSolver with multisig control and demonstrate initiate flow
/// @dev ONE-CLICK DEPLOYMENT & EXECUTION:
///      forge script script/DeployTestExecuteInitiates.s.sol --rpc-url http://localhost:8545 --broadcast
///
///      IMPORTANT: Multisig directly calls approve(), signer only gets permission for initiate()
///
///      Or run in two steps:
///      STEP 1: forge script script/DeployTestExecuteInitiates.s.sol --sig "deployContracts()" --rpc-url http://localhost:8545 --broadcast
///      STEP 2: forge script script/DeployTestExecuteInitiates.s.sol --sig "executeWithMultisig()" --rpc-url http://localhost:8545 --broadcast
contract DeployTestExecuteInitiates is Script {
    // Deployed contracts
    Orchestrator public orchestrator;
    MultiSigSigner public multiSigSigner;
    GardenSolver public solverAccount; // Standalone smart contract account
    ExperimentERC20 public testToken;
    Initiator public initiator;

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

    // Keys
    bytes32 public signer1KeyHash;
    bytes32 public signer2KeyHash;
    bytes32 public signer3KeyHash;
    bytes32 public multisigKeyHash;

    function setUp() public {
        // Derive addresses from Anvil default private keys
        deployer = vm.addr(deployerPrivateKey);
        signer1 = vm.addr(signer1PrivateKey);
        signer2 = vm.addr(signer2PrivateKey);
        signer3 = vm.addr(signer3PrivateKey);

        console.log("\n========================================");
        console.log("ANVIL DEFAULT ACCOUNTS");
        console.log("========================================");
        console.log("Deployer (Account #0):", deployer);
        console.log("Signer 1 (Account #2):", signer1);
        console.log("Signer 2 (Account #3):", signer2);
        console.log("Signer 3 (Account #4):", signer3);
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

        // Deploy Initiator contract
        initiator = new Initiator();
        console.log("Initiator:", address(initiator));

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
            "Run: forge script script/DeployTestExecuteInitiates.s.sol --sig \"executeWithMultisig()\" --rpc-url http://localhost:8545 --broadcast"
        );
        console.log("========================================\n");
    }

    /// @notice Main entry: Deploy and setup complete standalone account
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
        // solverAccount, multiSigSigner, testToken, initiator are already set from deployContracts()

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
        signer1TransfersTokens();
        printSummary();
    }

    function grantSigner1PermissionsWithMultisig() internal {
        console.log("\n========================================");
        console.log("PHASE 2: Multisig Approves & Grants signer1 Initiate Permission");
        console.log("========================================\n");

        bytes4 initiateSel = bytes4(keccak256("initiate(address,address,uint256)"));
        uint256 approveAmount = 100_000 ether;

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        // Call 0: Multisig directly approves Initiator to spend tokens (no signer permission for approve)
        calls[0] = ERC7821.Call({
            to: address(testToken),
            value: 0,
            data: abi.encodeWithSignature(
                "approve(address,uint256)", address(initiator), approveAmount
            )
        });
        // Call 1: Grant signer1 permission to call initiate on Initiator
        calls[1] = ERC7821.Call({
            to: address(solverAccount),
            value: 0,
            data: abi.encodeWithSelector(
                GuardedExecutor.setCanExecute.selector,
                signer1KeyHash,
                address(initiator),
                initiateSel,
                true
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

        console.log("[OK] Multisig approved", approveAmount / 1e18, "TT to Initiator");
        console.log("[OK] signer1 granted canExecute for initiate() only\n");
    }

    function signer1TransfersTokens() internal {
        console.log("\n========================================");
        console.log("PHASE 3: signer1 Initiates via Initiator");
        console.log("========================================\n");

        assert(testToken.balanceOf(address(initiator)) == 0);
        assert(testToken.balanceOf(address(solverAccount)) == 1_000_000 ether);

        uint256 amount = 1_000 ether;

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        // Only call initiate - approval was already done by multisig
        calls[0] = ERC7821.Call({
            to: address(initiator),
            value: 0,
            data: abi.encodeWithSignature(
                "initiate(address,address,uint256)",
                address(testToken),
                address(solverAccount),
                amount
            )
        });

        uint256 nonce = solverAccount.getNonce(0);
        bytes32 digest = solverAccount.computeDigest(calls, nonce);

        bytes memory signer1Wrapped = _wrapSecpSig(signer1PrivateKey, signer1KeyHash, digest);

        vm.startBroadcast(signer1PrivateKey);
        // Use GardenSolver's execute(Call[], bytes) signature
        solverAccount.execute(calls, abi.encodePacked(nonce, signer1Wrapped));
        vm.stopBroadcast();

        assert(testToken.balanceOf(address(solverAccount)) == 1_000_000 ether - amount);
        assert(testToken.balanceOf(address(initiator)) == amount);

        console.log("[OK] signer1 initiated transfer of", amount / 1e18, "TT to Initiator");
        console.log("Initiator balance:", testToken.balanceOf(address(initiator)) / 1e18, "TT");
        console.log("Account balance:", testToken.balanceOf(address(solverAccount)) / 1e18, "TT");
    }

    function printSummary() internal view {
        console.log("\n========================================");
        console.log("FINAL SUMMARY");
        console.log("========================================");
        console.log("Orchestrator:", address(orchestrator));
        console.log("MultiSigSigner:", address(multiSigSigner));
        console.log("GardenSolver (Standalone):", address(solverAccount));
        console.log("TestToken:", address(testToken));
        console.log("Initiator:", address(initiator));
        console.log("\nMultisig: 2 of 3");
        console.log("- Signer 1:", signer1);
        console.log("- Signer 2:", signer2);
        console.log("- Signer 3:", signer3);
        console.log("\nToken Balances:");
        console.log("- Account:", testToken.balanceOf(address(solverAccount)) / 1e18, "TT");
        console.log("- Initiator:", testToken.balanceOf(address(initiator)) / 1e18, "TT");
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

contract Initiator {
    function initiate(address token, address user, uint256 amount) public {
        IERC20(token).transferFrom(user, address(this), amount);
    }
}
