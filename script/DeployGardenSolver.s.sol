// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../src/GardenSolver.sol";
import {IthacaAccount} from "../src/IthacaAccount.sol";
import {Orchestrator} from "../src/Orchestrator.sol";
import {MultiSigSigner} from "../src/MultiSigSigner.sol";

/// @title DeployGardenSolver
/// @notice Deploy GardenSolver with multisig control
/// @dev DEPLOYMENT USAGE:
///      Local (Anvil):
///      forge script script/DeployGardenSolver.s.sol --rpc-url http://localhost:8545 --broadcast
///
///      Testnet/Mainnet:
///      forge script script/DeployGardenSolver.s.sol --rpc-url $RPC_URL --broadcast --verify
///
///      This script deploys:
///      1. Orchestrator - Core protocol orchestrator
///      2. MultiSigSigner - Multisig validation contract
///      3. GardenSolver - Smart contract account with 2-of-3 multisig control
///
///      Configuration:
///      - 3 signer addresses (signer1, signer2, signer3)
///      - 2-of-3 threshold for multisig operations
///      - Initial funding amount (configurable)
contract DeployGardenSolver is Script {
    // Deployed contracts
    Orchestrator public orchestrator;
    MultiSigSigner public multiSigSigner;
    GardenSolver public gardenSolver;

    // Configuration: Update these addresses for your deployment
    // For Anvil testing, these are the default accounts
    address public signer1 = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8; // Anvil Account #1
    address public signer2 = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC; // Anvil Account #2
    address public signer3 = 0x90F79bf6EB2c4f870365E785982E1f101E93b906; // Anvil Account #3

    // Multisig configuration
    uint256 public threshold = 2; // 2-of-3 multisig

    // Initial funding for the GardenSolver account
    uint256 public initialFunding = 10 ether;

    function setUp() public view {
        console.log("\n========================================");
        console.log("DEPLOYMENT CONFIGURATION");
        console.log("========================================");
        console.log("Deployer:", msg.sender);
        console.log("Signer 1:", signer1);
        console.log("Signer 2:", signer2);
        console.log("Signer 3:", signer3);
        console.log("Multisig Threshold:", threshold, "of 3");
        console.log("Initial Funding:", initialFunding / 1e18, "ETH");
        console.log("========================================\n");
    }

    /// @notice Main deployment function
    function run() public {
        vm.startBroadcast();

        console.log("\n========================================");
        console.log("DEPLOYING CONTRACTS");
        console.log("========================================\n");

        // Deploy Orchestrator
        orchestrator = new Orchestrator();
        console.log("1. Orchestrator deployed:", address(orchestrator));

        // Deploy MultiSigSigner
        multiSigSigner = new MultiSigSigner();
        console.log("2. MultiSigSigner deployed:", address(multiSigSigner));

        // Prepare signer keys for GardenSolver
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

        // Deploy GardenSolver with multisig configuration
        gardenSolver = new GardenSolver{value: initialFunding}(
            address(orchestrator), signerKeys, address(multiSigSigner), threshold
        );
        console.log("3. GardenSolver deployed:", address(gardenSolver));
        console.log("   - Funded with:", initialFunding / 1e18, "ETH");
        console.log("   - Keys authorized: 3");
        console.log("   - Multisig threshold:", threshold, "of 3");

        vm.stopBroadcast();

        // Print deployment summary
        printDeploymentSummary();
    }

    /// @notice Print comprehensive deployment information
    function printDeploymentSummary() internal view {
        console.log("\n========================================");
        console.log("DEPLOYMENT SUMMARY");
        console.log("========================================");
        console.log("Network Chain ID:", block.chainid);
        console.log("Block Number:", block.number);
        console.log("Deployer:", msg.sender);
        console.log("\nDeployed Contracts:");
        console.log("- Orchestrator:", address(orchestrator));
        console.log("- MultiSigSigner:", address(multiSigSigner));
        console.log("- GardenSolver:", address(gardenSolver));

        console.log("\nGardenSolver Configuration:");
        console.log("- Balance:", address(gardenSolver).balance / 1e18, "ETH");

        console.log("\nAuthorized Signers:");
        console.log("- Signer 1:", signer1);
        console.log("- Signer 2:", signer2);
        console.log("- Signer 3:", signer3);
        console.log("- Threshold:", threshold, "of 3");

        // Get and display key hashes
        console.log("\nKey Hashes:");
        (IthacaAccount.Key[] memory keys, bytes32[] memory keyHashes) = gardenSolver.getKeys();
        console.log("Number of keys:", keys.length);
        for (uint256 i = 0; i < keyHashes.length; i++) {
            console.log("  Key", i, "Hash:", vm.toString(keyHashes[i]));
        }

        console.log("\nNext Steps:");
        console.log("1. Verify contracts on block explorer (if on public network)");
        console.log("2. Configure whitelist addresses using multisig");
        console.log("3. Adjust cooldown period if needed");
        console.log("4. Fund the GardenSolver with tokens as required");
        console.log("========================================\n");
    }

    /// @notice Helper function to compute key hash for a given address
    /// @dev Useful for verifying key hashes after deployment
    function computeKeyHash(address signerAddress) public view returns (bytes32) {
        IthacaAccount.Key memory key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signerAddress)
        });
        return gardenSolver.hash(key);
    }
}
