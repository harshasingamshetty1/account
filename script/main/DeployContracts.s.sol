// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import {MultiSigSigner} from "../../src/MultiSigSigner.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";

/// @title DeployContracts
/// @notice Deploys MultiSigSigner and GardenSolver contracts
/// @dev Usage:
///      forge script script/main/DeployContracts.s.sol --rpc-url $RPC_URL --broadcast
///
///      Required environment variables:
///      - DEPLOYER_PRIVATE_KEY: Private key to deploy contracts (deployer address is derived from this)
///      - SIGNER1_ADDRESS: Address of signer 1
///      - SIGNER2_ADDRESS: Address of signer 2
///      - SIGNER3_ADDRESS: Address of signer 3
///      - FUND_AMOUNT_WEI: Amount of ETH to fund GardenSolver (in wei, as uint256)
///      - MULTISIG_THRESHOLD: Multisig threshold (e.g., 2 for 2-of-3)
contract DeployContracts is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address signer1 = vm.envAddress("SIGNER1_ADDRESS");
        address signer2 = vm.envAddress("SIGNER2_ADDRESS");
        address signer3 = vm.envAddress("SIGNER3_ADDRESS");
        uint256 fundAmountWei = vm.envUint("FUND_AMOUNT_WEI");
        uint256 threshold = vm.envUint("MULTISIG_THRESHOLD");
        uint256 fundAmountEth = fundAmountWei / 1e18;

        console.log("\n========================================");
        console.log("DEPLOYING CONTRACTS");
        console.log("========================================");
        console.log("Deployer:", deployer);
        console.log("Signer 1:", signer1);
        console.log("Signer 2:", signer2);
        console.log("Signer 3:", signer3);
        console.log("Multisig Threshold:", threshold);
        console.log("========================================\n");

        vm.startBroadcast(deployerPrivateKey);

        address orchestrator = address(0);

        MultiSigSigner multiSigSigner = new MultiSigSigner();
        console.log("MultiSigSigner:", address(multiSigSigner));

        // Prepare initial signer keys
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

        // Deploy GardenSolver
        GardenSolver solver = new GardenSolver{value: fundAmountWei}(
            orchestrator,
            signerKeys,
            address(multiSigSigner),
            threshold
        );
        console.log("GardenSolver:", address(solver));
        console.log("Funded with:", fundAmountEth, "ETH");
        console.log("Funded amount (wei):", fundAmountWei);
        console.log("Multisig threshold:", threshold);

        vm.stopBroadcast();

        // Compute and log key hashes
        bytes32 signer1KeyHash = solver.hash(signerKeys[0]);
        bytes32 signer2KeyHash = solver.hash(signerKeys[1]);
        bytes32 signer3KeyHash = solver.hash(signerKeys[2]);

        IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(address(multiSigSigner), bytes12(0))
        });
        bytes32 multisigKeyHash = solver.hash(multisigKey);

        console.log("\n========================================");
        console.log("DEPLOYMENT SUMMARY");
        console.log("========================================");
        console.log("MultiSigSigner:", address(multiSigSigner));
        console.log("GardenSolver:", address(solver));
        console.log("\nKey Hashes:");
        console.log("Signer1 KeyHash:", vm.toString(signer1KeyHash));
        console.log("Signer2 KeyHash:", vm.toString(signer2KeyHash));
        console.log("Signer3 KeyHash:", vm.toString(signer3KeyHash));
        console.log("Multisig KeyHash:", vm.toString(multisigKeyHash));
        console.log("========================================");
    }
}
