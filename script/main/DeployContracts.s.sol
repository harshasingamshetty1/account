// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import {MultiSigSigner} from "../../src/MultiSigSigner.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";

/// @title DeployContracts
/// @notice Script to deploy MultiSigSigner and GardenSolver contracts
/// @dev please never change the console.log the cli scripts parse these output and executes accordingly
contract DeployContracts is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address signer1 = vm.envAddress("SIGNER_ONE_ADDRESS");
        uint256 fundAmountWei = vm.envUint("FUND_AMOUNT_WEI");
        uint256 threshold = vm.envUint("MULTISIG_THRESHOLD");

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

        GardenSolver solver = new GardenSolver{value: fundAmountWei}(
            orchestrator,
            signerKeys,
            address(multiSigSigner),
            threshold
        );
        console.log("GardenSolver:", address(solver));

        vm.stopBroadcast();
        bytes32 signer1KeyHash = solver.hash(signerKeys[0]);
        console.log("Signer1 KeyHash:", vm.toString(signer1KeyHash));
        IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(address(multiSigSigner), bytes12(0))
        });
        bytes32 multisigKeyHash = solver.hash(multisigKey);
        console.log("Multisig KeyHash:", vm.toString(multisigKeyHash));
    }
}
