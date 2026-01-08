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

contract TestnetDeployment is Script {
    Orchestrator public orchestrator;
    MultiSigSigner public multiSigSigner;
    GardenSolver public solverAccount; // Standalone smart contract account
    ExperimentERC20 public testToken;

    // 0x55b2b8781b7b03aeac0657dd1c7ab9af273c47c001b956b72ba9987afc6f9d88
    // 0x89d9c4d5373722057bd6e8d0dfd633aee89a300e025c4afc441c764c8ef095ae
    // 0x1fe2d7d79794412f5d00203bd2bccd135de4599ee99cef5b3ecc63321ac5e20a

    // Anvil default accounts (accounts 0-4)
    // Account #0: Deployer
    uint256 public deployerPrivateKey =
        0x3037c67e6d244421cab8992e8464b88de5f63742b6f369e3c74860803c4d7657;
    address public deployer;

    // Account #2: Signer 1
    uint256 public signer1PrivateKey =
        0x55b2b8781b7b03aeac0657dd1c7ab9af273c47c001b956b72ba9987afc6f9d88;
    address public signer1;

    // Account #3: Signer 2
    uint256 public signer2PrivateKey =
        0x89d9c4d5373722057bd6e8d0dfd633aee89a300e025c4afc441c764c8ef095ae;
    address public signer2;

    // Account #4: Signer 3
    uint256 public signer3PrivateKey =
        0x1fe2d7d79794412f5d00203bd2bccd135de4599ee99cef5b3ecc63321ac5e20a;
    address public signer3;
    function run() external {
        signer1 = vm.addr(signer1PrivateKey);
        signer2 = vm.addr(signer2PrivateKey);
        signer3 = vm.addr(signer3PrivateKey);

        vm.startBroadcast(deployerPrivateKey);
        orchestrator = new Orchestrator();
        console.log("Orchestrator:", address(orchestrator));

        multiSigSigner = new MultiSigSigner();
        console.log("MultiSigSigner:", address(multiSigSigner));

        // Prepare initial signer keys (non-super-admin - only External keys can be super admin)
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
        solverAccount = new GardenSolver(
            address(0),
            signerKeys,
            address(multiSigSigner),
            2 // threshold: 2-of-3
        );

        console.log("GardenSolver Account:", address(solverAccount));
        vm.stopBroadcast();
    }
}