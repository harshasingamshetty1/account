// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";
import {MultiSigSigner} from "../../src/MultiSigSigner.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";
import {GuardedExecutor} from "../../src/GuardedExecutor.sol";
import {ExperimentERC20} from "../../deploy/mock/ExperimentalERC20.sol";

// forge script script/main/CompleteTestScript.s.sol --rpc-url https://0xrpc.io/sep --broadcast --verify

/// @title CompleteTestScript
/// @notice Complete test script to deploy all contracts and execute with multisig
/// @dev ONE-CLICK DEPLOYMENT & EXECUTION:
///      forge script script/main/CompleteTestScript.s.sol --rpc-url http://localhost:8545 --broadcast
///
///      Or run in two steps:
///      STEP 1: forge script script/main/CompleteTestScript.s.sol --sig "deployContracts()" --rpc-url http://localhost:8545 --broadcast
///      STEP 2: forge script script/main/CompleteTestScript.s.sol --sig "executeWithMultisig()" --rpc-url http://localhost:8545 --broadcast
///
contract CompleteTestScript is Script {
    // Deployed contracts
    MultiSigSigner public multiSigSigner;
    GardenSolver public solverAccount; // Standalone smart contract account
    ExperimentERC20 public testToken;

    // htlc[0].token()

    // Hardcoded list of HTLC addresses (Ethereum Sepolia)
    // 0xd1E0Ba2b165726b3a6051b765d4564d030FDcf50 - ethereum sepolia htlc
    // 0x730Be401ef981D199a0560C87DfdDaFd3EC1C493 - ethereum sepolia htlc again
    address[] public htlcAddresses = [
        address(0xd1E0Ba2b165726b3a6051b765d4564d030FDcf50),
        address(0x730Be401ef981D199a0560C87DfdDaFd3EC1C493)
    ];

    // Anvil default accounts (accounts 0-4)
    // Account #0: Deployer
    uint256 public deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY"); // - ethonline private key main (don't forget)
    address public deployer;

    // Account #2: Signer 1
    uint256 public signer1PrivateKey = vm.envUint("SIGNER_ONE_PRIVATE_KEY"); // account 3
    address public signer1;

    // Account #3: Signer 2
    uint256 public signer2PrivateKey = vm.envUint("SIGNER_TWO_PRIVATE_KEY"); // account 4
    address public signer2;

    // Account #4: Signer 3
    uint256 public signer3PrivateKey = vm.envUint("SIGNER_THREE_PRIVATE_KEY"); // account 5
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

        address orchestrator = address(0);

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
        solverAccount = new GardenSolver{value: 0.01 ether}(
            orchestrator,
            signerKeys,
            address(multiSigSigner),
            2 // threshold: 2-of-3
        );
        console.log("GardenSolver (Standalone):", address(solverAccount));
        console.log("- Funded with: 0.01 ETH");
        console.log("- Keys authorized: 3 (signer1, signer2, signer3)");
        console.log("- Multisig configured: 2-of-3");

        // Deploy test token
        testToken = new ExperimentERC20("TestToken", "TT", 1e18);
        console.log("TestToken:", address(testToken));

        // Log HTLC addresses
        console.log("HTLC Addresses:");
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            console.log("  HTLC", i);
            console.log("    Address:", htlcAddresses[i]);
        }

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
        (
            IthacaAccount.Key[] memory keys,
            bytes32[] memory actualKeyHashes
        ) = solverAccount.getKeys();
        console.log("Number of keys:", keys.length);
        for (uint256 i = 0; i < actualKeyHashes.length; i++) {
            console.log("Key", i);
            console.log("  Hash:", vm.toString(actualKeyHashes[i]));
        }

        console.log("\n========================================");
        console.log("NEXT STEP (Optional - already running)");
        console.log("========================================");
        console.log("If running separately:");
        console.log(
            'Run: forge script script/DeployHTLCExecute.s.sol --sig "executeWithMultisig()" --rpc-url http://localhost:8545 --broadcast'
        );
        console.log("========================================\n");
    }

    /// @notice Main entry: Deploy and setup complete standalone account
    function run() public {
        deployContracts();
        executeWithMultisig();
    }

    /// @notice Execute multisig operations: grant HTLC permissions
    function executeWithMultisig() public {
        console.log("\n========================================");
        console.log("STEP 2: Grant HTLC Permissions (Multisig)");
        console.log("========================================\n");

        console.log("\n========================================");
        console.log("PHASE 1: Computing KeyHashes");
        console.log("========================================");

        // Compute keyHashes using the contract's hash() function
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

        // Approve tokens to all HTLC addresses
        approveTokensToHTLC();

        // Grant HTLC permissions
        grantHTLCPermissions();
    }

    /// @notice Multisig approves tokens to all HTLC addresses
    function approveTokensToHTLC() internal {
        console.log("\n========================================");
        console.log("PHASE 2: Multisig Approves Tokens to All HTLC Addresses");
        console.log("========================================\n");

        uint256 approveAmount = type(uint256).max; // Approve maximum amount
        // address actualTokenAddress = HTLC(htlcAddresses[0]).token();

        // Create calls for all HTLC addresses (1 approve call per HTLC)
        uint256 numCalls = htlcAddresses.length;
        ERC7821.Call[] memory calls = new ERC7821.Call[](numCalls);

        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            calls[i] = ERC7821.Call({
                to: address(testToken),
                value: 0,
                data: abi.encodeWithSignature(
                    "approve(address,uint256)",
                    htlcAddresses[i],
                    approveAmount
                )
            });
        }

        uint256 nonce = solverAccount.getNonce(0);
        bytes32 digest = solverAccount.computeDigest(calls, nonce);

        bytes memory is1 = _wrapSecpSig(
            signer1PrivateKey,
            signer1KeyHash,
            digest
        );
        bytes memory is2 = _wrapSecpSig(
            signer2PrivateKey,
            signer2KeyHash,
            digest
        );

        bytes[] memory innerSignatures = new bytes[](2);
        innerSignatures[0] = is1;
        innerSignatures[1] = is2;

        bytes memory multisigSignature = abi.encodePacked(
            abi.encode(innerSignatures),
            multisigKeyHash,
            uint8(0)
        );

        vm.startBroadcast(deployerPrivateKey);
        solverAccount.execute(
            calls,
            abi.encodePacked(nonce, multisigSignature)
        );
        vm.stopBroadcast();

        console.log(
            "[OK] Multisig approved maximum amount (type(uint256).max) to all HTLC addresses:"
        );
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            uint256 allowance = testToken.allowance(
                address(solverAccount),
                htlcAddresses[i]
            );
            console.log("  HTLC", i);
            console.log("    Address:", htlcAddresses[i]);
            console.log("    - Allowance:", allowance / 1e18);
            console.log("      Token: TT");
        }
        console.log("\n");
    }

    /// @notice Multisig grants signer1 permissions to call HTLC functions for all HTLC addresses
    function grantHTLCPermissions() internal {
        console.log("\n========================================");
        console.log("PHASE 3: Multisig Grants HTLC Permissions to signer1");
        console.log("========================================\n");

        // Compute function selectors for HTLC functions
        // initiate(address,uint256,uint256,bytes32)
        bytes4 initiateSel = bytes4(
            keccak256("initiate(address,uint256,uint256,bytes32)")
        );
        // redeem(bytes32,bytes)
        bytes4 redeemSel = bytes4(keccak256("redeem(bytes32,bytes)"));
        // refund(bytes32)
        bytes4 refundSel = bytes4(keccak256("refund(bytes32)"));

        // Create calls for all HTLC addresses (3 functions per HTLC)
        uint256 numCalls = htlcAddresses.length * 3;
        ERC7821.Call[] memory calls = new ERC7821.Call[](numCalls);

        uint256 callIndex = 0;
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            address htlc = htlcAddresses[i];

            // Grant permission to call initiate()
            calls[callIndex++] = ERC7821.Call({
                to: address(solverAccount),
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    signer1KeyHash,
                    htlc,
                    initiateSel,
                    true
                )
            });

            // Grant permission to call redeem()
            calls[callIndex++] = ERC7821.Call({
                to: address(solverAccount),
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    signer1KeyHash,
                    htlc,
                    redeemSel,
                    true
                )
            });

            // Grant permission to call refund()
            calls[callIndex++] = ERC7821.Call({
                to: address(solverAccount),
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    signer1KeyHash,
                    htlc,
                    refundSel,
                    true
                )
            });
        }

        uint256 nonce = solverAccount.getNonce(0);
        bytes32 digest = solverAccount.computeDigest(calls, nonce);

        bytes memory is1 = _wrapSecpSig(
            signer1PrivateKey,
            signer1KeyHash,
            digest
        );
        bytes memory is2 = _wrapSecpSig(
            signer2PrivateKey,
            signer2KeyHash,
            digest
        );

        bytes[] memory innerSignatures = new bytes[](2);
        innerSignatures[0] = is1;
        innerSignatures[1] = is2;

        bytes memory multisigSignature = abi.encodePacked(
            abi.encode(innerSignatures),
            multisigKeyHash,
            uint8(0)
        );

        vm.startBroadcast(deployerPrivateKey);
        solverAccount.execute(
            calls,
            abi.encodePacked(nonce, multisigSignature)
        );
        vm.stopBroadcast();

        console.log("[OK] signer1 granted permissions for all HTLC addresses:");
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            console.log("  HTLC", i);
            console.log("    Address:", htlcAddresses[i]);
            console.log("    - initiate(address,uint256,uint256,bytes32)");
            console.log("    - redeem(bytes32,bytes)");
            console.log("    - refund(bytes32)");
        }
        console.log("\n");
    }

    function _wrapSecpSig(
        uint256 privateKey,
        bytes32 keyHash,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v, keyHash, uint8(0));
    }
}
