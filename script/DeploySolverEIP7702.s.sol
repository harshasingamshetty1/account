// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.23;

// import "forge-std/Script.sol";
// import {IthacaAccount} from "../src/IthacaAccount.sol";
// import {Orchestrator} from "../src/Orchestrator.sol";
// import {MultiSigSigner} from "../src/MultiSigSigner.sol";
// import {ERC7821} from "solady/accounts/ERC7821.sol";

// /// @title DeploySolverEIP7702
// /// @notice Deploy Solver with 2-of-3 multisig using EIP-7702 on Anvil
// /// @dev Uses vm.etch() to simulate EIP-7702 delegation (works on Anvil)
// ///      For real networks, wait for cast/forge EIP-7702 support
// contract DeploySolverEIP7702 is Script {
//     Orchestrator public orchestrator;
//     IthacaAccount public ithacaAccountImpl;
//     MultiSigSigner public multiSigSigner;

//     address public solverEOA;
//     uint256 public solverPrivateKey;

//     address public signer1;
//     uint256 public signer1PrivateKey;
//     address public signer2;
//     uint256 public signer2PrivateKey;
//     address public signer3;
//     uint256 public signer3PrivateKey;

//     bytes32 public signer1KeyHash;
//     bytes32 public signer2KeyHash;
//     bytes32 public signer3KeyHash;
//     bytes32 public multisigKeyHash;

//     function setUp() public {
//         // Generate deterministic accounts (same as test)
//         solverPrivateKey = uint256(keccak256("SOLVER_ACCOUNT_V1"));
//         solverEOA = vm.addr(solverPrivateKey);

//         signer1PrivateKey = uint256(keccak256("SIGNER_1_V1"));
//         signer1 = vm.addr(signer1PrivateKey);

//         signer2PrivateKey = uint256(keccak256("SIGNER_2_V1"));
//         signer2 = vm.addr(signer2PrivateKey);

//         signer3PrivateKey = uint256(keccak256("SIGNER_3_V1"));
//         signer3 = vm.addr(signer3PrivateKey);

//         console.log("\n========================================");
//         console.log("ACCOUNTS");
//         console.log("========================================");
//         console.log("Solver EOA:", solverEOA);
//         console.log("Signer 1:", signer1);
//         console.log("Signer 2:", signer2);
//         console.log("Signer 3:", signer3);
//         console.log("========================================\n");
//     }

//     function run() public {
//         // Phase 1: Deploy contracts
//         deployContracts();

//         // Phase 2: EIP-7702 delegation (simulated with vm.etch)
//         setupEIP7702Delegation();

//         // Phase 3: Setup multisig
//         setupMultisig();

//         // Phase 4: Test multisig
//         testMultisigRevoke();

//         // Phase 5: Summary
//         printSummary();
//     }

//     function deployContracts() internal {
//         console.log("\n========================================");
//         console.log("PHASE 1: Deploying Contracts");
//         console.log("========================================\n");

//         vm.startBroadcast();

//         orchestrator = new Orchestrator();
//         console.log("Orchestrator:", address(orchestrator));

//         ithacaAccountImpl = new IthacaAccount(address(orchestrator));
//         console.log("IthacaAccount Implementation:", address(ithacaAccountImpl));

//         multiSigSigner = new MultiSigSigner();
//         console.log("MultiSigSigner:", address(multiSigSigner));

//         vm.stopBroadcast();

//         console.log("\n[OK] Contracts deployed!");
//     }

//     function setupEIP7702Delegation() internal {
//         console.log("\n========================================");
//         console.log("PHASE 2: EIP-7702 Delegation");
//         console.log("========================================\n");

//         console.log("Simulating EIP-7702 delegation using vm.etch()");
//         console.log("This works on Anvil for testing!");
//         console.log("For real networks, use cast with EIP-7702 transaction type");

//         // Simulate EIP-7702: delegate solverEOA to ithacaAccountImpl
//         vm.etch(solverEOA, address(ithacaAccountImpl).code);

//         console.log("Solver EOA:", solverEOA);
//         console.log("Delegated to:", address(ithacaAccountImpl));
//         console.log("\n[OK] EIP-7702 delegation complete!");
//     }

//     function setupMultisig() internal {
//         console.log("\n========================================");
//         console.log("PHASE 3: Setup 2-of-3 Multisig");
//         console.log("========================================\n");

//         IthacaAccount solver = IthacaAccount(payable(solverEOA));

//         // Create signer keys
//         IthacaAccount.Key memory signer1Key = IthacaAccount.Key({
//             expiry: 0,
//             keyType: IthacaAccount.KeyType.Secp256k1,
//             isSuperAdmin: false,
//             publicKey: abi.encode(signer1)
//         });

//         IthacaAccount.Key memory signer2Key = IthacaAccount.Key({
//             expiry: 0,
//             keyType: IthacaAccount.KeyType.Secp256k1,
//             isSuperAdmin: false,
//             publicKey: abi.encode(signer2)
//         });

//         IthacaAccount.Key memory signer3Key = IthacaAccount.Key({
//             expiry: 0,
//             keyType: IthacaAccount.KeyType.Secp256k1,
//             isSuperAdmin: false,
//             publicKey: abi.encode(signer3)
//         });

//         // Authorize signers
//         vm.startBroadcast(solverPrivateKey);

//         console.log("Authorizing individual signers...");
//         signer1KeyHash = solver.authorize(signer1Key);
//         signer2KeyHash = solver.authorize(signer2Key);
//         signer3KeyHash = solver.authorize(signer3Key);

//         console.log("Signer 1 KeyHash:", vm.toString(signer1KeyHash));
//         console.log("Signer 2 KeyHash:", vm.toString(signer2KeyHash));
//         console.log("Signer 3 KeyHash:", vm.toString(signer3KeyHash));

//         // Create multisig super admin key
//         console.log("\nCreating multisig super admin key...");
//         IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
//             expiry: 0,
//             keyType: IthacaAccount.KeyType.External,
//             isSuperAdmin: true,
//             publicKey: abi.encodePacked(address(multiSigSigner), bytes12(0))
//         });

//         multisigKeyHash = solver.authorize(multisigKey);
//         console.log("Multisig KeyHash:", vm.toString(multisigKeyHash));

//         // Initialize multisig config
//         bytes32[] memory ownerKeyHashes = new bytes32[](3);
//         ownerKeyHashes[0] = signer1KeyHash;
//         ownerKeyHashes[1] = signer2KeyHash;
//         ownerKeyHashes[2] = signer3KeyHash;

//         console.log("\nInitializing 2-of-3 multisig...");
//         multiSigSigner.initConfig(multisigKeyHash, 2, ownerKeyHashes);

//         vm.stopBroadcast();

//         // Verify
//         (uint256 threshold, bytes32[] memory owners) =
//             multiSigSigner.getConfig(solverEOA, multisigKeyHash);
//         require(threshold == 2, "Threshold should be 2");
//         require(owners.length == 3, "Should have 3 owners");

//         console.log("\n[OK] Multisig configured: 2 of 3");
//         console.log("[IMPORTANT] Original solver key can now be destroyed!");
//     }

//     function testMultisigRevoke() internal {
//         console.log("\n========================================");
//         console.log("PHASE 4: Test Multisig - Revoke Key");
//         console.log("========================================\n");

//         IthacaAccount solver = IthacaAccount(payable(solverEOA));

//         // Create a test bot key
//         console.log("Creating test bot key...");
//         IthacaAccount.Key memory botKey = IthacaAccount.Key({
//             expiry: uint40(block.timestamp + 30 days),
//             keyType: IthacaAccount.KeyType.Secp256k1,
//             isSuperAdmin: false,
//             publicKey: abi.encode(address(0xB07))
//         });

//         vm.broadcast(solverPrivateKey);
//         bytes32 botKeyHash = solver.authorize(botKey);
//         console.log("Bot KeyHash:", vm.toString(botKeyHash));

//         // Revoke using multisig
//         console.log("\nRevoking bot key using multisig...");

//         ERC7821.Call[] memory calls = new ERC7821.Call[](1);
//         calls[0] = ERC7821.Call({
//             to: solverEOA,
//             value: 0,
//             data: abi.encodeWithSelector(IthacaAccount.revoke.selector, botKeyHash)
//         });

//         uint256 nonce = solver.getNonce(0);
//         bytes32 digest = solver.computeDigest(calls, nonce);

//         // Sign with 2 of 3 signers (signature format: r, s, v, keyHash, prehash)
//         bytes memory sig1 = _sign(signer1PrivateKey, signer1KeyHash, digest);
//         bytes memory sig2 = _sign(signer2PrivateKey, signer2KeyHash, digest);

//         bytes[] memory innerSignatures = new bytes[](2);
//         innerSignatures[0] = sig1;
//         innerSignatures[1] = sig2;

//         bytes memory multisigSignature =
//             abi.encodePacked(abi.encode(innerSignatures), multisigKeyHash, uint8(0));

//         // Execute via multisig
//         vm.broadcast(solverPrivateKey);
//         solver.execute(
//             hex"01000000000078210001", abi.encode(calls, abi.encodePacked(nonce, multisigSignature))
//         );

//         console.log("[OK] Multisig successfully revoked the key!");

//         // Verify
//         try solver.getKey(botKeyHash) {
//             revert("Key should be revoked!");
//         } catch {
//             console.log("[OK] Key confirmed revoked");
//         }
//     }

//     function printSummary() internal view {
//         console.log("\n========================================");
//         console.log("DEPLOYMENT SUMMARY");
//         console.log("========================================\n");

//         console.log("Solver EOA (delegated):", solverEOA);
//         console.log("Orchestrator:", address(orchestrator));
//         console.log("IthacaAccount Implementation:", address(ithacaAccountImpl));
//         console.log("MultiSigSigner:", address(multiSigSigner));

//         console.log("\nMultisig: 2 of 3");
//         console.log("Signer 1:", signer1);
//         console.log("Signer 2:", signer2);
//         console.log("Signer 3:", signer3);

//         console.log("\n========================================");
//         console.log("SUCCESS! Ready for production!");
//         console.log("========================================\n");
//     }

//     function _sign(uint256 privateKey, bytes32 keyHash, bytes32 digest)
//         internal
//         pure
//         returns (bytes memory)
//     {
//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
//         // Secp256k1 signature format: r, s, v, keyHash, prehash (0)
//         return abi.encodePacked(r, s, v, keyHash, uint8(0));
//     }
// }
