// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.23;

// import "forge-std/Script.sol";
// import {IthacaAccount} from "../src/IthacaAccount.sol";
// import {Orchestrator} from "../src/Orchestrator.sol";
// import {MultiSigSigner} from "../src/MultiSigSigner.sol";
// import {ERC7821} from "solady/accounts/ERC7821.sol";

// /// @title DeploySolverMultisig
// /// @notice Complete deployment and setup of Solver with 2-of-3 multisig on Base Sepolia
// /// @dev This script:
// ///      1. Deploys Orchestrator, IthacaAccount implementation, MultiSigSigner
// ///      2. Deploys a Solver IthacaAccount instance (smart contract wallet)
// ///      3. Sets up 3 signer keys
// ///      4. Configures 2-of-3 multisig as super admin
// ///      5. Tests multisig by revoking a key
// ///      WORKS ON ANY EVM NETWORK - no EIP-7702 required!
// contract DeploySolverMultisig is Script {
//     // Deployed contracts
//     Orchestrator public orchestrator;
//     IthacaAccount public ithacaAccountImpl;
//     MultiSigSigner public multiSigSigner;
//     IthacaAccount public solverAccount; // The actual solver smart contract account

//     // Original EOA (will become admin, can be destroyed later)
//     address public originalEOA;
//     uint256 public originalEOAPrivateKey;

//     // 3 Signer accounts (for 2-of-3 multisig)
//     address public signer1;
//     uint256 public signer1PrivateKey;
//     address public signer2;
//     uint256 public signer2PrivateKey;
//     address public signer3;
//     uint256 public signer3PrivateKey;

//     // Deployer account (needs ETH for deployment)
//     uint256 public deployerPrivateKey;
//     address public deployer;

//     // Keys
//     IthacaAccount.Key public signer1Key;
//     IthacaAccount.Key public signer2Key;
//     IthacaAccount.Key public signer3Key;
//     IthacaAccount.Key public multisigSuperAdminKey;

//     bytes32 public signer1KeyHash;
//     bytes32 public signer2KeyHash;
//     bytes32 public signer3KeyHash;
//     bytes32 public multisigKeyHash;

//     function setUp() public {
//         // Get deployer private key from environment or use default
//         deployerPrivateKey = vm.envOr("DEPLOYER_PRIVATE_KEY", uint256(0x1));
//         deployer = vm.addr(deployerPrivateKey);

//         console.log("\n========================================");
//         console.log("SETUP: Generating Accounts");
//         console.log("========================================\n");

//         // Generate original EOA (temporary admin)
//         originalEOAPrivateKey = uint256(keccak256("ORIGINAL_EOA_V1"));
//         originalEOA = vm.addr(originalEOAPrivateKey);

//         // Generate 3 signer accounts
//         signer1PrivateKey = uint256(keccak256("SIGNER_1_V1"));
//         signer1 = vm.addr(signer1PrivateKey);

//         signer2PrivateKey = uint256(keccak256("SIGNER_2_V1"));
//         signer2 = vm.addr(signer2PrivateKey);

//         signer3PrivateKey = uint256(keccak256("SIGNER_3_V1"));
//         signer3 = vm.addr(signer3PrivateKey);

//         console.log("Deployer Address:", deployer);
//         console.log("Original EOA (temp admin):", originalEOA);
//         console.log("Signer 1:", signer1);
//         console.log("Signer 2:", signer2);
//         console.log("Signer 3:", signer3);

//         console.log("\n========================================");
//         console.log("REQUIRED: Fund These Addresses");
//         console.log("========================================");
//         console.log("1. Deployer (for deployment):", deployer);
//         console.log("   Needs: ~0.05 ETH for contract deployments");
//         console.log("\n2. Original EOA (for setup):", originalEOA);
//         console.log("   Needs: ~0.03 ETH for initial setup transactions");
//         console.log("\nNOTE: Solver smart contract will be deployed during setup!");
//         console.log("========================================\n");
//     }

//     function run() public {
//         // Phase 1: Deploy Contracts
//         deployContracts();

//         // Phase 2: Setup Solver with EIP-7702
//         setupSolverDelegation();

//         // Phase 3: Setup Multisig
//         setupMultisig();

//         // Phase 4: Test Multisig (Revoke a key)
//         testMultisigRevoke();

//         // Phase 5: Print Summary
//         printSummary();
//     }

//     function deployContracts() internal {
//         console.log("\n========================================");
//         console.log("PHASE 1: Deploying Contracts");
//         console.log("========================================\n");

//         vm.startBroadcast(deployerPrivateKey);

//         // Deploy Orchestrator
//         console.log("Deploying Orchestrator...");
//         orchestrator = new Orchestrator();
//         console.log("Orchestrator deployed at:", address(orchestrator));

//         // Deploy IthacaAccount implementation
//         console.log("Deploying IthacaAccount implementation...");
//         ithacaAccountImpl = new IthacaAccount(address(orchestrator));
//         console.log("IthacaAccount deployed at:", address(ithacaAccountImpl));

//         // Deploy MultiSigSigner
//         console.log("Deploying MultiSigSigner...");
//         multiSigSigner = new MultiSigSigner();
//         console.log("MultiSigSigner deployed at:", address(multiSigSigner));

//         vm.stopBroadcast();

//         console.log("\n[OK] All contracts deployed successfully!");
//     }

//     function setupSolverDelegation() internal {
//         console.log("\n========================================");
//         console.log("PHASE 2: Deploy Solver Smart Contract Account");
//         console.log("========================================\n");

//         // Deploy a new IthacaAccount instance for the solver
//         // This is a standard smart contract deployment (works on any network!)

//         vm.broadcast(deployerPrivateKey);
//         solverAccount = new IthacaAccount(address(orchestrator));

//         console.log("Solver Smart Contract deployed at:", address(solverAccount));
//         console.log("This is the address that will hold your funds!");
//         console.log("\n[OK] Solver account is ready!");
//     }

//     function setupMultisig() internal {
//         console.log("\n========================================");
//         console.log("PHASE 3: Setup 2-of-3 Multisig Super Admin");
//         console.log("========================================\n");

//         // Create signer keys
//         signer1Key = IthacaAccount.Key({
//             expiry: 0,
//             keyType: IthacaAccount.KeyType.Secp256k1,
//             isSuperAdmin: false, // Individual signers are NOT super admins
//             publicKey: abi.encode(signer1)
//         });

//         signer2Key = IthacaAccount.Key({
//             expiry: 0,
//             keyType: IthacaAccount.KeyType.Secp256k1,
//             isSuperAdmin: false,
//             publicKey: abi.encode(signer2)
//         });

//         signer3Key = IthacaAccount.Key({
//             expiry: 0,
//             keyType: IthacaAccount.KeyType.Secp256k1,
//             isSuperAdmin: false,
//             publicKey: abi.encode(signer3)
//         });

//         // Authorize signers using original EOA
//         vm.startBroadcast(originalEOAPrivateKey);

//         console.log("Authorizing individual signers...");
//         signer1KeyHash = solverAccount.authorize(signer1Key);
//         signer2KeyHash = solverAccount.authorize(signer2Key);
//         signer3KeyHash = solverAccount.authorize(signer3Key);

//         console.log("Signer 1 KeyHash:", vm.toString(signer1KeyHash));
//         console.log("Signer 2 KeyHash:", vm.toString(signer2KeyHash));
//         console.log("Signer 3 KeyHash:", vm.toString(signer3KeyHash));

//         // Create multisig super admin key
//         console.log("\nCreating multisig super admin key...");
//         multisigSuperAdminKey = IthacaAccount.Key({
//             expiry: 0,
//             keyType: IthacaAccount.KeyType.External,
//             isSuperAdmin: true, // THIS is the super admin!
//             publicKey: abi.encodePacked(address(multiSigSigner), bytes12(0))
//         });

//         multisigKeyHash = solverAccount.authorize(multisigSuperAdminKey);
//         console.log("Multisig KeyHash:", vm.toString(multisigKeyHash));

//         // Initialize multisig config (MUST be called from solver!)
//         bytes32[] memory ownerKeyHashes = new bytes32[](3);
//         ownerKeyHashes[0] = signer1KeyHash;
//         ownerKeyHashes[1] = signer2KeyHash;
//         ownerKeyHashes[2] = signer3KeyHash;

//         console.log("\nInitializing 2-of-3 multisig configuration...");
//         multiSigSigner.initConfig(multisigKeyHash, 2, ownerKeyHashes);

//         vm.stopBroadcast();

//         // Verify configuration
//         (uint256 threshold, bytes32[] memory owners) =
//             multiSigSigner.getConfig(address(solverAccount), multisigKeyHash);
//         require(threshold == 2, "Threshold should be 2");
//         require(owners.length == 3, "Should have 3 owners");

//         console.log("[OK] Multisig configured: 2 of 3");
//         console.log("\n[IMPORTANT] Original solver private key can now be destroyed!");
//         console.log("[IMPORTANT] From now on, 2-of-3 multisig has FULL admin access");
//     }

//     function testMultisigRevoke() internal {
//         console.log("\n========================================");
//         console.log("PHASE 4: Test Multisig - Revoke a Key");
//         console.log("========================================\n");

//         // Create a test key to revoke
//         console.log("Creating a test bot key...");
//         IthacaAccount.Key memory botKey = IthacaAccount.Key({
//             expiry: uint40(block.timestamp + 30 days),
//             keyType: IthacaAccount.KeyType.Secp256k1,
//             isSuperAdmin: false,
//             publicKey: abi.encode(address(0xB07))
//         });

//         vm.broadcast(originalEOAPrivateKey);
//         bytes32 botKeyHash = solverAccount.authorize(botKey);
//         console.log("Bot KeyHash:", vm.toString(botKeyHash));

//         // Now use multisig to revoke it
//         console.log("\nUsing multisig to revoke bot key...");

//         ERC7821.Call[] memory calls = new ERC7821.Call[](1);
//         calls[0] = ERC7821.Call({
//             to: address(solverAccount),
//             value: 0,
//             data: abi.encodeWithSelector(IthacaAccount.revoke.selector, botKeyHash)
//         });

//         uint256 nonce = solverAccount.getNonce(0);
//         bytes32 digest = solverAccount.computeDigest(calls, nonce);

//         // Sign with signer1 and signer2 (2 of 3)
//         bytes memory sig1 = signMessage(signer1PrivateKey, digest);
//         bytes memory sig2 = signMessage(signer2PrivateKey, digest);

//         bytes[] memory innerSignatures = new bytes[](2);
//         innerSignatures[0] = sig1;
//         innerSignatures[1] = sig2;

//         bytes memory multisigSignature =
//             abi.encodePacked(abi.encode(innerSignatures), multisigKeyHash, uint8(0));

//         // Execute via multisig (can be submitted by anyone!)
//         vm.broadcast(originalEOAPrivateKey); // In production, this could be a relayer
//         solverAccount.execute(
//             hex"01000000000078210001", // ERC7821 batch execution mode
//             abi.encode(calls, abi.encodePacked(nonce, multisigSignature))
//         );

//         console.log("[OK] Multisig successfully revoked the key!");

//         // Verify key was revoked
//         try solverAccount.getKey(botKeyHash) {
//             revert("Key should have been revoked!");
//         } catch {
//             console.log("[OK] Key confirmed revoked");
//         }
//     }

//     function printSummary() internal view {
//         console.log("\n========================================");
//         console.log("DEPLOYMENT SUMMARY");
//         console.log("========================================\n");

//         console.log("Deployed Contracts:");
//         console.log("- Orchestrator:", address(orchestrator));
//         console.log("- IthacaAccount Implementation:", address(ithacaAccountImpl));
//         console.log("- MultiSigSigner:", address(multiSigSigner));
//         console.log("- Solver Account (IthacaAccount instance):", address(solverAccount));

//         console.log("\n");
//         console.log("======================================================================");
//         console.log("YOUR SOLVER ADDRESS (send funds here):", address(solverAccount));
//         console.log("======================================================================");

//         console.log("\nMultisig Configuration:");
//         console.log("- Threshold: 2 of 3");
//         console.log("- Signer 1:", signer1);
//         console.log("- Signer 2:", signer2);
//         console.log("- Signer 3:", signer3);
//         console.log("- Multisig KeyHash:", vm.toString(multisigKeyHash));

//         console.log("\nPrivate Keys (SAVE THESE!):");
//         console.log("- Original EOA:", vm.toString(originalEOAPrivateKey));
//         console.log("- Signer 1:", vm.toString(signer1PrivateKey));
//         console.log("- Signer 2:", vm.toString(signer2PrivateKey));
//         console.log("- Signer 3:", vm.toString(signer3PrivateKey));

//         console.log("\n========================================");
//         console.log("SUCCESS! Solver is secured with multisig!");
//         console.log("You can now destroy the original EOA key!");
//         console.log("========================================\n");
//     }

//     // Helper function to sign messages
//     function signMessage(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
//         (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
//         return abi.encodePacked(r, s, v);
//     }
// }
