// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";
import {GuardedExecutor} from "../../src/GuardedExecutor.sol";

/// @title GrantHTLCPermissions
/// @notice Production script to grant signer permissions to call HTLC functions via multisig
/// @dev Usage:
///      forge script script/GrantHTLCPermissions.s.sol --rpc-url $RPC_URL --broadcast
///
///      Required environment variables:
///      - GARDEN_SOLVER: Address of GardenSolver contract
///      - MULTISIG_SIGNER: Address of MultiSigSigner contract
///      - HTLC_ADDRESSES: Comma-separated list of HTLC addresses (or single address)
///      - SIGNER_ADDRESS: Address of signer to grant permissions to
///      - SIGNER1_PRIVATE_KEY: Private key of multisig signer 1
///      - SIGNER2_PRIVATE_KEY: Private key of multisig signer 2
///      - DEPLOYER_PRIVATE_KEY: Private key to broadcast transaction
contract GrantHTLCPermissions is Script {
    function run() public {
        // Load configuration from environment variables
        address gardenSolver = vm.envAddress("GARDEN_SOLVER");
        address multiSigSigner = vm.envAddress("MULTISIG_SIGNER");
        string memory htlcAddressesStr = vm.envString("HTLC_ADDRESSES");
        address signerAddress = vm.envAddress("SIGNER_ADDRESS");

        uint256 signer1PrivateKey = vm.envUint("SIGNER1_PRIVATE_KEY");
        uint256 signer2PrivateKey = vm.envUint("SIGNER2_PRIVATE_KEY");
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        address signer1 = vm.addr(signer1PrivateKey);
        address signer2 = vm.addr(signer2PrivateKey);

        // Parse HTLC addresses (comma-separated or single)
        address[] memory htlcAddresses = _parseAddresses(htlcAddressesStr);

        console.log("\n========================================");
        console.log("Grant HTLC Permissions (Multisig)");
        console.log("========================================");
        console.log("GardenSolver:", gardenSolver);
        console.log("Signer to grant:", signerAddress);
        console.log("HTLC Addresses:");
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            console.log("  HTLC", i);
            console.log("    Address:", htlcAddresses[i]);
        }
        console.log("========================================\n");

        GardenSolver solver = GardenSolver(payable(gardenSolver));

        // Compute key hashes
        IthacaAccount.Key memory signerKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signerAddress)
        });
        IthacaAccount.Key memory signer1KeyStruct = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer1)
        });
        IthacaAccount.Key memory signer2KeyStruct = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer2)
        });
        IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(multiSigSigner, bytes12(0))
        });

        bytes32 signerKeyHash = solver.hash(signerKey);
        bytes32 signer1KeyHash = solver.hash(signer1KeyStruct);
        bytes32 signer2KeyHash = solver.hash(signer2KeyStruct);
        bytes32 multisigKeyHash = solver.hash(multisigKey);

        // Compute function selectors for HTLC functions
        bytes4 initiateSel = bytes4(
            keccak256("initiate(address,uint256,uint256,bytes32)")
        );
        bytes4 redeemSel = bytes4(keccak256("redeem(bytes32,bytes)"));
        bytes4 refundSel = bytes4(keccak256("refund(bytes32)"));

        // Create calls for all HTLC addresses (3 functions per HTLC)
        uint256 numCalls = htlcAddresses.length * 3;
        ERC7821.Call[] memory calls = new ERC7821.Call[](numCalls);

        uint256 callIndex = 0;
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            address htlc = htlcAddresses[i];

            // Grant permission to call initiate()
            calls[callIndex++] = ERC7821.Call({
                to: gardenSolver,
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    signerKeyHash,
                    htlc,
                    initiateSel,
                    true
                )
            });

            // Grant permission to call redeem()
            calls[callIndex++] = ERC7821.Call({
                to: gardenSolver,
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    signerKeyHash,
                    htlc,
                    redeemSel,
                    true
                )
            });

            // Grant permission to call refund()
            calls[callIndex++] = ERC7821.Call({
                to: gardenSolver,
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    signerKeyHash,
                    htlc,
                    refundSel,
                    true
                )
            });
        }

        // Get nonce and compute digest
        uint256 nonce = solver.getNonce(0);
        bytes32 digest = solver.computeDigest(calls, nonce);

        // Sign with signer1 and signer2
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(signer1PrivateKey, digest);
        bytes memory sig1 = abi.encodePacked(
            r1,
            s1,
            v1,
            signer1KeyHash,
            uint8(0)
        );

        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(signer2PrivateKey, digest);
        bytes memory sig2 = abi.encodePacked(
            r2,
            s2,
            v2,
            signer2KeyHash,
            uint8(0)
        );

        // Create multisig signature
        bytes[] memory innerSignatures = new bytes[](2);
        innerSignatures[0] = sig1;
        innerSignatures[1] = sig2;

        bytes memory multisigSignature = abi.encodePacked(
            abi.encode(innerSignatures),
            multisigKeyHash,
            uint8(0)
        );

        // Execute
        vm.startBroadcast(deployerPrivateKey);
        solver.execute(calls, abi.encodePacked(nonce, multisigSignature));
        vm.stopBroadcast();

        console.log("\n[OK] Permissions granted successfully!");
        console.log("Signer:", signerAddress);
        console.log("Permissions granted for:");
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            console.log("  HTLC", i);
            console.log("    Address:", htlcAddresses[i]);
            console.log("    - initiate(address,uint256,uint256,bytes32)");
            console.log("    - redeem(bytes32,bytes)");
            console.log("    - refund(bytes32)");
        }
        console.log("========================================\n");
    }

    /// @notice Parse comma-separated addresses or single address
    function _parseAddresses(
        string memory addressesStr
    ) internal view returns (address[] memory) {
        // Check if it contains comma
        bytes memory strBytes = bytes(addressesStr);
        bool hasComma = false;
        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == bytes1(",")) {
                hasComma = true;
                break;
            }
        }

        if (!hasComma) {
            // Single address
            address[] memory singleResult = new address[](1);
            singleResult[0] = vm.parseAddress(addressesStr);
            return singleResult;
        }

        // Multiple addresses - count commas first
        uint256 commaCount = 0;
        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == bytes1(",")) {
                commaCount++;
            }
        }

        address[] memory result = new address[](commaCount + 1);
        uint256 count = 0;
        uint256 start = 0;

        for (uint256 i = 0; i <= strBytes.length; i++) {
            if (i == strBytes.length || strBytes[i] == bytes1(",")) {
                if (i > start) {
                    bytes memory addrBytes = new bytes(i - start);
                    for (uint256 j = start; j < i; j++) {
                        addrBytes[j - start] = strBytes[j];
                    }
                    result[count++] = vm.parseAddress(string(addrBytes));
                }
                start = i + 1;
            }
        }

        // Resize array to actual count
        address[] memory finalResult = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            finalResult[i] = result[i];
        }
        return finalResult;
    }
}
