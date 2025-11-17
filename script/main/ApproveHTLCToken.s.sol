// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";

interface IHTLC {
    function token() external view returns (address);
}

/// @title ApproveHTLCToken
/// @notice Production script to approve tokens from GardenSolver to HTLC contract(s) via multisig
/// @dev Usage:
///      forge script script/main/ApproveHTLCToken.s.sol --rpc-url $RPC_URL --broadcast
///
///      Required environment variables:
///      - GARDEN_SOLVER: Address of GardenSolver contract
///      - MULTISIG_SIGNER: Address of MultiSigSigner contract
///      - HTLC_ADDRESSES: Comma-separated list of HTLC addresses (or single address)
///                        Each HTLC's token will be fetched and approved to that HTLC
///      - SIGNER1_PRIVATE_KEY: Private key of signer 1
///      - SIGNER2_PRIVATE_KEY: Private key of signer 2
///      - DEPLOYER_PRIVATE_KEY: Private key to broadcast transaction
contract ApproveHTLCToken is Script {
    function run() public {
        address gardenSolver = vm.envAddress("GARDEN_SOLVER");
        address multiSigSigner = vm.envAddress("MULTISIG_SIGNER");
        string memory htlcAddressesStr = vm.envString("HTLC_ADDRESSES");

        // Parse HTLC addresses (comma-separated or single)
        address[] memory htlcAddresses = _parseAddresses(htlcAddressesStr);
        require(htlcAddresses.length > 0, "No HTLC addresses provided");

        // Fetch token from each HTLC contract
        address[] memory tokens = new address[](htlcAddresses.length);
        console.log("\nFetching tokens from HTLC contracts:");
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            IHTLC htlcContract = IHTLC(htlcAddresses[i]);
            tokens[i] = htlcContract.token();
            console.log("  HTLC", i);
            console.log("    Address:", htlcAddresses[i]);
            console.log("    Token:", tokens[i]);
        }

        uint256 signer1PrivateKey = vm.envUint("SIGNER1_PRIVATE_KEY");
        uint256 signer2PrivateKey = vm.envUint("SIGNER2_PRIVATE_KEY");
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        address signer1 = vm.addr(signer1PrivateKey);
        address signer2 = vm.addr(signer2PrivateKey);

        console.log("\n========================================");
        console.log("Approve Tokens to HTLCs (Multisig)");
        console.log("========================================");
        console.log("GardenSolver:", gardenSolver);
        console.log("HTLC Addresses and Tokens:");
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            console.log("  HTLC", i);
            console.log("    Address:", htlcAddresses[i]);
            console.log("    Token:", tokens[i]);
        }
        console.log("Signer 1:", signer1);
        console.log("Signer 2:", signer2);
        console.log("========================================\n");

        GardenSolver solver = GardenSolver(payable(gardenSolver));

        // Compute key hashes
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
        IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(multiSigSigner, bytes12(0))
        });

        bytes32 signer1KeyHash = solver.hash(signer1Key);
        bytes32 signer2KeyHash = solver.hash(signer2Key);
        bytes32 multisigKeyHash = solver.hash(multisigKey);

        // Create approval calls - each HTLC gets approval for its own token
        ERC7821.Call[] memory calls = new ERC7821.Call[](htlcAddresses.length);
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            calls[i] = ERC7821.Call({
                to: tokens[i], // Use the token specific to this HTLC
                value: 0,
                data: abi.encodeWithSignature(
                    "approve(address,uint256)",
                    htlcAddresses[i], // Approve to this specific HTLC
                    type(uint256).max
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

        // Verify approvals - check each HTLC's token allowance
        console.log("\n[OK] Tokens approved successfully!");
        console.log("Allowances:");
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            (bool success, bytes memory data) = tokens[i].staticcall(
                abi.encodeWithSignature(
                    "allowance(address,address)",
                    gardenSolver,
                    htlcAddresses[i]
                )
            );
            require(success, "Failed to check allowance");
            uint256 allowance = abi.decode(data, (uint256));
            console.log("  HTLC", i);
            console.log("    Address:", htlcAddresses[i]);
            console.log("    Token:", tokens[i]);
            console.log("    Allowance:", allowance);
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
