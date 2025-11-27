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
/// @dev please never change the console.log the cli scripts parse these output and executes accordingly
/// @notice Script to approve each HTLC’s token allowance via hardware wallet signatures
contract ApproveHTLCToken is Script {
    function run() public {
        address gardenSolverAddress = vm.envAddress("GARDEN_SOLVER");
        string memory htlcAddressesStr = vm.envString("HTLC_ADDRESSES");
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        address[] memory htlcAddresses = _parseAddresses(htlcAddressesStr);
        require(htlcAddresses.length > 0, "No HTLC addresses provided");

        address[] memory tokens = _fetchTokens(htlcAddresses);
        address signer = vm.envAddress("SIGNER_ONE_ADDRESS");
        GardenSolver solver = GardenSolver(payable(gardenSolverAddress));

        bytes32 signerKeyHash = _signerKeyHash(signer, solver);
        bytes32 multisigKeyHash = vm.envBytes32("MULTISIG_KEY_HASH");

        ERC7821.Call[] memory calls = _buildApprovalCalls(
            htlcAddresses,
            tokens
        );

        uint256 nonce = solver.getNonce(0);
        bytes32 digest = solver.computeDigest(calls, nonce);
        console.log("Digest:", vm.toString(digest));

        bytes memory signerOneSig = _collectSignature(
            digest,
            signer,
            signerKeyHash
        );
        console.log("Signer One Signature:", vm.toString(signerOneSig));

        if (signerOneSig.length == 0) {
            revert("Signature not provided");
        }

        bytes[] memory innerSignatures = new bytes[](1);
        innerSignatures[0] = signerOneSig;

        bytes memory signature = abi.encodePacked(
            abi.encode(innerSignatures),
            multisigKeyHash,
            uint8(0)
        );

        console.log("\nBroadcasting approval transaction");
        vm.startBroadcast(deployerPrivateKey);
        solver.execute(calls, abi.encodePacked(nonce, signature));
        vm.stopBroadcast();

        _verifyAllowances(gardenSolverAddress, htlcAddresses, tokens);
    }

    function _fetchTokens(
        address[] memory htlcAddresses
    ) internal view returns (address[] memory) {
        address[] memory tokens = new address[](htlcAddresses.length);
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            tokens[i] = IHTLC(htlcAddresses[i]).token();
        }
        return tokens;
    }

    function _buildApprovalCalls(
        address[] memory htlcAddresses,
        address[] memory tokens
    ) internal pure returns (ERC7821.Call[] memory) {
        ERC7821.Call[] memory calls = new ERC7821.Call[](htlcAddresses.length);
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            calls[i] = ERC7821.Call({
                to: tokens[i],
                value: 0,
                data: abi.encodeWithSignature(
                    "approve(address,uint256)",
                    htlcAddresses[i],
                    type(uint256).max
                )
            });
        }
        return calls;
    }

    function _signerKeyHash(
        address signer,
        GardenSolver solver
    ) internal pure returns (bytes32) {
        IthacaAccount.Key memory signerKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer)
        });
        return solver.hash(signerKey);
    }

    function _collectSignature(
        bytes32 digest,
        address signer,
        bytes32 signerKeyHash
    ) internal view returns (bytes memory) {
        string memory signature = vm.envString("SIGNATURE");
        bytes memory sigBytes = vm.parseBytes(signature);
        require(sigBytes.length == 65, "Signature must be 65 bytes");

        (bytes32 r, bytes32 s, uint8 v) = _splitSignature(sigBytes);
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );

        address recovered = ecrecover(ethSignedMessageHash, v, r, s);
        require(recovered == signer, "Signature verification failed");

        console.log("Signature verified for signer:", signer);
        return abi.encodePacked(r, s, v, signerKeyHash, uint8(0));
    }

    function _splitSignature(
        bytes memory sigBytes
    ) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := mload(add(sigBytes, 0x20))
            s := mload(add(sigBytes, 0x40))
            v := byte(0, mload(add(sigBytes, 0x60)))
        }
    }

    function _verifyAllowances(
        address gardenSolver,
        address[] memory htlcAddresses,
        address[] memory tokens
    ) internal view {
        console.log("\nVerifying allowances...");
        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            (bool success, bytes memory data) = tokens[i].staticcall(
                abi.encodeWithSignature(
                    "allowance(address,address)",
                    gardenSolver,
                    htlcAddresses[i]
                )
            );
            require(success, "Allowance lookup failed");
            uint256 allowance = abi.decode(data, (uint256));
            console.log("  HTLC", i, "allowance", allowance);
        }
    }

    /// @notice Parse comma-separated addresses or single address
    function _parseAddresses(
        string memory addressesStr
    ) internal pure returns (address[] memory) {
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
