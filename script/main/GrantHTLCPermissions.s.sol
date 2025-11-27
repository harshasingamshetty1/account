// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";
import {GuardedExecutor} from "../../src/GuardedExecutor.sol";

/// @title GrantHTLCPermissions
/// @notice Script to grant executor permissions to HTLCs via a hardware signature
/// @dev please never change the console.log the cli scripts parse these output and executes accordingly
contract GrantHTLCPermissions is Script {
    function run() public {
        address gardenSolver = vm.envAddress("GARDEN_SOLVER");
        address executorAddress = vm.envAddress("PERMISSION_ADDRESS");
        address signer = vm.envAddress("SIGNER_ONE_ADDRESS");
        bytes32 multisigKeyHash = vm.envBytes32("MULTISIG_KEY_HASH");
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        string memory htlcAddressesStr = vm.envString("HTLC_ADDRESSES");
        address[] memory htlcAddresses = _parseAddresses(htlcAddressesStr);

        require(htlcAddresses.length > 0, "No HTLCs provided");

        GardenSolver solver = GardenSolver(payable(gardenSolver));

        IthacaAccount.Key memory executorKey = _buildKey(executorAddress);
        IthacaAccount.Key memory signerKey = _buildKey(signer);

        bytes32 executorKeyHash = solver.hash(executorKey);
        bytes32 signerKeyHash = solver.hash(signerKey);

        ERC7821.Call[] memory permissionCalls = _buildPermissionCalls(
            gardenSolver,
            executorKeyHash,
            htlcAddresses
        );

        uint256 permNonce = solver.getNonce(0);
        bytes32 permDigest = solver.computeDigest(permissionCalls, permNonce);
        console.log("PermDigest:", vm.toString(permDigest));

        (string memory signatureHex, bool hasSignature) = _loadSignature(
            "SIGNATURE_PERM"
        );
        console.log("PermSignature:", signatureHex);

        if (!hasSignature) {
            return;
        }

        bytes memory signerOneSig = _collectSignature(
            signatureHex,
            permDigest,
            signer,
            signerKeyHash
        );

        bytes[] memory innerSignatures = new bytes[](1);
        innerSignatures[0] = signerOneSig;

        bytes memory permSignature = abi.encodePacked(
            abi.encode(innerSignatures),
            multisigKeyHash,
            uint8(0)
        );

        console.log("\nBroadcasting permissions transaction");
        vm.startBroadcast(deployerPrivateKey);
        solver.execute(
            permissionCalls,
            abi.encodePacked(permNonce, permSignature)
        );
        vm.stopBroadcast();

        console.log("\nPermissions granted:");
        console.log("Executor:", executorAddress);
        console.log("Executor KeyHash:", vm.toString(executorKeyHash));
        console.log("HTLC count:", htlcAddresses.length);
    }

    function _buildKey(
        address target
    ) internal pure returns (IthacaAccount.Key memory) {
        return
            IthacaAccount.Key({
                expiry: 0,
                keyType: IthacaAccount.KeyType.Secp256k1,
                isSuperAdmin: false,
                publicKey: abi.encode(target)
            });
    }

    function _loadSignature(
        string memory envKey
    ) internal view returns (string memory, bool) {
        try vm.envString(envKey) returns (string memory value) {
            bool provided = bytes(value).length != 0;
            return (value, provided);
        } catch {
            return ("", false);
        }
    }

    function _collectSignature(
        string memory hexSignature,
        bytes32 digest,
        address signer,
        bytes32 signerKeyHash
    ) internal pure returns (bytes memory) {
        bytes memory sigBytes = vm.parseBytes(hexSignature);
        require(sigBytes.length == 65, "Signature must be 65 bytes");

        (bytes32 r, bytes32 s, uint8 v) = _splitSignature(sigBytes);
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );

        address recovered = ecrecover(ethSignedMessageHash, v, r, s);
        require(recovered == signer, "Signature verification failed");

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

    function _buildPermissionCalls(
        address gardenSolver,
        bytes32 executorKeyHash,
        address[] memory htlcAddresses
    ) internal pure returns (ERC7821.Call[] memory permissionCalls) {
        bytes4 initiateSel = bytes4(
            keccak256("initiate(address,uint256,uint256,bytes32)")
        );
        bytes4 redeemSel = bytes4(keccak256("redeem(bytes32,bytes)"));
        bytes4 refundSel = bytes4(keccak256("refund(bytes32)"));
        bytes4 instantRefundSel = bytes4(
            keccak256("instantRefund(bytes32,bytes)")
        );

        uint256 numCalls = htlcAddresses.length * 4 + 1;
        permissionCalls = new ERC7821.Call[](numCalls);
        uint256 callIndex;

        for (uint256 i = 0; i < htlcAddresses.length; i++) {
            address htlc = htlcAddresses[i];

            permissionCalls[callIndex++] = ERC7821.Call({
                to: gardenSolver,
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    executorKeyHash,
                    htlc,
                    initiateSel,
                    true
                )
            });

            permissionCalls[callIndex++] = ERC7821.Call({
                to: gardenSolver,
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    executorKeyHash,
                    htlc,
                    redeemSel,
                    true
                )
            });

            permissionCalls[callIndex++] = ERC7821.Call({
                to: gardenSolver,
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    executorKeyHash,
                    htlc,
                    refundSel,
                    true
                )
            });

            permissionCalls[callIndex++] = ERC7821.Call({
                to: gardenSolver,
                value: 0,
                data: abi.encodeWithSelector(
                    GuardedExecutor.setCanExecute.selector,
                    executorKeyHash,
                    htlc,
                    instantRefundSel,
                    true
                )
            });
        }

        permissionCalls[callIndex] = ERC7821.Call({
            to: gardenSolver,
            value: 0,
            data: abi.encodeWithSelector(
                GuardedExecutor.setSpendLimit.selector,
                executorKeyHash,
                address(0),
                GuardedExecutor.SpendPeriod.Forever,
                100 ether
            )
        });
    }

    function _parseAddresses(
        string memory addressesStr
    ) internal pure returns (address[] memory) {
        bytes memory strBytes = bytes(addressesStr);
        bool hasComma = false;
        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == bytes1(",")) {
                hasComma = true;
                break;
            }
        }

        if (!hasComma) {
            address[] memory singleResult = new address[](1);
            singleResult[0] = vm.parseAddress(addressesStr);
            return singleResult;
        }

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

        address[] memory finalResult = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            finalResult[i] = result[i];
        }
        return finalResult;
    }
}
