// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";

/// @title AuthorizeExecutor
/// @dev please never change the console.log the cli scripts parse these output and executes accordingly
/// @notice Minimal workflow to authorize an executor key via hardware wallet signatures
contract AuthorizeExecutor is Script {
    function run() public {
        address gardenSolver = vm.envAddress("GARDEN_SOLVER");
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address executorAddress = vm.envAddress("PERMISSION_ADDRESS");
        address signer = vm.envAddress("SIGNER_ONE_ADDRESS");
        bytes32 multisigKeyHash = vm.envBytes32("MULTISIG_KEY_HASH");

        GardenSolver solver = GardenSolver(payable(gardenSolver));

        IthacaAccount.Key memory executorKey = _buildKey(executorAddress);
        IthacaAccount.Key memory signerKey = _buildKey(signer);

        bytes32 executorKeyHash = solver.hash(executorKey);
        bytes32 signerKeyHash = solver.hash(signerKey);

        ERC7821.Call[] memory authCalls = _authCalls(gardenSolver, executorKey);
        uint256 authNonce = solver.getNonce(0);
        bytes32 authDigest = solver.computeDigest(authCalls, authNonce);
        console.log("AuthDigest:", vm.toString(authDigest));

        (string memory signatureHex, bool hasSignature) = _loadSignature(
            "SIGNATURE_AUTH"
        );
        console.log("AuthSignature:", signatureHex);

        if (!hasSignature) {
            return;
        }

        bytes memory signerOneSig = _collectSignature(
            signatureHex,
            authDigest,
            signer,
            signerKeyHash
        );

        bytes[] memory innerSignatures = new bytes[](1);
        innerSignatures[0] = signerOneSig;

        bytes memory authSignature = abi.encodePacked(
            abi.encode(innerSignatures),
            multisigKeyHash,
            uint8(0)
        );

        console.log("\nBroadcasting authorization transaction");

        vm.startBroadcast(deployerPrivateKey);
        solver.execute(authCalls, abi.encodePacked(authNonce, authSignature));
        vm.stopBroadcast();

        console.log("\nExecutor authorized:");
        console.log("Executor:", executorAddress);
        console.log("Executor KeyHash:", vm.toString(executorKeyHash));
    }

    function _buildKey(
        address signer
    ) internal pure returns (IthacaAccount.Key memory) {
        return
            IthacaAccount.Key({
                expiry: 0,
                keyType: IthacaAccount.KeyType.Secp256k1,
                isSuperAdmin: false,
                publicKey: abi.encode(signer)
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

    function _authCalls(
        address gardenSolver,
        IthacaAccount.Key memory executorKey
    ) internal pure returns (ERC7821.Call[] memory) {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: gardenSolver,
            value: 0,
            data: abi.encodeWithSelector(
                IthacaAccount.authorize.selector,
                executorKey
            )
        });
        return calls;
    }
}
