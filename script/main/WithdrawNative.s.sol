// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";

/// @title WithdrawNative
/// @dev please never change the console.log the cli scripts parse these output and executes accordingly
/// @notice Script to withdraw funds from GardenSolver via hardware wallet signature
contract WithdrawNative is Script {
    function run() public {
        address gardenSolverAddress = vm.envAddress("GARDEN_SOLVER");
        address recipient = vm.envAddress("RECIPIENT_ADDRESS");
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        uint256 amount = vm.envUint("AMOUNT");

        address signer = vm.envAddress("SIGNER_ONE_ADDRESS");
        GardenSolver solver = GardenSolver(payable(gardenSolverAddress));

        bytes32 signerKeyHash = _signerKeyHash(signer, solver);
        bytes32 multisigKeyHash = vm.envBytes32("MULTISIG_KEY_HASH");

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: address(solver),
            value: 0,
            data: abi.encodeWithSignature(
                "withdraw(address,address,uint256)",
                recipient,
                address(0), // native token
                amount
            )
        });

        uint256 nonce = solver.getNonce(0);
        bytes32 digest = solver.computeDigest(calls, nonce);
        console.log("WithdrawDigest:", vm.toString(digest));

        (string memory signatureHex, bool hasSignature) = _loadSignature(
            "SIGNATURE"
        );
        console.log("Signature:", signatureHex);

        if (!hasSignature) {
            return;
        }

        bytes memory signerOneSig = _collectSignature(
            signatureHex,
            digest,
            signer,
            signerKeyHash
        );
        console.log("Signer One Signature:", vm.toString(signerOneSig));

        bytes[] memory innerSignatures = new bytes[](1);
        innerSignatures[0] = signerOneSig;

        bytes memory signature = abi.encodePacked(
            abi.encode(innerSignatures),
            multisigKeyHash,
            uint8(0)
        );

        console.log("\nBroadcasting withdrawal transaction");
        vm.startBroadcast(deployerPrivateKey);
        solver.execute(calls, abi.encodePacked(nonce, signature));
        vm.stopBroadcast();

        console.log("Withdrawal done!");
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
}
