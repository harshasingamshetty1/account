// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";

/// @title AuthorizeExecutor
/// @notice Script to authorize executor key via hardware wallet
/// @dev Usage:
///
///      Step 1 - Get authorization digest to sign:
///      forge script script/main/AuthorizeExecutor.s.sol --rpc-url $RPC_URL
///
///      Step 2 - Sign the authorization digest with Ledger:
///      cast wallet sign --ledger <AUTH_DIGEST_FROM_STEP_1>
///      export SIGNATURE_AUTH=<SIGNATURE_FROM_STEP_2>
///
///      Step 3 - Broadcast authorization:
///      forge script script/main/AuthorizeExecutor.s.sol --rpc-url $RPC_URL --broadcast
///
///      Required environment variables:
///      - GARDEN_SOLVER: Address of GardenSolver contract
///      - PERMISSION_ADDRESS: Address of executor to authorize
///      - SIGNER_ONE_ADDRESS (or SIGNER_ADDRESS): Hardware signer address
///      - SIGNER_TWO_ADDRESS: Address of second signer (software key)
///      - SIGNER_TWO_PRIVATE_KEY: Private key for second signer (hex string)
///      - SIGNATURE_AUTH: (Optional) Signature for authorization step (hardware signer)
///      - DEPLOYER_PRIVATE_KEY: Private key to broadcast transaction (required)
contract AuthorizeExecutor is Script {
    function run() public {
        // Load configuration from environment variables
        address gardenSolver = vm.envAddress("GARDEN_SOLVER");
        address executorAddress = vm.envAddress("PERMISSION_ADDRESS");

        address signer = vm.envAddress("SIGNER_ONE_ADDRESS");
        // uint256 signer2PrivateKey = vm.envUint("SIGNER_TWO_PRIVATE_KEY");
        // address signer2 = vm.addr(signer2PrivateKey);

        console.log("\n========================================");
        console.log("Authorize Executor");
        console.log("========================================");
        console.log("GardenSolver:", gardenSolver);
        console.log("Executor Address:", executorAddress);
        console.log("Signer 1 Address:", signer);
        // console.log("Signer 2 Address:", signer2);
        console.log("========================================\n");

        GardenSolver solver = GardenSolver(payable(gardenSolver));

        // Compute key hashes
        IthacaAccount.Key memory executorKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(executorAddress)
        });
        IthacaAccount.Key memory signerKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer)
        });
        // IthacaAccount.Key memory signer2Key = IthacaAccount.Key({
        //     expiry: 0,
        //     keyType: IthacaAccount.KeyType.Secp256k1,
        //     isSuperAdmin: false,
        //     publicKey: abi.encode(signer2)
        // });

        bytes32 executorKeyHash = solver.hash(executorKey);
        bytes32 signerKeyHash = solver.hash(signerKey);
        // bytes32 signer2KeyHash = solver.hash(signer2Key);

        // Get multisig key hash from environment (from deployed.json)
        bytes32 multisigKeyHash;
        try vm.envBytes32("MULTISIG_KEY_HASH") returns (bytes32 hash) {
            multisigKeyHash = hash;
        } catch {
            // Compute multisig key hash if not provided
            address multiSigSigner = vm.envAddress("MULTISIG_SIGNER");
            IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
                expiry: 0,
                keyType: IthacaAccount.KeyType.External,
                isSuperAdmin: true,
                publicKey: abi.encodePacked(multiSigSigner, bytes12(0))
            });
            multisigKeyHash = solver.hash(multisigKey);
        }

        console.log("Executor KeyHash:", vm.toString(executorKeyHash));
        console.log("Signer KeyHash:", vm.toString(signerKeyHash));
        // console.log("Signer 2 KeyHash:", vm.toString(signer2KeyHash));
        console.log("Multisig KeyHash:", vm.toString(multisigKeyHash));
        console.log("");

        // Authorize executor key
        console.log("Authorizing executor key...");
        ERC7821.Call[] memory authCalls = new ERC7821.Call[](1);
        authCalls[0] = ERC7821.Call({
            to: gardenSolver,
            value: 0,
            data: abi.encodeWithSelector(
                IthacaAccount.authorize.selector,
                executorKey
            )
        });

        // Get current nonce and compute digest
        uint256 authNonce = solver.getNonce(0);
        bytes32 authDigest = solver.computeDigest(authCalls, authNonce);

        console.log("\n========================================");
        console.log("AUTHORIZATION - SIGNING INFORMATION");
        console.log("========================================");
        console.log("Digest to sign:", vm.toString(authDigest));
        console.log("Signer address:", signer);
        // console.log("Signer 2 address:", signer2);
        console.log("Signer KeyHash:", vm.toString(signerKeyHash));
        // console.log("Signer 2 KeyHash:", vm.toString(signer2KeyHash));
        console.log("Multisig KeyHash:", vm.toString(multisigKeyHash));
        console.log("========================================\n");

        bytes memory signerOneSig;
        {
            string memory authSigHex;
            bool authSignatureProvided;
            try vm.envString("SIGNATURE_AUTH") returns (
                string memory sigHexValue
            ) {
                authSigHex = sigHexValue;
                authSignatureProvided = bytes(authSigHex).length != 0;
            } catch {}

            if (authSignatureProvided) {
                // Parse the signature: format is 0x + 130 hex chars
                bytes memory sigBytes = vm.parseBytes(authSigHex);
                require(sigBytes.length == 65, "Signature must be 65 bytes");

                bytes32 r;
                bytes32 s;
                uint8 v;
                assembly {
                    r := mload(add(sigBytes, 0x20))
                    s := mload(add(sigBytes, 0x40))
                    v := byte(0, mload(add(sigBytes, 0x60)))
                }

                // Calculate the EIP-191 "Prefixed" Hash
                bytes32 ethSignedMessageHash = keccak256(
                    abi.encodePacked(
                        "\x19Ethereum Signed Message:\n32",
                        authDigest
                    )
                );

                // Recover the address using the PREFIXED hash
                address recoveredAddress = ecrecover(
                    ethSignedMessageHash,
                    v,
                    r,
                    s
                );
                address recoveredAddressAlt = address(0);

                // Handle EIP-2093 malleability (v=27 vs v=28)
                if (recoveredAddress != signer) {
                    uint8 vAlt = (v == 27) ? 28 : 27;
                    recoveredAddressAlt = ecrecover(
                        ethSignedMessageHash,
                        vAlt,
                        r,
                        s
                    );
                }

                bool isMatch = (recoveredAddress == signer) ||
                    (recoveredAddressAlt == signer);

                // Fix 'v' if the alternate was the correct one
                if (
                    recoveredAddressAlt == signer && recoveredAddress != signer
                ) {
                    v = (v == 27) ? 28 : 27;
                }

                require(
                    isMatch,
                    "Signature verification failed: Signer does not match (EIP-191 check)."
                );

                // Pack the signer signature: r + s + v + signerKeyHash + prehashFlag(0)
                signerOneSig = abi.encodePacked(
                    r,
                    s,
                    v,
                    signerKeyHash,
                    uint8(0)
                );
            }
        }

        if (signerOneSig.length == 0) {
            console.log("\n========================================");
            console.log("GET DIGEST TO SIGN (AUTHORIZATION)");
            console.log("========================================");
            console.log("Please sign the digest with your Ledger:");
            console.log("1. Copy the digest above.");
            console.log("2. Run this command (NO --raw flag):");
            console.log("");
            console.log(
                "   cast wallet sign --ledger",
                vm.toString(authDigest)
            );
            console.log("");
            console.log("3. Export the result:");
            console.log("   export SIGNATURE_AUTH=<result>");
            console.log("4. Run this script again with --broadcast");
            console.log("========================================\n");
            return;
        }

        // (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(
        //     signer2PrivateKey,
        //     authDigest
        // );
        // bytes memory signerTwoSig = abi.encodePacked(
        //     r2,
        //     s2,
        //     v2,
        //     signer2KeyHash,
        //     uint8(0)
        // );

        bytes[] memory innerSignatures = new bytes[](2);
        innerSignatures[0] = signerOneSig;
        // innerSignatures[1] = signerTwoSig;

        bytes memory authSignature = abi.encodePacked(
            abi.encode(innerSignatures),
            multisigKeyHash,
            uint8(0)
        );

        // Execute authorization
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        solver.execute(authCalls, abi.encodePacked(authNonce, authSignature));
        vm.stopBroadcast();

        console.log("\n[OK] Executor key authorized successfully!");
        console.log("Executor:", executorAddress);
        console.log("Executor KeyHash:", vm.toString(executorKeyHash));
        console.log("========================================\n");
    }
}
