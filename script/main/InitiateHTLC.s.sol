// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";

/// @title InitiateHTLC
/// @notice Production script to initiate an HTLC order via signer1
/// @dev Usage:
///      forge script script/InitiateHTLC.s.sol --rpc-url $RPC_URL --broadcast
///
///      Required environment variables:
///      - GARDEN_SOLVER: Address of GardenSolver contract
///      - HTLC_ADDRESS: Address of HTLC contract
///      - REDEEMER_ADDRESS: Address that can redeem the HTLC
///      - TIMELOCK: Block number timelock for the HTLC
///      - AMOUNT: Amount of tokens to lock (in raw units, account for decimals)
///      - SECRET_HASH: bytes32 hash of the secret (keccak256 of secret)
///      - SIGNER_PRIVATE_KEY: Private key of signer 1
contract InitiateHTLC is Script {
    function run() public {
        // Load configuration from environment variables
        address gardenSolver = vm.envAddress("GARDEN_SOLVER");
        address htlc = vm.envAddress("HTLC_ADDRESS");
        address redeemer = vm.envAddress("REDEEMER_ADDRESS");
        uint256 timelock = vm.envUint("TIMELOCK");
        uint256 amount = vm.envUint("AMOUNT");
        bytes32 secretHash = vm.envBytes32("SECRET_HASH");
        uint256 oneSignerPrivateKey = vm.envUint("SIGNER_PRIVATE_KEY");

        address signer1 = vm.addr(oneSignerPrivateKey);

        console.log("\n========================================");
        console.log("Initiate HTLC Order");
        console.log("========================================");
        console.log("GardenSolver:", gardenSolver);
        console.log("HTLC:", htlc);
        console.log("Redeemer:", redeemer);
        console.log("Timelock:", timelock);
        console.log("Amount:", amount);
        console.log("Secret Hash:", vm.toString(secretHash));
        console.log("Signer 1:", signer1);
        console.log("========================================\n");

        GardenSolver solver = GardenSolver(payable(gardenSolver));

        // Compute signer1 key hash
        IthacaAccount.Key memory signer1Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer1)
        });
        bytes32 signer1KeyHash = solver.hash(signer1Key);

        // Create the initiate call
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: htlc,
            value: 0,
            data: abi.encodeWithSignature(
                "initiate(address,uint256,uint256,bytes32)",
                redeemer,
                timelock,
                amount,
                secretHash
            )
        });

        // Get nonce and compute digest
        uint256 nonce = solver.getNonce(0);
        bytes32 digest = solver.computeDigest(calls, nonce);

        // Sign with signer1
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oneSignerPrivateKey, digest);
        bytes memory signature = abi.encodePacked(
            r,
            s,
            v,
            signer1KeyHash,
            uint8(0)
        );

        // Execute
        vm.startBroadcast(oneSignerPrivateKey);
        solver.execute(calls, abi.encodePacked(nonce, signature));
        vm.stopBroadcast();

        // Compute order ID (same as HTLC contract does)
        bytes32 orderID = keccak256(
            abi.encode(
                block.chainid,
                secretHash,
                gardenSolver, // initiator
                redeemer,
                timelock,
                amount,
                htlc
            )
        );

        console.log("\nHTLC order initiated successfully!");
        console.log("Order ID:", vm.toString(orderID));
        console.log("Secret Hash:", vm.toString(secretHash));
        console.log("Amount:", amount);
        console.log("Redeemer:", redeemer);
        console.log("Timelock:", timelock);
        console.log("========================================\n");
    }
}
