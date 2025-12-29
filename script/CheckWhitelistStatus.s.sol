// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";

interface IGardenSolver {
    function whitelistedAddresses(address) external view returns (bool);

    function whitelistingTimestamps(address) external view returns (uint256);

    function cooldownPeriod() external view returns (uint256);
}

contract CheckWhitelistStatus is Script {
    function run() external view {
        address solver = 0x18C03D26cC2462A8668d29c18DC2223b869b17b1;
        address recipient = 0x90Eb912279Ee8a3c56F784A44DeDFfAe4487524d;

        IGardenSolver gs = IGardenSolver(solver);

        bool isWhitelisted = gs.whitelistedAddresses(recipient);
        uint256 timestamp = gs.whitelistingTimestamps(recipient);
        uint256 cooldown = gs.cooldownPeriod();

        console.log("\n=== Whitelist Status ===");
        console.log("Recipient:", recipient);
        console.log("Is Whitelisted:", isWhitelisted);
        console.log("Whitelisting Timestamp:", timestamp);
        console.log("Cooldown Period (seconds):", cooldown);
        console.log("Cooldown Period (days):", cooldown / 1 days);
        console.log("Current Block Timestamp:", block.timestamp);

        if (isWhitelisted) {
            uint256 unlockTime = timestamp + cooldown;
            bool canWithdraw = block.timestamp >= unlockTime;
            console.log("\n=== Withdrawal Eligibility ===");
            console.log("Unlock Timestamp:", unlockTime);
            console.log("Can Withdraw Now:", canWithdraw);
            if (!canWithdraw) {
                uint256 remaining = unlockTime - block.timestamp;
                console.log("Time Remaining (seconds):", remaining);
                console.log("Time Remaining (hours):", remaining / 1 hours);
            }
        } else {
            console.log("\n!!! RECIPIENT IS NOT WHITELISTED !!!");
            console.log(
                "You need to whitelist this address first using whitelistAddress()"
            );
        }
    }
}
