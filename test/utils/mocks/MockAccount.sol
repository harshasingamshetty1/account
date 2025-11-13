// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {GardenAccount} from "../../../src/GardenAccount.sol";
import {Brutalizer} from "../Brutalizer.sol";

import {LibTStack} from "../../../src/libraries/LibTStack.sol";

/// @dev WARNING! This mock is strictly intended for testing purposes only.
/// Do NOT copy anything here into production code unless you really know what you are doing.
contract MockAccount is GardenAccount, Brutalizer {
    using LibTStack for LibTStack.TStack;

    uint256 public x;

    constructor(address orchestrator, Key memory key) payable GardenAccount(orchestrator, key) {}

    function setX(uint256 newX) public onlyThis {
        x = newX;
    }

    function resetX() public {
        x = 0;
    }

    function setContextKeyHash(bytes32 keyHash) public {
        LibTStack.TStack(_KEYHASH_STACK_TRANSIENT_SLOT).push(keyHash);
    }
}
