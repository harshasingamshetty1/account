// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import {MultiSigSigner} from "../../src/MultiSigSigner.sol";
import {GardenSolver} from "../../src/GardenSolver.sol";
import {IthacaAccount} from "../../src/IthacaAccount.sol";

contract TestShit is Script {
    function run() public {
        vm.startBroadcast();
        console.log("msg.sender:", msg.sender);
        console.log("tx.origin:", tx.origin);
        Damn damn = new Damn(msg.sender);
        console.log("x:", address(damn.x()));
        vm.stopBroadcast();
    }
}

contract Damn {
    address public x;

    constructor(address _x) {
        x = _x;
    }
}
