// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IthacaAccount} from "./IthacaAccount.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";

contract GardenAccount is IthacaAccount, Pausable {
    mapping(address => bool) public whitelistedAddresses;
    mapping(address => uint256) public whitelistingTimestamps;

    error GardenAccount__TargetNotWhitelisted();

    constructor(address orchestrator, Key memory key) IthacaAccount(orchestrator, key) {}

    function whitelistAddress(address addr) external onlyThis whenNotPaused {
        whitelistedAddresses[addr] = true;
        whitelistingTimestamps[addr] = block.timestamp;
    }

    function removeWhitelistedAddress(address addr) external onlyThis whenNotPaused {
        whitelistedAddresses[addr] = false;
        whitelistingTimestamps[addr] = 0;
    }

    function execute(bytes32, bytes calldata) public payable virtual override {}

    function execute(Call[] calldata calls, bytes calldata opData) external whenNotPaused {
        Call[] memory filteredCalls = new Call[](calls.length);
        uint256 count = 0;

        for(uint256 i = 0; i < calls.length; i++) {
            (address target, uint256 value, bytes calldata data) = _get(calls, i);
            uint32 fnSel = uint32(bytes4(LibBytes.loadCalldata(data, 0x00)));
            if(fnSel == 0xa9059cbb) { 
                address to = LibBytes.loadCalldata(data, 0x04).lsbToAddress();
                if(whitelistedAddresses[to] || whitelistingTimestamps[to] >= block.timestamp - 1 days) {
                    continue;
                }
            }
            if(fnSel == 0x23b872dd) { 
                address to = LibBytes.loadCalldata(data, 0x24).lsbToAddress();
                if(whitelistedAddresses[to] || whitelistingTimestamps[to] >= block.timestamp - 1 days) {
                    continue;
                }
            }
            if(
                (whitelistedAddresses[target] || whitelistingTimestamps[target] >= block.timestamp - 1 days) && value != 0
            ) {
                continue;
            }
            filteredCalls[count] = calls[i];
            count++;
        }

        Call[] memory finalCalls = new Call[](count);
        for(uint256 j = 0; j < count; j++) {
            finalCalls[j] = filteredCalls[j];
        }

        address(this).call(
            abi.encodeWithSelector(this.executeCall.selector, finalCalls, opData)
        );
    }

    function executeCall(Call[] calldata calls, bytes calldata opData) external onlyThis {
        _execute(bytes32(0), opData, calls, opData); // @note the first two values are placeholders, dead values that are not used in _execute
    }
}