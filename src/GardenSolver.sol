// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IthacaAccount} from "./IthacaAccount.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract GardenSolver is IthacaAccount, Pausable {
    using LibBytes for *;

    mapping(address => bool) public whitelistedAddresses;
    mapping(address => uint256) public whitelistingTimestamps;
    uint256 public cooldownPeriod;

    error GardenAccount__TargetNotWhitelisted();
    error GardenAccount__ExecuteCallFailed();
    error GardenAccount__AlreadyWhitelisted();
    error GardenAccount__NotWhitelisted();
    error GardenAccount__ZeroValue();

    event CooldownPeriodUpdated(uint256 indexed newCooldownPeriod);

    // @note add cooldown period
    constructor(
        address orchestrator,
        Key[] memory initialKeys,
        address multiSigSigner,
        uint256 threshold
    ) payable IthacaAccount(orchestrator, initialKeys, multiSigSigner, threshold) {
        cooldownPeriod = 1 days;
    }

    function changeCooldownPeriod(uint256 newCooldownPeriod) external onlyThis whenNotPaused {
        require(newCooldownPeriod != 0, GardenAccount__ZeroValue());
        cooldownPeriod = newCooldownPeriod;
        emit CooldownPeriodUpdated(newCooldownPeriod);
    }

    function whitelistAddress(address addr) external onlyThis whenNotPaused {
        require(addr != address(0), GardenAccount__ZeroValue());
        require(!whitelistedAddresses[addr], GardenAccount__AlreadyWhitelisted());
        whitelistedAddresses[addr] = true;
        whitelistingTimestamps[addr] = block.timestamp;
    }

    function removeWhitelistedAddress(address addr) external onlyThis whenNotPaused {
        require(whitelistedAddresses[addr], GardenAccount__NotWhitelisted());
        whitelistedAddresses[addr] = false;
        whitelistingTimestamps[addr] = 0;
    }

    function execute(bytes32, bytes calldata) public payable virtual override {}

    function execute(Call[] calldata calls, bytes calldata opData) external whenNotPaused {
        _execute(bytes32(0), opData, calls, opData); // @note the first two values are placeholders, dead values that are not used in _execute
    }

    function withdraw(address recipient, address token, uint256 amount) external onlyThis {
        if (
            !whitelistedAddresses[recipient]
                || block.timestamp < whitelistingTimestamps[recipient] + cooldownPeriod
        ) {
            revert GardenAccount__TargetNotWhitelisted();
        }

        if (token == address(0)) {
            (bool success,) = recipient.call{value: amount}("");
            if (!success) {
                revert GardenAccount__ExecuteCallFailed();
            }
            return;
        } else {
            IERC20(token).transfer(recipient, amount);
        }
    }

    function pause() external onlyThis whenNotPaused {
        _pause();
    }

    function unpause() external onlyThis whenPaused {
        _unpause();
    }
}
