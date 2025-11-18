// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface ArbSys {
    function arbBlockNumber() external view returns (uint256);
}

interface ArbHTLC {

    // IERC20 public token;
    // uint256 public isInitialized;

    // mapping(bytes32 => Order) external orders;

    function initialise(address _token) external;

    function initiate(address redeemer, uint256 timelock, uint256 amount, bytes32 secretHash)
        external;

    function initiate(
        address redeemer,
        uint256 timelock,
        uint256 amount,
        bytes32 secretHash,
        bytes calldata destinationData
    ) external;

    function initiateOnBehalf(address initiator, address redeemer, uint256 timelock, uint256 amount, bytes32 secretHash)
        external;

    function initiateOnBehalf(
        address initiator,
        address redeemer,
        uint256 timelock,
        uint256 amount,
        bytes32 secretHash,
        bytes calldata destinationData
    ) external;

    function initiateWithSignature(
        address initiator,
        address redeemer,
        uint256 timelock,
        uint256 amount,
        bytes32 secretHash,
        bytes calldata signature
    ) external;

    function redeem(bytes32 orderID, bytes calldata secret) external;
    function refund(bytes32 orderID) external;

    function instantRefund(bytes32 orderID, bytes calldata signature) external;

    function instantRefundDigest(bytes32 orderID) external view returns (bytes32);
}
