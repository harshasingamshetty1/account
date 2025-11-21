// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IthacaAccount} from "./IthacaAccount.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
// import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {TokenTransferLib} from "./libraries/TokenTransferLib.sol";

contract GardenSolver is IthacaAccount, Pausable {
    mapping(address => bool) public whitelistedAddresses;
    mapping(address => uint256) public whitelistingTimestamps;
    uint256 public cooldownPeriod;

    error GardenSolver__TargetNotWhitelisted();
    error GardenSolver__ExecuteCallFailed();
    error GardenSolver__AlreadyWhitelisted();
    error GardenSolver__NotWhitelisted();
    error GardenSolver__ZeroValue();

    event CooldownPeriodUpdated(uint256 indexed newCooldownPeriod);

    constructor(
        address orchestrator,
        Key[] memory initialKeys,
        address multiSigSigner,
        uint256 threshold
    ) payable IthacaAccount(orchestrator) {
        cooldownPeriod = 1 days;

        // 1. Authorize individual keys
        bytes32[] memory keyHashes = new bytes32[](initialKeys.length);
        for (uint256 i = 0; i < initialKeys.length; i++) {
            // Prevent individual keys from being super admin if we're setting up multisig
            if (multiSigSigner != address(0) && initialKeys[i].isSuperAdmin) {
                revert KeyTypeCannotBeSuperAdmin();
            }
            keyHashes[i] = _addKey(initialKeys[i]);
            emit Authorized(keyHashes[i], initialKeys[i]);
        }

        // 2. Setup multisig if address provided
        if (multiSigSigner != address(0)) {
            // Create and authorize multisig super admin key
            Key memory multisigKey = Key({
                expiry: 0,
                keyType: KeyType.External,
                isSuperAdmin: true,
                publicKey: abi.encodePacked(multiSigSigner, bytes12(0))
            });
            bytes32 multisigKeyHash = _addKey(multisigKey);
            emit Authorized(multisigKeyHash, multisigKey);

            // Initialize multisig config
            // Note: msg.sender in MultiSigSigner.initConfig will be address(this)
            // Config is stored under _configs[address(this)][multisigKeyHash]
            (bool success,) = multiSigSigner.call(
                abi.encodeWithSignature(
                    "initConfig(bytes32,uint256,bytes32[])", multisigKeyHash, threshold, keyHashes
                )
            );
            require(success, "Multisig init failed");
        }
    }

    function changeCooldownPeriod(uint256 newCooldownPeriod) external onlyThis whenNotPaused {
        require(newCooldownPeriod != 0, GardenSolver__ZeroValue());
        cooldownPeriod = newCooldownPeriod;
        emit CooldownPeriodUpdated(newCooldownPeriod);
    }

    function whitelistAddress(address addr) external onlyThis whenNotPaused {
        require(addr != address(0), GardenSolver__ZeroValue());
        require(!whitelistedAddresses[addr], GardenSolver__AlreadyWhitelisted());
        whitelistedAddresses[addr] = true;
        whitelistingTimestamps[addr] = block.timestamp;
    }

    function removeWhitelistedAddress(address addr) external onlyThis whenNotPaused {
        require(whitelistedAddresses[addr], GardenSolver__NotWhitelisted());
        whitelistedAddresses[addr] = false;
        whitelistingTimestamps[addr] = 0;
    }

    function execute(bytes32, bytes calldata) public payable virtual override {}

    function execute(Call[] calldata calls, bytes calldata opData) external whenNotPaused {
        _execute(bytes32(0), opData, calls, opData); // @note the first two values are placeholders
    }

    function withdraw(address recipient, address token, uint256 amount) external onlyThis {
        if (
            !whitelistedAddresses[recipient]
                || block.timestamp < whitelistingTimestamps[recipient] + cooldownPeriod
        ) {
            revert GardenSolver__TargetNotWhitelisted();
        }

        TokenTransferLib.safeTransfer(token, recipient, amount);

        bytes32 keyHash = getContextKeyHash();
        
        if (!(keyHash == bytes32(0) || _isSuperAdmin(keyHash))) {
            SpendStorage storage spends = _getGuardedExecutorKeyStorage(keyHash).spends;
            _incrementSpent(spends.spends[token], token, amount);
        }
    }

    function pause() external onlyThis whenNotPaused {
        _pause();
    }

    function unpause() external onlyThis whenPaused {
        _unpause();
    }
}