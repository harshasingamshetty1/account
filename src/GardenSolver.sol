// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IthacaAccount} from "./IthacaAccount.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

contract GardenSolver is IthacaAccount, Pausable {
    error GardenSolver__ExecuteCallFailed();
    error GardenSolver__ZeroValue();
    error GardenSolver__IncorrectFunctionSelector(bytes4 expected);

    constructor(
        address orchestrator,
        Key[] memory initialKeys,
        address multiSigSigner,
        uint256 threshold
    ) payable IthacaAccount(orchestrator) {
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

    function execute(bytes32, bytes calldata) public payable virtual override {
        revert GardenSolver__IncorrectFunctionSelector(0x6171d1c9);
    }

    function execute(Call[] calldata calls, bytes calldata opData) external whenNotPaused {
        _execute(bytes32(0), opData, calls, opData); // @note the first two values are placeholders
    }

    function pause() external onlyThis whenNotPaused {
        _pause();
    }

    function unpause() external onlyThis whenPaused {
        _unpause();
    }
}
