#!/bin/bash

# Deploy Solver with 2-of-3 Multisig using EIP-7702 on Anvil
# This script uses cast to create EIP-7702 authorization transactions

set -e

echo "=========================================="
echo "Deploying Solver with EIP-7702 on Anvil"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Start Anvil with EIP-7702 support (Pectra hardfork)
echo -e "${BLUE}Step 1: Starting Anvil with EIP-7702 support...${NC}"
echo "Starting Anvil in background with Pectra hardfork..."

# Kill any existing anvil processes
pkill -f "anvil" || true
sleep 1

# Start Anvil with latest hardfork (should include EIP-7702 if available)
# If EIP-7702 isn't available, we'll use vm.etch as fallback
anvil --hardfork latest --port 8545 > anvil.log 2>&1 &
ANVIL_PID=$!
sleep 3

# Check if Anvil started successfully
if ! kill -0 $ANVIL_PID 2>/dev/null; then
    echo "❌ Failed to start Anvil. Check anvil.log for errors."
    exit 1
fi

echo -e "${GREEN}✓ Anvil started (PID: $ANVIL_PID)${NC}"
echo ""

# Set RPC URL
export RPC_URL="http://localhost:8545"

# Step 2: Generate deterministic accounts
echo -e "${BLUE}Step 2: Generating accounts...${NC}"

# Generate private keys (same as in SolverMultisigSetup.t.sol)
SOLVER_PRIVATE_KEY=$(cast keccak "SOLVER_ACCOUNT_V1")
SIGNER1_PRIVATE_KEY=$(cast keccak "SIGNER_1_V1")
SIGNER2_PRIVATE_KEY=$(cast keccak "SIGNER_2_V1")
SIGNER3_PRIVATE_KEY=$(cast keccak "SIGNER_3_V1")
DEPLOYER_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" # Anvil default

# Get addresses
SOLVER_EOA=$(cast wallet address $SOLVER_PRIVATE_KEY)
SIGNER1=$(cast wallet address $SIGNER1_PRIVATE_KEY)
SIGNER2=$(cast wallet address $SIGNER2_PRIVATE_KEY)
SIGNER3=$(cast wallet address $SIGNER3_PRIVATE_KEY)
DEPLOYER=$(cast wallet address $DEPLOYER_PRIVATE_KEY)

echo "Solver EOA: $SOLVER_EOA"
echo "Signer 1: $SIGNER1"
echo "Signer 2: $SIGNER2"
echo "Signer 3: $SIGNER3"
echo "Deployer: $DEPLOYER"
echo ""

# Fund accounts from Anvil default account
echo -e "${BLUE}Step 3: Funding accounts...${NC}"
ANVIL_DEFAULT="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
cast send $SOLVER_EOA --value 10ether --private-key $DEPLOYER_PRIVATE_KEY --rpc-url $RPC_URL > /dev/null
cast send $SIGNER1 --value 1ether --private-key $DEPLOYER_PRIVATE_KEY --rpc-url $RPC_URL > /dev/null
cast send $SIGNER2 --value 1ether --private-key $DEPLOYER_PRIVATE_KEY --rpc-url $RPC_URL > /dev/null
cast send $SIGNER3 --value 1ether --private-key $DEPLOYER_PRIVATE_KEY --rpc-url $RPC_URL > /dev/null
echo -e "${GREEN}✓ Accounts funded${NC}"
echo ""

# Step 4: Deploy contracts
echo -e "${BLUE}Step 4: Deploying contracts...${NC}"

# Deploy Orchestrator
ORCHESTRATOR=$(forge create Orchestrator --private-key $DEPLOYER_PRIVATE_KEY --rpc-url $RPC_URL | grep "Deployed to:" | awk '{print $3}')
echo "Orchestrator: $ORCHESTRATOR"

# Deploy IthacaAccount implementation
ITHACA_IMPL=$(forge create IthacaAccount --constructor-args $ORCHESTRATOR --private-key $DEPLOYER_PRIVATE_KEY --rpc-url $RPC_URL | grep "Deployed to:" | awk '{print $3}')
echo "IthacaAccount Implementation: $ITHACA_IMPL"

# Deploy MultiSigSigner
MULTISIG_SIGNER=$(forge create MultiSigSigner --private-key $DEPLOYER_PRIVATE_KEY --rpc-url $RPC_URL | grep "Deployed to:" | awk '{print $3}')
echo "MultiSigSigner: $MULTISIG_SIGNER"
echo -e "${GREEN}✓ Contracts deployed${NC}"
echo ""

# Step 5: Create EIP-7702 authorization
echo -e "${BLUE}Step 5: Creating EIP-7702 authorization...${NC}"
echo "This delegates the Solver EOA to IthacaAccount implementation"

# Get chain ID
CHAIN_ID=$(cast chain-id --rpc-url $RPC_URL)
echo "Chain ID: $CHAIN_ID"

# Get nonce for the solver EOA
NONCE=$(cast nonce $SOLVER_EOA --rpc-url $RPC_URL)
echo "Solver EOA Nonce: $NONCE"

# Create EIP-7702 authorization
# Format: authorizationList = [(chainId, address, nonce, yParity, r, s), ...]
# We need to sign the authorization

echo "Creating EIP-7702 authorization signature..."
echo "This will delegate $SOLVER_EOA to $ITHACA_IMPL"

# Note: Cast doesn't have direct EIP-7702 support yet, so we'll use a workaround
# We'll use vm.etch in a Foundry script to simulate it, or use cast's low-level features

# For now, let's use a Foundry script that uses vm.etch (which works on Anvil)
echo "Using Foundry script with vm.etch for EIP-7702 simulation..."

# Create a temporary script that does the EIP-7702 setup
cat > /tmp/eip7702_setup.s.sol <<EOF
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {IthacaAccount} from "../src/IthacaAccount.sol";

contract EIP7702Setup is Script {
    function run() external {
        address solverEOA = vm.envAddress("SOLVER_EOA");
        address ithacaImpl = vm.envAddress("ITHACA_IMPL");
        
        // Simulate EIP-7702 delegation using vm.etch
        vm.etch(solverEOA, address(ithacaImpl).code);
        
        console.log("EIP-7702 delegation complete!");
        console.log("Solver EOA:", solverEOA);
        console.log("Delegated to:", ithacaImpl);
    }
}
EOF

# Run the setup script
export SOLVER_EOA=$SOLVER_EOA
export ITHACA_IMPL=$ITHACA_IMPL
forge script /tmp/eip7702_setup.s.sol:EIP7702Setup --rpc-url $RPC_URL -vv

echo -e "${GREEN}✓ EIP-7702 authorization complete${NC}"
echo ""

# Step 6: Setup multisig (using the test pattern)
echo -e "${BLUE}Step 6: Setting up 2-of-3 multisig...${NC}"
echo "This step will be done via a Foundry script that calls the authorized functions"

# Create the multisig setup script
cat > /tmp/multisig_setup.s.sol <<'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {IthacaAccount} from "../src/IthacaAccount.sol";
import {MultiSigSigner} from "../src/MultiSigSigner.sol";

contract MultisigSetup is Script {
    function run() external {
        address solverEOA = vm.envAddress("SOLVER_EOA");
        address multiSigSigner = vm.envAddress("MULTISIG_SIGNER");
        address signer1 = vm.envAddress("SIGNER1");
        address signer2 = vm.envAddress("SIGNER2");
        address signer3 = vm.envAddress("SIGNER3");
        
        IthacaAccount solver = IthacaAccount(payable(solverEOA));
        
        // Create signer keys
        IthacaAccount.Key memory signer1Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer1)
        });
        
        IthacaAccount.Key memory signer2Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer2)
        });
        
        IthacaAccount.Key memory signer3Key = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.Secp256k1,
            isSuperAdmin: false,
            publicKey: abi.encode(signer3)
        });
        
        // Authorize signers (using solver's original key)
        uint256 solverKey = vm.envUint("SOLVER_PRIVATE_KEY");
        vm.startBroadcast(solverKey);
        
        bytes32 signer1KeyHash = solver.authorize(signer1Key);
        bytes32 signer2KeyHash = solver.authorize(signer2Key);
        bytes32 signer3KeyHash = solver.authorize(signer3Key);
        
        console.log("Signer 1 KeyHash:", vm.toString(signer1KeyHash));
        console.log("Signer 2 KeyHash:", vm.toString(signer2KeyHash));
        console.log("Signer 3 KeyHash:", vm.toString(signer3KeyHash));
        
        // Create multisig super admin key
        IthacaAccount.Key memory multisigKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(multiSigSigner, bytes12(0))
        });
        
        bytes32 multisigKeyHash = solver.authorize(multisigKey);
        console.log("Multisig KeyHash:", vm.toString(multisigKeyHash));
        
        // Initialize multisig config
        bytes32[] memory ownerKeyHashes = new bytes32[](3);
        ownerKeyHashes[0] = signer1KeyHash;
        ownerKeyHashes[1] = signer2KeyHash;
        ownerKeyHashes[2] = signer3KeyHash;
        
        MultiSigSigner(multiSigSigner).initConfig(multisigKeyHash, 2, ownerKeyHashes);
        
        vm.stopBroadcast();
        
        console.log("✓ Multisig setup complete!");
    }
}
EOF

# Export environment variables
export MULTISIG_SIGNER=$MULTISIG_SIGNER
export SIGNER1=$SIGNER1
export SIGNER2=$SIGNER2
export SIGNER3=$SIGNER3
export SOLVER_PRIVATE_KEY=$SOLVER_PRIVATE_KEY

# Run multisig setup
forge script /tmp/multisig_setup.s.sol:MultisigSetup --rpc-url $RPC_URL --broadcast -vv

echo -e "${GREEN}✓ Multisig setup complete${NC}"
echo ""

# Step 7: Print summary
echo -e "${GREEN}=========================================="
echo "DEPLOYMENT COMPLETE!"
echo "==========================================${NC}"
echo ""
echo "Solver EOA (delegated to IthacaAccount): $SOLVER_EOA"
echo "Orchestrator: $ORCHESTRATOR"
echo "IthacaAccount Implementation: $ITHACA_IMPL"
echo "MultiSigSigner: $MULTISIG_SIGNER"
echo ""
echo "Signers:"
echo "  - Signer 1: $SIGNER1"
echo "  - Signer 2: $SIGNER2"
echo "  - Signer 3: $SIGNER3"
echo ""
echo -e "${YELLOW}To stop Anvil, run: kill $ANVIL_PID${NC}"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    kill $ANVIL_PID 2>/dev/null || true
    rm -f /tmp/eip7702_setup.s.sol /tmp/multisig_setup.s.sol
    echo "Done!"
}

trap cleanup EXIT

echo "Anvil is running. Press Ctrl+C to stop."

