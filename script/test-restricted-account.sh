#!/bin/bash

# Test Restricted Account on Base Sepolia
# This script helps you test the restricted account flow

set -e

RPC_URL="https://sepolia.base.org"
SCRIPT="script/TestRestrictedAccount.s.sol:TestRestrictedAccount"

echo "=========================================="
echo "Base Sepolia Restricted Account Test"
echo "=========================================="
echo ""

# Check if private key is set
if [ -z "$DEPLOYER_PRIVATE_KEY" ]; then
    echo "⚠️  DEPLOYER_PRIVATE_KEY not set, using default deterministic key"
    echo ""
fi

# Step 1: Simulate to see addresses
echo "Step 1: Checking addresses that need funding..."
echo "----------------------------------------"
forge script $SCRIPT --rpc-url $RPC_URL 2>&1 | grep -A 20 "REQUIRED: Fund These Addresses" || true
echo ""

# Ask user if they want to proceed
read -p "Have you funded the addresses? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Please fund the addresses first, then run this script again."
    exit 1
fi

# Step 2: Run the full test
echo ""
echo "Step 2: Running full test..."
echo "----------------------------------------"

if [ -z "$DEPLOYER_PRIVATE_KEY" ]; then
    forge script $SCRIPT \
        --rpc-url $RPC_URL \
        --broadcast \
        --slow
else
    forge script $SCRIPT \
        --rpc-url $RPC_URL \
        --broadcast \
        --slow \
        --private-key $DEPLOYER_PRIVATE_KEY
fi

echo ""
echo "=========================================="
echo "Test Complete!"
echo "=========================================="
echo ""
echo "Check the output above for:"
echo "  ✅ All contracts deployed"
echo "  ✅ Restricted key created and authorized"
echo "  ✅ Permissions set"
echo "  ✅ All tests passed"
echo ""
echo "View on Basescan: https://sepolia.basescan.org/"

