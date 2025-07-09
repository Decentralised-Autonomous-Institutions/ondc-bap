#!/bin/bash

# ONDC Challenge Testing Script
# This script demonstrates how to generate and test ONDC challenges with a BAP server

set -e  # Exit on any error

echo "=== ONDC Challenge Testing Script ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    print_error "jq is required but not installed. Please install jq first."
    exit 1
fi

# Configuration
BAP_SERVER_URL="http://localhost:8080"
SUBSCRIBER_ID="test.example.com"
ENVIRONMENT="staging"
TEST_DATA="ONDC Challenge Test $(date +%s)"

print_status "Configuration:"
echo "  BAP Server URL: $BAP_SERVER_URL"
echo "  Subscriber ID: $SUBSCRIBER_ID"
echo "  Environment: $ENVIRONMENT"
echo "  Test Data: $TEST_DATA"
echo

# Step 1: Generate X25519 key pair
print_status "Step 1: Generating X25519 key pair..."
cargo run --package ondc-crypto-cli -- generate x25519 --json > x25519.keys.json
X25519_PRIVATE_KEY=$(jq -r .private_key x25519.keys.json)
X25519_PUBLIC_KEY=$(jq -r .public_key x25519.keys.json)
print_success "X25519 key pair generated"
echo "  Private Key: ${X25519_PRIVATE_KEY:0:20}..."
echo "  Public Key:  ${X25519_PUBLIC_KEY:0:20}..."
echo

# Step 2: Generate test challenge
print_status "Step 2: Generating test challenge..."
cargo run --package ondc-crypto-cli -- challenge \
  --private-key "$X25519_PRIVATE_KEY" \
  --data "$TEST_DATA" \
  --environment "$ENVIRONMENT" \
  --json > challenge.json

CHALLENGE_B64=$(jq -r .encrypted_challenge challenge.json)
ORIGINAL_DATA=$(jq -r .original_data challenge.json)
print_success "Challenge generated"
echo "  Encrypted Challenge: ${CHALLENGE_B64:0:20}..."
echo "  Original Data: $ORIGINAL_DATA"
echo

# Step 3: Test BAP server health
print_status "Step 3: Checking BAP server health..."
if curl -s "$BAP_SERVER_URL/health" > /dev/null; then
    print_success "BAP server is running"
else
    print_warning "BAP server is not responding at $BAP_SERVER_URL"
    print_warning "Make sure the BAP server is running with:"
    echo "  cd ../ondc-bap"
    echo "  ONDC_ENV=staging cargo run"
    echo
    print_warning "Continuing with challenge generation only..."
    echo
fi

# Step 4: Test on_subscribe endpoint
print_status "Step 4: Testing /on_subscribe endpoint..."

# Prepare the JSON payload
JSON_PAYLOAD=$(cat <<EOF
{
  "subscriber_id": "$SUBSCRIBER_ID",
  "challenge": "$CHALLENGE_B64"
}
EOF
)

# Test the endpoint
if curl -s -X POST "$BAP_SERVER_URL/on_subscribe" \
  -H "Content-Type: application/json" \
  -d "$JSON_PAYLOAD" > response.json; then
    
    print_success "Request sent successfully"
    
    # Check if response contains expected data
    if jq -e '.answer' response.json > /dev/null 2>&1; then
        ANSWER=$(jq -r '.answer' response.json)
        print_success "Challenge decrypted successfully!"
        echo "  Expected: $ORIGINAL_DATA"
        echo "  Received: $ANSWER"
        
        if [ "$ANSWER" = "$ORIGINAL_DATA" ]; then
            print_success "✅ Challenge/response match perfectly!"
        else
            print_error "❌ Challenge/response mismatch!"
            echo "  Expected: $ORIGINAL_DATA"
            echo "  Received: $ANSWER"
        fi
    else
        print_error "❌ Invalid response format"
        echo "Response:"
        cat response.json
    fi
else
    print_error "❌ Failed to connect to BAP server"
    print_warning "Make sure the BAP server is running and accessible"
fi

echo

# Step 5: Generate curl command for manual testing
print_status "Step 5: Manual testing command..."
echo "You can manually test the challenge using this curl command:"
echo
echo "curl -X POST $BAP_SERVER_URL/on_subscribe \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{"
echo "    \"subscriber_id\": \"$SUBSCRIBER_ID\","
echo "    \"challenge\": \"$CHALLENGE_B64\""
echo "  }'"
echo

# Step 6: Cleanup
print_status "Step 6: Cleaning up temporary files..."
rm -f x25519.keys.json challenge.json response.json
print_success "Temporary files cleaned up"

echo
print_success "=== Challenge Testing Complete ==="
echo
print_status "Summary:"
echo "  ✅ X25519 key pair generated"
echo "  ✅ Challenge encrypted with ONDC public key"
echo "  ✅ Challenge ready for BAP server testing"
echo
print_status "Next steps:"
echo "  1. Start your BAP server with the same X25519 private key"
echo "  2. Use the generated challenge to test the /on_subscribe endpoint"
echo "  3. Verify that the server can decrypt and return the original data" 