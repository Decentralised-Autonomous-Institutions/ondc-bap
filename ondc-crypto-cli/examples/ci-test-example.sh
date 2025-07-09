#!/bin/bash

# CI/CD Example: Automated ONDC Challenge Testing
# This script demonstrates how to integrate challenge testing into CI/CD pipelines

set -e

echo "=== CI/CD Challenge Testing Example ==="
echo

# Configuration (in CI, these would be environment variables)
X25519_PRIVATE_KEY="${X25519_PRIVATE_KEY:-}"
BAP_SERVER_URL="${BAP_SERVER_URL:-http://localhost:8080}"
SUBSCRIBER_ID="${SUBSCRIBER_ID:-test.example.com}"
ENVIRONMENT="${ENVIRONMENT:-staging}"

# Validate required environment variables
if [ -z "$X25519_PRIVATE_KEY" ]; then
    echo "❌ X25519_PRIVATE_KEY environment variable is required"
    echo "   Set it in your CI/CD environment or export it locally"
    exit 1
fi

echo "Configuration:"
echo "  BAP Server: $BAP_SERVER_URL"
echo "  Subscriber ID: $SUBSCRIBER_ID"
echo "  Environment: $ENVIRONMENT"
echo "  Private Key: ${X25519_PRIVATE_KEY:0:20}..."
echo

# Generate unique test data
TEST_DATA="CI-Test-$(date +%s)-$(openssl rand -hex 8)"

echo "🔧 Step 1: Generating test challenge..."
cargo run --package ondc-crypto-cli -- challenge \
  --private-key "$X25519_PRIVATE_KEY" \
  --data "$TEST_DATA" \
  --environment "$ENVIRONMENT" \
  --json > challenge.json

CHALLENGE_B64=$(jq -r .encrypted_challenge challenge.json)
echo "✅ Challenge generated: ${CHALLENGE_B64:0:20}..."

echo
echo "🔧 Step 2: Testing BAP server endpoint..."

# Prepare test payload
JSON_PAYLOAD=$(cat <<EOF
{
  "subscriber_id": "$SUBSCRIBER_ID",
  "challenge": "$CHALLENGE_B64"
}
EOF
)

# Test the endpoint with timeout
if timeout 30s curl -s -X POST "$BAP_SERVER_URL/on_subscribe" \
  -H "Content-Type: application/json" \
  -d "$JSON_PAYLOAD" > response.json; then
    
    echo "✅ Request completed successfully"
    
    # Validate response
    if jq -e '.answer' response.json > /dev/null 2>&1; then
        ANSWER=$(jq -r '.answer' response.json)
        
        if [ "$ANSWER" = "$TEST_DATA" ]; then
            echo "✅ Challenge/response validation PASSED"
            echo "   Expected: $TEST_DATA"
            echo "   Received: $ANSWER"
            exit 0
        else
            echo "❌ Challenge/response validation FAILED"
            echo "   Expected: $TEST_DATA"
            echo "   Received: $ANSWER"
            exit 1
        fi
    else
        echo "❌ Invalid response format"
        echo "Response:"
        cat response.json
        exit 1
    fi
else
    echo "❌ BAP server test FAILED"
    echo "   Server not responding or timeout reached"
    exit 1
fi 