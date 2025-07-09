#!/bin/bash

echo "=== ONDC Crypto CLI Demo ==="
echo

# Generate Ed25519 keys
echo "1. Generating Ed25519 key pair..."
cargo run --package ondc-crypto-cli -- generate ed25519 --json > ed25519.keys.json
echo "Keys saved to ed25519.keys.json"
echo

# Generate X25519 keys
echo "2. Generating X25519 key pair..."
cargo run --package ondc-crypto-cli -- generate x25519 --json > x25519.keys.json
echo "Keys saved to x25519.keys.json"
echo

# Extract keys for signing
PRIVATE_KEY=$(jq -r .private_key ed25519.keys.json)
PUBLIC_KEY=$(jq -r .public_key ed25519.keys.json)

echo "3. Signing a message..."
MESSAGE="Hello, ONDC World!"
echo "Message: $MESSAGE"
SIGNATURE=$(cargo run --package ondc-crypto-cli -- sign --private-key "$PRIVATE_KEY" --data "$MESSAGE")
echo "Signature: $SIGNATURE"
echo

echo "4. Verifying the signature..."
cargo run --package ondc-crypto-cli -- verify --public-key "$PUBLIC_KEY" --signature "$SIGNATURE" --data "$MESSAGE"
echo

echo "5. Testing invalid signature..."
MODIFIED_MESSAGE="Hello, ONDC World! (modified)"
echo "Modified message: $MODIFIED_MESSAGE"
cargo run --package ondc-crypto-cli -- verify --public-key "$PUBLIC_KEY" --signature "$SIGNATURE" --data "$MODIFIED_MESSAGE" || echo "Expected failure for modified message"
echo

echo "6. Different output formats..."
echo "Base64 format:"
cargo run --package ondc-crypto-cli -- generate ed25519 --format base64 | head -2
echo

echo "Hex format:"
cargo run --package ondc-crypto-cli -- generate ed25519 --format hex | head -2
echo

# Extract X25519 private key for challenge generation
X25519_PRIVATE_KEY=$(jq -r .private_key x25519.keys.json)

echo "7. Generating ONDC test challenge..."
echo "Using default test data:"
cargo run --package ondc-crypto-cli -- challenge --private-key "$X25519_PRIVATE_KEY" --environment staging
echo

echo "8. Generating custom challenge data..."
CUSTOM_CHALLENGE="Custom ONDC challenge for testing"
echo "Custom data: $CUSTOM_CHALLENGE"
cargo run --package ondc-crypto-cli -- challenge --private-key "$X25519_PRIVATE_KEY" --data "$CUSTOM_CHALLENGE" --environment staging
echo

echo "9. Generating challenge in JSON format..."
cargo run --package ondc-crypto-cli -- challenge --private-key "$X25519_PRIVATE_KEY" --data "$CUSTOM_CHALLENGE" --environment staging --json > challenge.json
echo "Challenge saved to challenge.json"
echo

echo "10. Testing different ONDC environments..."
echo "Pre-production environment:"
cargo run --package ondc-crypto-cli -- challenge --private-key "$X25519_PRIVATE_KEY" --data "Pre-prod test" --environment pre-prod
echo

echo "Production environment:"
cargo run --package ondc-crypto-cli -- challenge --private-key "$X25519_PRIVATE_KEY" --data "Production test" --environment production
echo

echo "11. Challenge testing workflow..."
echo "Generated challenge can be used to test BAP server /on_subscribe endpoint:"
echo
CHALLENGE_B64=$(jq -r .encrypted_challenge challenge.json)
echo "curl -X POST http://localhost:8080/on_subscribe \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{"
echo "    \"subscriber_id\": \"test.example.com\","
echo "    \"challenge\": \"$CHALLENGE_B64\""
echo "  }'"
echo

echo "=== Demo Complete ===" 