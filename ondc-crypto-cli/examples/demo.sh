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

echo "=== Demo Complete ===" 