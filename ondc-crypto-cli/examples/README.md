# ONDC Crypto CLI Examples

This directory contains examples demonstrating how to use the ONDC Crypto CLI for various cryptographic operations, including the new challenge generation capabilities for testing ONDC BAP servers.

## Quick Start

Run the complete demo to see all features in action:

```bash
cd examples
chmod +x demo.sh
./demo.sh
```

## Available Scripts

### 1. `demo.sh` - Complete Feature Demo
Demonstrates all CLI features including key generation, signing, verification, and challenge generation.

### 2. `test-challenge.sh` - Interactive Challenge Testing
Interactive script for testing challenge generation and BAP server integration with colored output and detailed feedback.

### 3. `ci-test-example.sh` - CI/CD Integration Example
Example script showing how to integrate challenge testing into CI/CD pipelines with environment variables.

## Challenge Generation Examples

### 1. Basic Challenge Generation

Generate a test challenge using default test data:

```bash
# First, generate an X25519 key pair
cargo run --package ondc-crypto-cli -- generate x25519

# Use the private key to generate a challenge
cargo run --package ondc-crypto-cli -- challenge \
  --private-key "YOUR_X25519_PRIVATE_KEY" \
  --environment staging
```

### 2. Custom Challenge Data

Generate a challenge with custom data:

```bash
cargo run --package ondc-crypto-cli -- challenge \
  --private-key "YOUR_X25519_PRIVATE_KEY" \
  --data "Custom challenge data for testing" \
  --environment staging
```

### 3. JSON Output Format

Generate challenge with structured JSON output:

```bash
cargo run --package ondc-crypto-cli -- challenge \
  --private-key "YOUR_X25519_PRIVATE_KEY" \
  --data "JSON test challenge" \
  --environment staging \
  --json
```

Example JSON output:
```json
{
  "encrypted_challenge": "OEWkbQV71HButW404pt3WFoz5fcJYtJpJFOQqYm+FZQ=",
  "environment": "staging",
  "original_data": "JSON test challenge"
}
```

### 4. Different ONDC Environments

Test with different ONDC environments:

```bash
# Staging environment
cargo run --package ondc-crypto-cli -- challenge \
  --private-key "YOUR_X25519_PRIVATE_KEY" \
  --environment staging

# Pre-production environment
cargo run --package ondc-crypto-cli -- challenge \
  --private-key "YOUR_X25519_PRIVATE_KEY" \
  --environment pre-prod

# Production environment
cargo run --package ondc-crypto-cli -- challenge \
  --private-key "YOUR_X25519_PRIVATE_KEY" \
  --environment production
```

## Testing BAP Server with Generated Challenges

### Interactive Testing

Use the interactive test script for comprehensive testing:

```bash
chmod +x test-challenge.sh
./test-challenge.sh
```

This script will:
- Generate X25519 key pairs
- Create test challenges
- Check BAP server health
- Test the `/on_subscribe` endpoint
- Validate challenge/response matching
- Provide manual testing commands

### Complete Testing Workflow

1. **Generate X25519 Key Pair**:
   ```bash
   cargo run --package ondc-crypto-cli -- generate x25519 --json > x25519.keys.json
   ```

2. **Generate Test Challenge**:
   ```bash
   PRIVATE_KEY=$(jq -r .private_key x25519.keys.json)
   cargo run --package ondc-crypto-cli -- challenge \
     --private-key "$PRIVATE_KEY" \
     --data "Test challenge for BAP server" \
     --environment staging \
     --json > challenge.json
   ```

3. **Extract Challenge for Testing**:
   ```bash
   CHALLENGE_B64=$(jq -r .encrypted_challenge challenge.json)
   ```

4. **Test BAP Server Endpoint**:
   ```bash
   curl -X POST http://localhost:8080/on_subscribe \
     -H "Content-Type: application/json" \
     -d "{
       \"subscriber_id\": \"test.example.com\",
       \"challenge\": \"$CHALLENGE_B64\"
     }"
   ```

### Expected Response

If the BAP server is working correctly, you should receive:

```json
{
  "answer": "Test challenge for BAP server"
}
```

## CI/CD Integration

### Automated Testing

Use the CI/CD example script for automated testing:

```bash
# Set environment variables
export X25519_PRIVATE_KEY="your-base64-encoded-private-key"
export BAP_SERVER_URL="http://your-bap-server:8080"
export SUBSCRIBER_ID="your.subscriber.id"
export ENVIRONMENT="staging"

# Run automated test
chmod +x ci-test-example.sh
./ci-test-example.sh
```

### GitHub Actions Example

```yaml
name: ONDC Challenge Testing

on: [push, pull_request]

jobs:
  test-challenge:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      
      - name: Generate and test challenge
        env:
          X25519_PRIVATE_KEY: ${{ secrets.X25519_PRIVATE_KEY }}
          BAP_SERVER_URL: ${{ secrets.BAP_SERVER_URL }}
          SUBSCRIBER_ID: ${{ secrets.SUBSCRIBER_ID }}
          ENVIRONMENT: staging
        run: |
          cd ondc-crypto-cli/examples
          chmod +x ci-test-example.sh
          ./ci-test-example.sh
```

## Automated Testing Script

The `demo.sh` script demonstrates a complete workflow:

1. **Key Generation**: Creates Ed25519 and X25519 key pairs
2. **Signature Operations**: Signs and verifies messages
3. **Challenge Generation**: Creates test challenges for all environments
4. **Testing Setup**: Prepares curl commands for BAP server testing

### Running the Demo

```bash
# Make the script executable
chmod +x demo.sh

# Run the complete demo
./demo.sh
```

## Challenge Generation Details

### How It Works

1. **X25519 Key Exchange**: 
   - Uses your private key and ONDC's public key
   - Generates a shared secret using Diffie-Hellman key exchange

2. **AES-256-ECB Encryption**:
   - Encrypts challenge data using the shared secret as the key
   - Uses AES-256-ECB mode as required by ONDC specification
   - Automatically pads data to 16-byte blocks

3. **Base64 Encoding**:
   - Outputs encrypted challenge in base64 format
   - Ready for HTTP transmission to BAP server

### ONDC Public Keys

The CLI uses the official ONDC public keys for each environment:

- **Staging**: `MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM=`
- **Pre-Production**: `MCowBQYDK2VuAyEAa9Wbpvd9SsrpOZFcynyt/TO3x0Yrqyys4NUGIvyxX2Q=`
- **Production**: `MCowBQYDK2VuAyEAvVEyZY91O2yV8w8/CAwVDAnqIZDJJUPdLUUKwLo3K0M=`

### Security Notes

- **Key Management**: Keep your private keys secure and never share them
- **Environment Testing**: Use staging environment for development and testing
- **Challenge Uniqueness**: Each challenge should be unique for proper testing
- **Server Configuration**: Ensure your BAP server uses the same X25519 private key

## Troubleshooting

### Common Issues

1. **Invalid Private Key Format**:
   - Ensure the private key is base64-encoded
   - X25519 private keys must be exactly 32 bytes when decoded

2. **Environment Mismatch**:
   - Use the same environment (staging/preprod/prod) for both challenge generation and BAP server configuration

3. **BAP Server Not Responding**:
   - Ensure the BAP server is running on the expected port
   - Check that the subscriber_id matches your configuration

4. **Decryption Failures**:
   - Verify that the BAP server uses the same X25519 private key
   - Ensure the challenge was generated for the correct environment

### Debug Mode

For debugging, you can use the JSON output to inspect the challenge details:

```bash
cargo run --package ondc-crypto-cli -- challenge \
  --private-key "$PRIVATE_KEY" \
  --data "Debug test" \
  --environment staging \
  --json | jq .
```

This will show you the encrypted challenge, environment, and original data for verification.

## Prerequisites

- **Rust**: Latest stable version
- **jq**: For JSON processing in scripts
- **curl**: For HTTP testing
- **BAP Server**: Running instance for endpoint testing

### Installation

```bash
# Install jq (Ubuntu/Debian)
sudo apt-get install jq

# Install jq (macOS)
brew install jq

# Install jq (CentOS/RHEL)
sudo yum install jq
``` 