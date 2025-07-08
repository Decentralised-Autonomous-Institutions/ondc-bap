# ONDC Crypto CLI

A command-line interface for ONDC cryptographic operations.

## Features

- Generate Ed25519 and X25519 key pairs
- Sign data with Ed25519
- Verify Ed25519 signatures
- Hash data with BLAKE2
- Multiple output formats (Base64, Hex, Raw)
- JSON output support

## Usage

### Generate Keys
```bash
ondc-crypto generate ed25519
ondc-crypto generate x25519 --format hex --json
```

### Sign Data
```bash
ondc-crypto sign --private-key <key> --data "Hello World"
```

### Verify Signatures
```bash
ondc-crypto verify --public-key <key> --signature <sig> --data "Hello World"
```

### Hash Data
```bash
ondc-crypto hash --data "Hello World"
``` 