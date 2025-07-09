use clap::{Parser, Subcommand};
use ondc_crypto_algorithms::{prelude::*, encrypt_aes256_ecb};
use ondc_crypto_formats::prelude::*;
use ondc_crypto_traits::traits::{Hasher, Signer, Verifier};
use std::io::{self, Read};

#[derive(Parser)]
#[command(name = "ondc-crypto")]
#[command(about = "ONDC Cryptographic CLI Utilities")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate cryptographic keys
    Generate {
        /// Type of key to generate
        #[arg(value_enum)]
        key_type: KeyType,

        /// Output format for the keys
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Base64)]
        format: OutputFormat,

        /// Output to JSON format
        #[arg(short, long)]
        json: bool,
    },

    /// Sign data with Ed25519
    Sign {
        /// Private key in base64 format
        #[arg(short, long)]
        private_key: String,

        /// Data to sign (if not provided, reads from stdin)
        #[arg(short, long)]
        data: Option<String>,

        /// Output format for the signature
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Base64)]
        format: OutputFormat,
    },

    /// Verify Ed25519 signature
    Verify {
        /// Public key in base64 format
        #[arg(short, long)]
        public_key: String,

        /// Signature to verify
        #[arg(short, long)]
        signature: String,

        /// Data that was signed (if not provided, reads from stdin)
        #[arg(short, long)]
        data: Option<String>,
    },

    /// Hash data with BLAKE2
    Hash {
        /// Data to hash (if not provided, reads from stdin)
        #[arg(short, long)]
        data: Option<String>,

        /// Output format for the hash
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Hex)]
        format: OutputFormat,
    },

    /// Generate ONDC test challenge
    Challenge {
        /// Challenge data to encrypt (if not provided, uses default test data)
        #[arg(short, long)]
        data: Option<String>,

        /// Your X25519 private key in base64 format
        #[arg(short, long)]
        private_key: String,

        /// ONDC environment (staging, preprod, production)
        #[arg(short, long, value_enum, default_value_t = ONDCEnvironment::Staging)]
        environment: ONDCEnvironment,

        /// Output to JSON format
        #[arg(short, long)]
        json: bool,
    },
}

#[derive(clap::ValueEnum, Clone)]
enum KeyType {
    Ed25519,
    X25519,
}

#[derive(clap::ValueEnum, Clone)]
enum OutputFormat {
    Base64,
    Hex,
    Raw,
}

#[derive(clap::ValueEnum, Clone)]
enum ONDCEnvironment {
    Staging,
    PreProd,
    Production,
}

impl std::fmt::Display for ONDCEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ONDCEnvironment::Staging => write!(f, "staging"),
            ONDCEnvironment::PreProd => write!(f, "preprod"),
            ONDCEnvironment::Production => write!(f, "production"),
        }
    }
}

#[derive(serde::Serialize)]
struct KeyPairOutput {
    private_key: String,
    public_key: String,
    key_type: String,
}

fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            key_type,
            format,
            json,
        } => {
            generate_keys(key_type, format, json)?;
        }
        Commands::Sign {
            private_key,
            data,
            format,
        } => {
            sign_data(private_key, data, format)?;
        }
        Commands::Verify {
            public_key,
            signature,
            data,
        } => {
            verify_signature(public_key, signature, data)?;
        }
        Commands::Hash { data, format } => {
            hash_data(data, format)?;
        }
        Commands::Challenge {
            data,
            private_key,
            environment,
            json,
        } => {
            generate_challenge(data, private_key, environment, json)?;
        }
    }

    Ok(())
}

fn generate_keys(key_type: KeyType, format: OutputFormat, json: bool) -> anyhow::Result<()> {
    match key_type {
        KeyType::Ed25519 => {
            let signer = Ed25519Signer::generate()?;
            let private_key = signer.private_key();
            let public_key = signer.public_key();

            let private_key_str = format_key(private_key, &format);
            let public_key_str = format_key(&public_key, &format);

            if json {
                let key_pair = KeyPairOutput {
                    private_key: private_key_str,
                    public_key: public_key_str,
                    key_type: "Ed25519".to_string(),
                };
                println!("{}", serde_json::to_string_pretty(&key_pair)?);
            } else {
                println!("Ed25519 Key Pair:");
                println!("Private Key: {}", private_key_str);
                println!("Public Key:  {}", public_key_str);
            }
        }
        KeyType::X25519 => {
            let key_exchange = X25519KeyExchange::generate()?;
            let private_key = key_exchange.private_key();
            let public_key = key_exchange.public_key();

            let private_key_str = format_key(private_key, &format);
            let public_key_str = format_key(&public_key, &format);

            if json {
                let key_pair = KeyPairOutput {
                    private_key: private_key_str,
                    public_key: public_key_str,
                    key_type: "X25519".to_string(),
                };
                println!("{}", serde_json::to_string_pretty(&key_pair)?);
            } else {
                println!("X25519 Key Pair:");
                println!("Private Key: {}", private_key_str);
                println!("Public Key:  {}", public_key_str);
            }
        }
    }

    Ok(())
}

fn sign_data(
    private_key: String,
    data: Option<String>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    // Decode private key
    let private_key_bytes = ed25519_private_key_from_base64(&private_key)?;
    let signer = Ed25519Signer::new(&private_key_bytes)?;

    // Get data to sign
    let data_to_sign = if let Some(data) = data {
        data.into_bytes()
    } else {
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer)?;
        buffer
    };

    // Sign the data
    let signature = signer.sign(&data_to_sign)?;
    let signature_str = format_signature(&signature, &format);

    println!("{}", signature_str);
    Ok(())
}

fn verify_signature(
    public_key: String,
    signature: String,
    data: Option<String>,
) -> anyhow::Result<()> {
    // Decode public key
    let public_key_bytes = ed25519_public_key_from_base64(&public_key)?;
    let verifier = Ed25519Verifier::new();

    // Decode signature
    let signature_bytes = decode_signature(&signature)?;

    // Get data that was signed
    let data_to_verify = if let Some(data) = data {
        data.into_bytes()
    } else {
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer)?;
        buffer
    };

    // Convert public key to fixed-size array
    let mut public_key_array = [0u8; 32];
    public_key_array.copy_from_slice(&public_key_bytes);

    // Convert signature to fixed-size array
    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(&signature_bytes);

    // Verify the signature
    match verifier.verify(&public_key_array, &data_to_verify, &signature_array) {
        Ok(_) => {
            println!("✓ Signature is valid");
            std::process::exit(0);
        }
        Err(_) => {
            eprintln!("✗ Signature is invalid");
            std::process::exit(1);
        }
    }
}

fn hash_data(data: Option<String>, format: OutputFormat) -> anyhow::Result<()> {
    let hasher = Blake2Hasher::new();

    // Get data to hash
    let data_to_hash = if let Some(data) = data {
        data.into_bytes()
    } else {
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer)?;
        buffer
    };

    // Hash the data
    let hash = hasher.hash(&data_to_hash)?;
    let hash_str = format_hash(&hash, &format);

    println!("{}", hash_str);
    Ok(())
}

fn generate_challenge(
    data: Option<String>,
    private_key: String,
    environment: ONDCEnvironment,
    json: bool,
) -> anyhow::Result<()> {
    // Decode private key from base64
    let private_key_bytes = x25519_private_key_from_base64(&private_key)?;
    let key_exchange = X25519KeyExchange::new(&private_key_bytes)?;

    // Get ONDC public key for the environment
    let ondc_public_key = get_ondc_public_key(environment.clone())?;

    // Generate shared secret using X25519 key exchange
    let shared_secret = key_exchange.diffie_hellman(&ondc_public_key)?;

    // Prepare challenge data
    let challenge_data = if let Some(data) = data {
        data.into_bytes()
    } else {
        b"This is a test challenge for ONDC".to_vec()
    };

    // Encrypt challenge using AES-256-ECB with shared secret
    let encrypted_challenge = encrypt_aes256_ecb(&challenge_data, &shared_secret)?;

    if json {
        let challenge_output = ChallengeOutput {
            encrypted_challenge: encode_signature(&encrypted_challenge),
            environment: environment.to_string(),
            original_data: String::from_utf8_lossy(&challenge_data).to_string(),
        };
        println!("{}", serde_json::to_string_pretty(&challenge_output)?);
    } else {
        println!("ONDC Test Challenge Generated:");
        println!("Encrypted Challenge (Base64):");
        println!("{}", encode_signature(&encrypted_challenge));
        println!("Environment: {}", environment);
        println!("Original Data: {}", String::from_utf8_lossy(&challenge_data));
    }

    Ok(())
}

fn get_ondc_public_key(environment: ONDCEnvironment) -> anyhow::Result<[u8; 32]> {
    let public_key_b64 = match environment {
        ONDCEnvironment::Staging => "MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM=",
        ONDCEnvironment::PreProd => "MCowBQYDK2VuAyEAa9Wbpvd9SsrpOZFcynyt/TO3x0Yrqyys4NUGIvyxX2Q=",
        ONDCEnvironment::Production => "MCowBQYDK2VuAyEAvVEyZY91O2yV8w8/CAwVDAnqIZDJJUPdLUUKwLo3K0M=",
    };

    let decoded = decode_signature(public_key_b64)?;
    
    // Extract raw key from DER format (last 32 bytes)
    if decoded.len() < 32 {
        return Err(anyhow::anyhow!("ONDC public key too short"));
    }
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[decoded.len() - 32..]);
    Ok(key)
}

fn x25519_private_key_from_base64(private_key_b64: &str) -> anyhow::Result<[u8; 32]> {
    let decoded = decode_signature(private_key_b64)?;
    if decoded.len() != 32 {
        return Err(anyhow::anyhow!("X25519 private key must be 32 bytes"));
    }
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

#[derive(serde::Serialize)]
struct ChallengeOutput {
    encrypted_challenge: String,
    environment: String,
    original_data: String,
}

fn format_key(key: &[u8], format: &OutputFormat) -> String {
    match format {
        OutputFormat::Base64 => encode_signature(key),
        OutputFormat::Hex => hex::encode(key),
        OutputFormat::Raw => String::from_utf8_lossy(key).to_string(),
    }
}

fn format_signature(signature: &[u8], format: &OutputFormat) -> String {
    match format {
        OutputFormat::Base64 => encode_signature(signature),
        OutputFormat::Hex => hex::encode(signature),
        OutputFormat::Raw => String::from_utf8_lossy(signature).to_string(),
    }
}

fn format_hash(hash: &[u8], format: &OutputFormat) -> String {
    match format {
        OutputFormat::Base64 => encode_signature(hash),
        OutputFormat::Hex => hex::encode(hash),
        OutputFormat::Raw => String::from_utf8_lossy(hash).to_string(),
    }
}
