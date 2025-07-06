//! ONDC Crypto CLI tool
//!
//! This binary provides a command-line interface for ONDC cryptographic operations.

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [options]", args[0]);
        eprintln!("Commands:");
        eprintln!("  sign <body> <private_key> <subscriber_id> <key_id>");
        eprintln!("  verify <header> <body> <public_key>");
        eprintln!("  vlookup <country> <domain> <type> <city> <subscriber_id> <private_key>");
        process::exit(1);
    }
    
    let command = &args[1];
    
    match command.as_str() {
        "sign" => {
            if args.len() != 6 {
                eprintln!("Usage: {} sign <body> <private_key> <subscriber_id> <key_id>", args[0]);
                process::exit(1);
            }
            
            // TODO: Implement sign command
            eprintln!("Sign command not yet implemented");
            process::exit(1);
        }
        
        "verify" => {
            if args.len() != 5 {
                eprintln!("Usage: {} verify <header> <body> <public_key>", args[0]);
                process::exit(1);
            }
            
            // TODO: Implement verify command
            eprintln!("Verify command not yet implemented");
            process::exit(1);
        }
        
        "vlookup" => {
            if args.len() != 8 {
                eprintln!("Usage: {} vlookup <country> <domain> <type> <city> <subscriber_id> <private_key>", args[0]);
                process::exit(1);
            }
            
            // TODO: Implement vlookup command
            eprintln!("VLookup command not yet implemented");
            process::exit(1);
        }
        
        _ => {
            eprintln!("Unknown command: {}", command);
            eprintln!("Available commands: sign, verify, vlookup");
            process::exit(1);
        }
    }
} 