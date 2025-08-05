# ONDC Agent

🤖 A Rust library for converting natural language queries into ONDC/Beckn protocol-compliant JSON requests using Large Language Models (LLMs).

## Overview

The ONDC Agent bridges the gap between natural language and structured e-commerce protocols by:

1. **Intent Extraction**: Parsing user queries to extract e-commerce intent (items, location, price range, etc.)
2. **Beckn Generation**: Converting extracted intent into valid Beckn protocol search requests
3. **Provider Integration**: Supporting multiple LLM providers (Ollama, OpenAI, Anthropic)
4. **Validation**: Ensuring generated requests comply with ONDC/Beckn specifications

## Quick Start

```rust
use ondc_agent::{ONDCAgent, AgentConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize agent with Ollama (default)
    let config = AgentConfig::default();
    let agent = ONDCAgent::new(config).await?;
    
    // Process natural language query
    let query = "I need to buy fresh vegetables in Bangalore";
    let intent = agent.extract_intent(query).await?;
    let beckn_request = agent.generate_search_request(intent).await?;
    
    println!("Generated Beckn request: {}", serde_json::to_string_pretty(&beckn_request)?);
    Ok(())
}
```

## Features

- ✅ **Multi-Provider Support**: Ollama, OpenAI, Anthropic Claude
- ✅ **Intent Extraction**: Sophisticated NL → structured intent conversion
- ✅ **Beckn Compliance**: Generate valid ONDC/Beckn protocol requests
- ✅ **Error Handling**: Comprehensive error types and recovery
- ✅ **Async/Await**: Full async support with Tokio
- ✅ **Configurable**: Flexible configuration for different environments
- ✅ **Validation**: Input/output validation and confidence scoring

## Architecture

```
User Query → Intent Extractor → Beckn Generator → ONDC Network
     ↓              ↓              ↓
   Ollama    →  Intent JSON  →  Beckn JSON
```

## Configuration

```rust
use ondc_agent::{AgentConfig, ProviderConfig};

let config = AgentConfig {
    provider: ProviderConfig::Ollama {
        base_url: "http://localhost:11434".to_string(),
        model: "gemma2:latest".to_string(),
    },
    confidence_threshold: 0.7,
    timeout_secs: 30,
    max_retries: 3,
    ..Default::default()
};
```

## Examples

See the `examples/` directory for more detailed usage examples:
- Basic intent extraction
- Beckn request generation  
- Provider configuration
- Error handling

## Integration

This crate is designed to integrate with ONDC BAP servers:

```rust
// In your BAP server
use ondc_agent::{ONDCAgent, AgentConfig};

pub struct AppState {
    pub agent: ONDCAgent,
    // ... other services
}
```

## Development

```bash
# Run tests
cargo test

# Run with specific features
cargo build --features openai

# Format code
cargo fmt

# Check with clippy
cargo clippy
```

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.