//! Basic usage example for the ONDC Agent.
//!
//! This example demonstrates how to create an agent and process natural language queries.

use ondc_agent::{ONDCAgent, AgentConfig, BapConfig, ProviderConfig};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    println!("🤖 ONDC Agent Basic Usage Example");
    
    // Create agent configuration
    let config = AgentConfig {
        provider: ProviderConfig::ollama("http://localhost:11434", "gemma2:latest"),
        bap: BapConfig {
            id: "example.bap.com".to_string(),
            uri: "https://example.bap.com".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    
    println!("📝 Configuration: {:?}", config.provider.provider_type());
    
    // Create the agent
    let agent = match ONDCAgent::new(config).await {
        Ok(agent) => {
            println!("✅ Agent created successfully");
            agent
        }
        Err(e) => {
            println!("❌ Failed to create agent: {}", e);
            return Err(e.into());
        }
    };
    
    // Test queries
    let test_queries = vec![
        "I need to buy fresh vegetables in Bangalore",
        "Find me a restaurant that delivers pizza",
        "Book a cab from MG Road to Airport",
        "I want to order groceries under 500 rupees",
    ];
    
    for query in test_queries {
        println!("\n🔍 Processing query: '{}'", query);
        
        match agent.extract_intent(query).await {
            Ok(intent) => {
                println!("✅ Intent extracted:");
                println!("   - Confidence: {:.2}", intent.confidence);
                println!("   - Category: {:?}", intent.category);
                println!("   - Item: {:?}", intent.item_name);
                println!("   - Location: {:?}", intent.location.as_ref().map(|l| l.to_string()));
                
                if intent.is_valid() {
                    match agent.generate_search_request(intent).await {
                        Ok(beckn_request) => {
                            println!("✅ Beckn request generated:");
                            println!("   - Domain: {}", beckn_request.context.domain);
                            println!("   - City: {}", beckn_request.context.city);
                            println!("   - Confidence: {:.2}", beckn_request.confidence);
                        }
                        Err(e) => {
                            println!("❌ Failed to generate Beckn request: {}", e);
                        }
                    }
                } else {
                    println!("⚠️  Intent confidence too low for processing");
                }
            }
            Err(e) => {
                println!("❌ Failed to extract intent: {}", e);
            }
        }
    }
    
    println!("\n🎉 Example completed!");
    Ok(())
}