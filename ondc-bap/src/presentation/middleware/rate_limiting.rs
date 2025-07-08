//! Rate limiting middleware for ONDC BAP Server

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    http::StatusCode,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::warn;

/// Rate limiter for per-IP limiting
#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window_duration: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_duration: Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window_duration,
        }
    }
    
    pub fn check_rate_limit(&self, client_ip: &str) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();
        
        let client_requests = requests.entry(client_ip.to_string()).or_insert_with(Vec::new);
        
        // Remove old requests outside the window
        client_requests.retain(|&request_time| {
            now.duration_since(request_time) < self.window_duration
        });
        
        if client_requests.len() >= self.max_requests {
            false
        } else {
            client_requests.push(now);
            true
        }
    }
}

/// Extract client IP from request headers
fn extract_client_ip(request: &Request) -> String {
    // Check for forwarded headers first (for requests behind proxies)
    if let Some(forwarded_for) = request.headers().get("x-forwarded-for") {
        if let Ok(forwarded_for_str) = forwarded_for.to_str() {
            // Take the first IP in the chain (original client IP)
            if let Some(first_ip) = forwarded_for_str.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }
    
    // Check for real IP header
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        if let Ok(real_ip_str) = real_ip.to_str() {
            return real_ip_str.to_string();
        }
    }
    
    // Check for CF-Connecting-IP (Cloudflare)
    if let Some(cf_ip) = request.headers().get("cf-connecting-ip") {
        if let Ok(cf_ip_str) = cf_ip.to_str() {
            return cf_ip_str.to_string();
        }
    }
    
    // Fallback to remote address if available
    if let Some(remote_addr) = request.extensions().get::<std::net::SocketAddr>() {
        return remote_addr.ip().to_string();
    }
    
    // Final fallback
    "unknown".to_string()
}

/// Rate limiting middleware (per-IP)
pub async fn rate_limiting_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract client IP from request
    let client_ip = extract_client_ip(&request);
    
    // Create rate limiter (in production, this would be shared state)
    let rate_limiter = RateLimiter::new(100, Duration::from_secs(60)); // 100 requests per minute per IP
    
    if !rate_limiter.check_rate_limit(&client_ip) {
        warn!("Rate limit exceeded for IP: {}", client_ip);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    Ok(next.run(request).await)
}

/// Rate limiting middleware with custom limits (per-IP)
pub async fn rate_limiting_middleware_with_limits(
    max_requests: usize,
    window_duration: Duration,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let client_ip = extract_client_ip(&request);
    let rate_limiter = RateLimiter::new(max_requests, window_duration);
    
    if !rate_limiter.check_rate_limit(&client_ip) {
        warn!("Rate limit exceeded for IP: {}", client_ip);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    Ok(next.run(request).await)
}

/// Rate limiting middleware with different limits for different IP ranges
pub async fn adaptive_rate_limiting_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let client_ip = extract_client_ip(&request);
    
    // Define different rate limits based on IP characteristics
    let (max_requests, window_duration) = if client_ip == "127.0.0.1" || client_ip == "::1" {
        // Localhost gets higher limits for development
        (1000, Duration::from_secs(60))
    } else if client_ip.starts_with("10.") || client_ip.starts_with("192.168.") || client_ip.starts_with("172.") {
        // Private network IPs get moderate limits
        (200, Duration::from_secs(60))
    } else {
        // Public IPs get standard limits
        (100, Duration::from_secs(60))
    };
    
    let rate_limiter = RateLimiter::new(max_requests, window_duration);
    
    if !rate_limiter.check_rate_limit(&client_ip) {
        warn!("Rate limit exceeded for IP: {} (limit: {}/min)", client_ip, max_requests);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, HeaderMap};
    use axum::body::Body;

    #[test]
    fn test_extract_client_ip_from_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "192.168.1.1, 10.0.0.1".parse().unwrap());
        
        let mut request = Request::new(Body::empty());
        *request.headers_mut() = headers;
        
        let client_ip = extract_client_ip(&request);
        assert_eq!(client_ip, "192.168.1.1");
    }

    #[test]
    fn test_extract_client_ip_from_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "203.0.113.1".parse().unwrap());
        
        let mut request = Request::new(Body::empty());
        *request.headers_mut() = headers;
        
        let client_ip = extract_client_ip(&request);
        assert_eq!(client_ip, "203.0.113.1");
    }

    #[test]
    fn test_extract_client_ip_from_cloudflare() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "198.51.100.1".parse().unwrap());
        
        let mut request = Request::new(Body::empty());
        *request.headers_mut() = headers;
        
        let client_ip = extract_client_ip(&request);
        assert_eq!(client_ip, "198.51.100.1");
    }

    #[test]
    fn test_extract_client_ip_fallback() {
        let request = Request::new(Body::empty());
        let client_ip = extract_client_ip(&request);
        assert_eq!(client_ip, "unknown");
    }

    #[test]
    fn test_rate_limiter_basic() {
        let rate_limiter = RateLimiter::new(2, Duration::from_secs(1));
        
        // First two requests should succeed
        assert!(rate_limiter.check_rate_limit("192.168.1.1"));
        assert!(rate_limiter.check_rate_limit("192.168.1.1"));
        
        // Third request should fail
        assert!(!rate_limiter.check_rate_limit("192.168.1.1"));
        
        // Different IP should still work
        assert!(rate_limiter.check_rate_limit("192.168.1.2"));
    }

    #[test]
    fn test_rate_limiter_window_expiry() {
        let rate_limiter = RateLimiter::new(1, Duration::from_millis(100));
        
        // First request should succeed
        assert!(rate_limiter.check_rate_limit("192.168.1.1"));
        
        // Second request should fail immediately
        assert!(!rate_limiter.check_rate_limit("192.168.1.1"));
        
        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(150));
        
        // Should succeed again
        assert!(rate_limiter.check_rate_limit("192.168.1.1"));
    }
} 