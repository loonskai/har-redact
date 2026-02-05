use crate::config::{RedactionConfig, RedactionRule, RedactionScope};
use crate::har::{Cookie, Entry, HarFile, Header, PostData, QueryParam};
use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

lazy_static! {
    static ref AUTH_HEADER_NAMES: Regex = Regex::new(
        r"(?i)^(authorization|x-api-key|x-auth-token|x-csrf-token|api-key|auth-token|access-token|session-id|x-session-id)$"
    ).unwrap();

    static ref BEARER_PATTERN: Regex = Regex::new(r"(?i)bearer\s+([a-zA-Z0-9\-._~+/]+=*)").unwrap();

    static ref BASIC_AUTH_PATTERN: Regex = Regex::new(r"(?i)basic\s+([a-zA-Z0-9+/]+=*)").unwrap();

    static ref AUTH_QUERY_PARAMS: Regex = Regex::new(
        r"(?i)^(api_key|apikey|api-key|token|access_token|accesstoken|secret|password|passwd|pwd|session|sessionid|session_id|auth|authorization)$"
    ).unwrap();

    static ref EMAIL_PATTERN: Regex = Regex::new(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    ).unwrap();

    static ref PHONE_PATTERN: Regex = Regex::new(
        r"\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b"
    ).unwrap();

    static ref IPV4_PATTERN: Regex = Regex::new(
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    ).unwrap();

    static ref JWT_PATTERN: Regex = Regex::new(
        r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"
    ).unwrap();

    static ref CREDIT_CARD_PATTERN: Regex = Regex::new(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    ).unwrap();
}

#[derive(Debug, Default, Clone)]
pub struct RedactionStats {
    pub headers_redacted: usize,
    pub cookies_redacted: usize,
    pub query_params_redacted: usize,
    pub bodies_redacted: usize,
    pub urls_redacted: usize,
    pub total_redactions: usize,
}

impl RedactionStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_header(&mut self) {
        self.headers_redacted += 1;
        self.total_redactions += 1;
    }

    pub fn increment_cookie(&mut self) {
        self.cookies_redacted += 1;
        self.total_redactions += 1;
    }

    pub fn increment_query_param(&mut self) {
        self.query_params_redacted += 1;
        self.total_redactions += 1;
    }

    pub fn increment_body(&mut self) {
        self.bodies_redacted += 1;
        self.total_redactions += 1;
    }

    pub fn increment_url(&mut self) {
        self.urls_redacted += 1;
        self.total_redactions += 1;
    }
}

pub struct RedactionEngine {
    config: RedactionConfig,
    custom_regexes: Vec<(Regex, RedactionRule)>,
    hash_cache: HashMap<String, String>,
}

impl RedactionEngine {
    pub fn new(config: RedactionConfig) -> Result<Self> {
        config.validate()?;

        let mut custom_regexes = Vec::new();
        for rule in &config.custom_patterns {
            let regex = rule.compile()?;
            custom_regexes.push((regex, rule.clone()));
        }

        Ok(Self {
            config,
            custom_regexes,
            hash_cache: HashMap::new(),
        })
    }

    pub fn redact_har(&mut self, har: &mut HarFile) -> Result<RedactionStats> {
        let mut stats = RedactionStats::new();

        for entry in &mut har.log.entries {
            self.redact_entry(entry, &mut stats)?;
        }

        Ok(stats)
    }

    fn redact_entry(&mut self, entry: &mut Entry, stats: &mut RedactionStats) -> Result<()> {
        self.redact_url(&mut entry.request.url, stats);
        self.redact_headers(&mut entry.request.headers, stats);
        self.redact_cookies(&mut entry.request.cookies, stats);
        self.redact_query_params(&mut entry.request.query_string, stats);

        if let Some(post_data) = &mut entry.request.post_data {
            self.redact_post_data(post_data, stats);
        }

        self.redact_headers(&mut entry.response.headers, stats);
        self.redact_cookies(&mut entry.response.cookies, stats);

        if let Some(text) = &mut entry.response.content.text {
            self.redact_body(text, stats);
        }

        Ok(())
    }

    fn redact_url(&mut self, url: &mut String, stats: &mut RedactionStats) {
        let original = url.clone();
        let mut modified = false;

        let custom_rules: Vec<_> = self
            .custom_regexes
            .iter()
            .filter(|(_, rule)| rule.applies_to(RedactionScope::Urls))
            .map(|(regex, rule)| (regex.clone(), rule.replacement.clone()))
            .collect();

        for (regex, replacement) in custom_rules {
            if regex.is_match(url) {
                *url = self.apply_redaction(url, &regex, &replacement);
                modified = true;
            }
        }

        if self.config.redact_emails && EMAIL_PATTERN.is_match(url) {
            *url = self.apply_pattern_redaction(url, &EMAIL_PATTERN);
            modified = true;
        }

        if modified && *url != original {
            stats.increment_url();
        }
    }

    fn redact_headers(&mut self, headers: &mut [Header], stats: &mut RedactionStats) {
        for header in headers {
            if self.should_redact_header(&header.name) {
                let original = header.value.clone();
                header.value = self.redact_value(&original);
                if header.value != original {
                    stats.increment_header();
                }
            } else {
                let original = header.value.clone();
                header.value = self.redact_patterns(&original, RedactionScope::Headers);
                if header.value != original {
                    stats.increment_header();
                }
            }
        }
    }

    fn redact_cookies(&mut self, cookies: &mut [Cookie], stats: &mut RedactionStats) {
        if !self.config.redact_cookies {
            return;
        }

        for cookie in cookies {
            let original = cookie.value.clone();
            cookie.value = self.redact_value(&original);
            if cookie.value != original {
                stats.increment_cookie();
            }
        }
    }

    fn redact_query_params(&mut self, params: &mut [QueryParam], stats: &mut RedactionStats) {
        if !self.config.redact_auth_params {
            return;
        }

        for param in params {
            if AUTH_QUERY_PARAMS.is_match(&param.name) {
                let original = param.value.clone();
                param.value = self.redact_value(&original);
                if param.value != original {
                    stats.increment_query_param();
                }
            } else {
                let original = param.value.clone();
                param.value = self.redact_patterns(&original, RedactionScope::Urls);
                if param.value != original {
                    stats.increment_query_param();
                }
            }
        }
    }

    fn redact_post_data(&mut self, post_data: &mut PostData, stats: &mut RedactionStats) {
        let original = post_data.text.clone();
        post_data.text = self.redact_patterns(&original, RedactionScope::Body);
        if post_data.text != original {
            stats.increment_body();
        }

        if let Some(params) = &mut post_data.params {
            for param in params {
                if let Some(value) = &mut param.value {
                    let original = value.clone();
                    *value = self.redact_patterns(&original, RedactionScope::Body);
                    if *value != original {
                        stats.increment_body();
                    }
                }
            }
        }
    }

    fn redact_body(&mut self, text: &mut String, stats: &mut RedactionStats) {
        let original = text.clone();
        *text = self.redact_patterns(&original, RedactionScope::Body);
        if *text != original {
            stats.increment_body();
        }
    }

    fn should_redact_header(&self, name: &str) -> bool {
        self.config.redact_auth_headers && AUTH_HEADER_NAMES.is_match(name)
    }

    fn redact_patterns(&mut self, text: &str, scope: RedactionScope) -> String {
        let mut result = text.to_string();

        let custom_rules: Vec<_> = self
            .custom_regexes
            .iter()
            .filter(|(_, rule)| rule.applies_to(scope.clone()))
            .map(|(regex, rule)| (regex.clone(), rule.replacement.clone()))
            .collect();

        for (regex, replacement) in custom_rules {
            result = self.apply_redaction(&result, &regex, &replacement);
        }

        if self.config.redact_emails {
            result = self.apply_pattern_redaction(&result, &EMAIL_PATTERN);
        }

        if self.config.redact_phone_numbers {
            result = self.apply_pattern_redaction(&result, &PHONE_PATTERN);
        }

        if self.config.redact_ips {
            result = self.apply_pattern_redaction(&result, &IPV4_PATTERN);
        }

        result = self.apply_pattern_redaction(&result, &JWT_PATTERN);
        result = self.apply_pattern_redaction(&result, &CREDIT_CARD_PATTERN);

        result
    }

    fn apply_pattern_redaction(&mut self, text: &str, pattern: &Regex) -> String {
        pattern
            .replace_all(text, |caps: &regex::Captures| {
                let matched = caps.get(0).unwrap().as_str();
                self.redact_value(matched)
            })
            .to_string()
    }

    fn apply_redaction(&mut self, text: &str, pattern: &Regex, replacement: &str) -> String {
        pattern
            .replace_all(text, |caps: &regex::Captures| {
                let matched = caps.get(0).unwrap().as_str();
                if replacement.contains("{hash}") {
                    let hash = self.hash_value(matched);
                    replacement.replace("{hash}", &hash)
                } else if replacement.contains("{length}") {
                    replacement.replace("{length}", &matched.len().to_string())
                } else {
                    replacement.to_string()
                }
            })
            .to_string()
    }

    fn redact_value(&mut self, value: &str) -> String {
        if self.config.hash_values {
            self.hash_value(value)
        } else if self.config.preserve_length {
            format!("[REDACTED:{}]", value.len())
        } else {
            "[REDACTED]".to_string()
        }
    }

    fn hash_value(&mut self, value: &str) -> String {
        if let Some(cached) = self.hash_cache.get(value) {
            return cached.clone();
        }

        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        let result = hasher.finalize();
        let hash = format!("[HASH:{}]", hex::encode(&result[..8]));

        self.hash_cache.insert(value.to_string(), hash.clone());
        hash
    }

    pub fn config(&self) -> &RedactionConfig {
        &self.config
    }

    pub fn stats(&self) -> RedactionStats {
        RedactionStats::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactionConfig;
    use crate::har::*;

    fn create_test_entry() -> Entry {
        Entry {
            pageref: None,
            started_date_time: "2023-01-01T00:00:00Z".to_string(),
            time: 100.0,
            request: Request {
                method: "GET".to_string(),
                url: "https://api.example.com/data?token=secret123".to_string(),
                http_version: "HTTP/1.1".to_string(),
                cookies: vec![],
                headers: vec![Header {
                    name: "Authorization".to_string(),
                    value: "Bearer abc123xyz".to_string(),
                    comment: None,
                }],
                query_string: vec![QueryParam {
                    name: "token".to_string(),
                    value: "secret123".to_string(),
                    comment: None,
                }],
                post_data: None,
                headers_size: 100,
                body_size: 0,
                comment: None,
            },
            response: Response {
                status: 200,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                cookies: vec![],
                headers: vec![],
                content: Content {
                    size: 0,
                    compression: None,
                    mime_type: "application/json".to_string(),
                    text: Some("{}".to_string()),
                    encoding: None,
                    comment: None,
                },
                redirect_url: "".to_string(),
                headers_size: 100,
                body_size: 0,
                comment: None,
            },
            cache: Cache {
                before_request: None,
                after_request: None,
                comment: None,
            },
            timings: Timings {
                blocked: Some(1.0),
                dns: Some(2.0),
                connect: Some(3.0),
                send: 4.0,
                wait: 5.0,
                receive: 6.0,
                ssl: Some(7.0),
                comment: None,
            },
            server_ip_address: None,
            connection: None,
            comment: None,
        }
    }

    #[test]
    fn test_redaction_engine_creation() {
        let config = RedactionConfig::default();
        let engine = RedactionEngine::new(config);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_redact_header() {
        let config = RedactionConfig::default();
        let mut engine = RedactionEngine::new(config).unwrap();
        let mut stats = RedactionStats::new();

        let mut headers = vec![Header {
            name: "Authorization".to_string(),
            value: "Bearer token123".to_string(),
            comment: None,
        }];

        engine.redact_headers(&mut headers, &mut stats);
        assert_eq!(headers[0].value, "[REDACTED]");
        assert_eq!(stats.headers_redacted, 1);
    }

    #[test]
    fn test_preserve_length() {
        let config = RedactionConfig::builder()
            .preserve_length(true)
            .build()
            .unwrap();
        let mut engine = RedactionEngine::new(config).unwrap();

        let value = engine.redact_value("secret123");
        assert_eq!(value, "[REDACTED:9]");
    }

    #[test]
    fn test_hash_values() {
        let config = RedactionConfig::builder()
            .hash_values(true)
            .build()
            .unwrap();
        let mut engine = RedactionEngine::new(config).unwrap();

        let value1 = engine.redact_value("secret");
        let value2 = engine.redact_value("secret");

        // Same input should produce same hash
        assert_eq!(value1, value2);
        assert!(value1.starts_with("[HASH:"));
    }

    #[test]
    fn test_email_redaction() {
        let config = RedactionConfig::builder()
            .redact_emails(true)
            .build()
            .unwrap();
        let mut engine = RedactionEngine::new(config).unwrap();

        let text = "Contact us at user@example.com for support";
        let redacted = engine.redact_patterns(text, RedactionScope::Body);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("user@example.com"));
    }

    #[test]
    fn test_phone_redaction() {
        let config = RedactionConfig::builder()
            .redact_phone_numbers(true)
            .build()
            .unwrap();
        let mut engine = RedactionEngine::new(config).unwrap();

        let text = "Call us at 555-123-4567";
        let redacted = engine.redact_patterns(text, RedactionScope::Body);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("555-123-4567"));
    }

    #[test]
    fn test_jwt_redaction() {
        let config = RedactionConfig::default();
        let mut engine = RedactionEngine::new(config).unwrap();

        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let text = format!("Token: {}", jwt);
        let redacted = engine.redact_patterns(&text, RedactionScope::Body);
        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("eyJhbGci"));
    }

    #[test]
    fn test_query_param_redaction() {
        let config = RedactionConfig::default();
        let mut engine = RedactionEngine::new(config).unwrap();
        let mut stats = RedactionStats::new();

        let mut params = vec![QueryParam {
            name: "api_key".to_string(),
            value: "secret123".to_string(),
            comment: None,
        }];

        engine.redact_query_params(&mut params, &mut stats);
        assert_eq!(params[0].value, "[REDACTED]");
        assert_eq!(stats.query_params_redacted, 1);
    }

    #[test]
    fn test_cookie_redaction() {
        let config = RedactionConfig::default();
        let mut engine = RedactionEngine::new(config).unwrap();
        let mut stats = RedactionStats::new();

        let mut cookies = vec![Cookie {
            name: "session".to_string(),
            value: "abc123".to_string(),
            path: None,
            domain: None,
            expires: None,
            http_only: None,
            secure: None,
            comment: None,
        }];

        engine.redact_cookies(&mut cookies, &mut stats);
        assert_eq!(cookies[0].value, "[REDACTED]");
        assert_eq!(stats.cookies_redacted, 1);
    }

    #[test]
    fn test_custom_pattern() {
        let rule = RedactionRule::new("custom", r"SECRET_\d+")
            .with_replacement("[CUSTOM]")
            .with_scope(RedactionScope::Body);

        let config = RedactionConfig::builder()
            .add_custom_pattern(rule)
            .build()
            .unwrap();

        let mut engine = RedactionEngine::new(config).unwrap();
        let text = "The code is SECRET_12345";
        let redacted = engine.redact_patterns(text, RedactionScope::Body);
        assert!(redacted.contains("[CUSTOM]"));
        assert!(!redacted.contains("SECRET_12345"));
    }
}
