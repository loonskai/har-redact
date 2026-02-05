use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionConfig {
    #[serde(default)]
    pub preserve_length: bool,

    #[serde(default)]
    pub hash_values: bool,

    #[serde(default)]
    pub strict_mode: bool,

    #[serde(default)]
    pub custom_patterns: Vec<RedactionRule>,

    #[serde(default = "default_true")]
    pub redact_emails: bool,

    #[serde(default = "default_true")]
    pub redact_phone_numbers: bool,

    #[serde(default = "default_false")]
    pub redact_ips: bool,

    #[serde(default = "default_true")]
    pub redact_cookies: bool,

    #[serde(default = "default_true")]
    pub redact_auth_headers: bool,

    #[serde(default = "default_true")]
    pub redact_auth_params: bool,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            preserve_length: false,
            hash_values: false,
            strict_mode: false,
            custom_patterns: Vec::new(),
            redact_emails: true,
            redact_phone_numbers: true,
            redact_ips: false,
            redact_cookies: true,
            redact_auth_headers: true,
            redact_auth_params: true,
        }
    }
}

impl RedactionConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content =
            fs::read_to_string(path.as_ref()).context("Failed to read configuration file")?;

        Self::from_yaml(&content)
    }

    pub fn from_yaml(yaml: &str) -> Result<Self> {
        serde_yaml::from_str(yaml).context("Failed to parse YAML configuration")
    }

    pub fn builder() -> RedactionConfigBuilder {
        RedactionConfigBuilder::default()
    }

    pub fn validate(&self) -> Result<()> {
        for rule in &self.custom_patterns {
            rule.validate()?;
        }
        Ok(())
    }
}

/// Builder for RedactionConfig
#[derive(Debug, Default)]
pub struct RedactionConfigBuilder {
    config: RedactionConfig,
}

impl RedactionConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn preserve_length(mut self, value: bool) -> Self {
        self.config.preserve_length = value;
        self
    }

    pub fn hash_values(mut self, value: bool) -> Self {
        self.config.hash_values = value;
        self
    }

    pub fn strict_mode(mut self, value: bool) -> Self {
        self.config.strict_mode = value;
        self
    }

    pub fn redact_emails(mut self, value: bool) -> Self {
        self.config.redact_emails = value;
        self
    }

    pub fn redact_phone_numbers(mut self, value: bool) -> Self {
        self.config.redact_phone_numbers = value;
        self
    }

    pub fn redact_ips(mut self, value: bool) -> Self {
        self.config.redact_ips = value;
        self
    }

    pub fn redact_cookies(mut self, value: bool) -> Self {
        self.config.redact_cookies = value;
        self
    }

    pub fn redact_auth_headers(mut self, value: bool) -> Self {
        self.config.redact_auth_headers = value;
        self
    }

    pub fn redact_auth_params(mut self, value: bool) -> Self {
        self.config.redact_auth_params = value;
        self
    }

    pub fn add_custom_pattern(mut self, rule: RedactionRule) -> Self {
        self.config.custom_patterns.push(rule);
        self
    }

    pub fn build(self) -> Result<RedactionConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RedactionScope {
    Headers,
    Body,
    Urls,
    Cookies,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionRule {
    pub name: String,

    pub pattern: String,

    #[serde(default = "default_replacement")]
    pub replacement: String,

    #[serde(default = "default_scope")]
    pub scope: RedactionScope,

    #[serde(default)]
    pub case_insensitive: bool,
}

fn default_replacement() -> String {
    "[REDACTED]".to_string()
}

fn default_scope() -> RedactionScope {
    RedactionScope::All
}

impl RedactionRule {
    pub fn new(name: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pattern: pattern.into(),
            replacement: default_replacement(),
            scope: default_scope(),
            case_insensitive: false,
        }
    }

    pub fn with_replacement(mut self, replacement: impl Into<String>) -> Self {
        self.replacement = replacement.into();
        self
    }

    pub fn with_scope(mut self, scope: RedactionScope) -> Self {
        self.scope = scope;
        self
    }

    pub fn case_insensitive(mut self) -> Self {
        self.case_insensitive = true;
        self
    }

    pub fn compile(&self) -> Result<Regex> {
        let pattern = if self.case_insensitive {
            format!("(?i){}", self.pattern)
        } else {
            self.pattern.clone()
        };

        Regex::new(&pattern)
            .with_context(|| format!("Failed to compile pattern for rule '{}'", self.name))
    }

    pub fn validate(&self) -> Result<()> {
        self.compile()?;
        Ok(())
    }

    pub fn applies_to(&self, scope: RedactionScope) -> bool {
        self.scope == RedactionScope::All || self.scope == scope
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RedactionConfig::default();
        assert!(config.redact_emails);
        assert!(config.redact_cookies);
        assert!(!config.preserve_length);
        assert!(!config.hash_values);
    }

    #[test]
    fn test_config_builder() {
        let config = RedactionConfig::builder()
            .preserve_length(true)
            .hash_values(true)
            .strict_mode(true)
            .build()
            .unwrap();

        assert!(config.preserve_length);
        assert!(config.hash_values);
        assert!(config.strict_mode);
    }

    #[test]
    fn test_redaction_rule_creation() {
        let rule = RedactionRule::new("test", r"\d{3}-\d{3}-\d{4}")
            .with_replacement("[PHONE]")
            .with_scope(RedactionScope::Body)
            .case_insensitive();

        assert_eq!(rule.name, "test");
        assert_eq!(rule.replacement, "[PHONE]");
        assert_eq!(rule.scope, RedactionScope::Body);
        assert!(rule.case_insensitive);
    }

    #[test]
    fn test_rule_compile() {
        let rule = RedactionRule::new("email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}");
        let regex = rule.compile();
        assert!(regex.is_ok());
    }

    #[test]
    fn test_rule_applies_to() {
        let all_rule = RedactionRule::new("test", "pattern").with_scope(RedactionScope::All);
        assert!(all_rule.applies_to(RedactionScope::Headers));
        assert!(all_rule.applies_to(RedactionScope::Body));

        let header_rule = RedactionRule::new("test", "pattern").with_scope(RedactionScope::Headers);
        assert!(header_rule.applies_to(RedactionScope::Headers));
        assert!(!header_rule.applies_to(RedactionScope::Body));
    }

    #[test]
    fn test_config_from_yaml() {
        let yaml = r#"
preserve_length: true
hash_values: false
strict_mode: true
redact_emails: true
custom_patterns:
  - name: "custom"
    pattern: "secret"
    replacement: "[SECRET]"
    scope: "body"
"#;

        let config = RedactionConfig::from_yaml(yaml).unwrap();
        assert!(config.preserve_length);
        assert!(!config.hash_values);
        assert!(config.strict_mode);
        assert_eq!(config.custom_patterns.len(), 1);
        assert_eq!(config.custom_patterns[0].name, "custom");
    }
}
