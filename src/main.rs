mod cli;
mod config;
mod har;
mod redactor;

use anyhow::{Context, Result};
use clap::Parser;
use cli::Cli;
use config::RedactionConfig;
use har::HarFile;
use redactor::RedactionEngine;
use std::fs;
use std::io::{self, Write};

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    cli.validate()
        .map_err(|e| anyhow::anyhow!("Invalid arguments: {}", e))?;

    if cli.verbose {
        eprintln!("Reading HAR file: {:?}", cli.input);
    }

    let input_data = fs::read_to_string(&cli.input)
        .with_context(|| format!("Failed to read input file: {:?}", cli.input))?;

    let mut har: HarFile = serde_json::from_str(&input_data)
        .context("Failed to parse HAR file - invalid JSON or HAR format")?;

    if cli.verbose {
        eprintln!("Parsed HAR file with {} entries", har.log.entries.len());
    }

    let mut config = if let Some(config_path) = &cli.config {
        if cli.verbose {
            eprintln!("Loading configuration from: {:?}", config_path);
        }
        RedactionConfig::from_file(config_path)
            .with_context(|| format!("Failed to load config file: {:?}", config_path))?
    } else {
        RedactionConfig::default()
    };
    if cli.preserve_length {
        config.preserve_length = true;
    }
    if cli.hash_values {
        config.hash_values = true;
    }
    if cli.strict {
        config.strict_mode = true;
    }
    if cli.no_redact_emails {
        config.redact_emails = false;
    }
    if cli.no_redact_phone_numbers {
        config.redact_phone_numbers = false;
    }
    if cli.redact_ips {
        config.redact_ips = true;
    }
    if cli.no_redact_cookies {
        config.redact_cookies = false;
    }
    if cli.no_redact_auth_headers {
        config.redact_auth_headers = false;
    }
    if cli.no_redact_auth_params {
        config.redact_auth_params = false;
    }

    if cli.verbose {
        eprintln!("Configuration:");
        eprintln!("  - Preserve length: {}", config.preserve_length);
        eprintln!("  - Hash values: {}", config.hash_values);
        eprintln!("  - Strict mode: {}", config.strict_mode);
        eprintln!("  - Redact emails: {}", config.redact_emails);
        eprintln!("  - Redact phone numbers: {}", config.redact_phone_numbers);
        eprintln!("  - Redact IPs: {}", config.redact_ips);
        eprintln!("  - Redact cookies: {}", config.redact_cookies);
        eprintln!("  - Redact auth headers: {}", config.redact_auth_headers);
        eprintln!("  - Redact auth params: {}", config.redact_auth_params);
    }

    let mut engine =
        RedactionEngine::new(config).context("Failed to initialize redaction engine")?;

    if cli.verbose {
        eprintln!("Starting redaction process...");
    }

    let stats = if cli.dry_run {
        let mut har_clone = har.clone();
        engine
            .redact_har(&mut har_clone)
            .context("Failed to perform dry run")?
    } else {
        engine
            .redact_har(&mut har)
            .context("Failed to redact HAR file")?
    };

    if cli.verbose || cli.summary {
        eprintln!("\nRedaction Summary:");
        eprintln!("  - Headers redacted: {}", stats.headers_redacted);
        eprintln!("  - Cookies redacted: {}", stats.cookies_redacted);
        eprintln!(
            "  - Query parameters redacted: {}",
            stats.query_params_redacted
        );
        eprintln!("  - Bodies redacted: {}", stats.bodies_redacted);
        eprintln!("  - URLs redacted: {}", stats.urls_redacted);
        eprintln!("  - Total redactions: {}", stats.total_redactions);
    }

    if engine.config().strict_mode && stats.total_redactions == 0 {
        if cli.verbose {
            eprintln!("Warning: Strict mode enabled but no redactions found");
        }
    }
    if cli.dry_run {
        if cli.verbose {
            eprintln!("\nDry run complete. No changes written.");
        }
        return Ok(());
    }

    let output_json = if cli.should_pretty_print() {
        serde_json::to_string_pretty(&har).context("Failed to serialize redacted HAR file")?
    } else {
        serde_json::to_string(&har).context("Failed to serialize redacted HAR file")?
    };
    if let Some(output_path) = &cli.output {
        if cli.verbose {
            eprintln!("Writing output to: {:?}", output_path);
        }
        fs::write(output_path, output_json)
            .with_context(|| format!("Failed to write output file: {:?}", output_path))?;
        if cli.verbose {
            eprintln!("Output written successfully");
        }
    } else {
        io::stdout()
            .write_all(output_json.as_bytes())
            .context("Failed to write to stdout")?;
        io::stdout()
            .write_all(b"\n")
            .context("Failed to write newline to stdout")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let version = env!("CARGO_PKG_VERSION");
        assert!(!version.is_empty());
    }
}
