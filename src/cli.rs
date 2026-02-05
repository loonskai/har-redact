use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "har-redact",
    version,
    about = "Redact sensitive information from HAR files",
    long_about = "A tool to sanitize/redact sensitive information from HTTP Archive (HAR) files.\n\
                  Removes tokens, credentials, cookies, PII, and other sensitive data while preserving\n\
                  the structure and useful information for debugging and analysis."
)]
pub struct Cli {
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    #[arg(short, long, value_name = "OUTPUT")]
    pub output: Option<PathBuf>,

    #[arg(short, long, value_name = "CONFIG")]
    pub config: Option<PathBuf>,

    #[arg(long)]
    pub preserve_length: bool,

    #[arg(long)]
    pub hash_values: bool,

    #[arg(long)]
    pub strict: bool,

    #[arg(long)]
    pub summary: bool,

    #[arg(long)]
    pub dry_run: bool,

    #[arg(long)]
    pub no_redact_emails: bool,

    #[arg(long)]
    pub no_redact_phone_numbers: bool,

    #[arg(long)]
    pub redact_ips: bool,

    #[arg(long)]
    pub no_redact_cookies: bool,

    #[arg(long)]
    pub no_redact_auth_headers: bool,

    #[arg(long)]
    pub no_redact_auth_params: bool,

    #[arg(short = 'f', long, value_enum, default_value = "json")]
    pub format: OutputFormat,

    #[arg(long)]
    pub pretty: bool,

    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Json,
    Compact,
}

impl Cli {
    pub fn validate(&self) -> Result<(), String> {
        if !self.input.exists() {
            return Err(format!("Input file does not exist: {:?}", self.input));
        }

        if !self.input.is_file() {
            return Err(format!("Input path is not a file: {:?}", self.input));
        }

        if let Some(config) = &self.config {
            if !config.exists() {
                return Err(format!("Config file does not exist: {:?}", config));
            }
            if !config.is_file() {
                return Err(format!("Config path is not a file: {:?}", config));
            }
        }

        if let Some(output) = &self.output {
            if let Some(parent) = output.parent() {
                if !parent.exists() {
                    return Err(format!("Output directory does not exist: {:?}", parent));
                }
            }
        }

        if self.preserve_length && self.hash_values {
            return Err("Cannot use both --preserve-length and --hash-values together".to_string());
        }

        Ok(())
    }

    pub fn use_stdout(&self) -> bool {
        self.output.is_none()
    }

    pub fn should_pretty_print(&self) -> bool {
        match self.format {
            OutputFormat::Json => self.pretty || self.use_stdout(),
            OutputFormat::Compact => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        // Basic command
        let cli = Cli::try_parse_from(["har-redact", "test.har"]);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        assert_eq!(cli.input, PathBuf::from("test.har"));
        assert!(!cli.preserve_length);
        assert!(!cli.hash_values);
    }

    #[test]
    fn test_cli_with_options() {
        let cli = Cli::try_parse_from([
            "har-redact",
            "input.har",
            "-o",
            "output.har",
            "--preserve-length",
            "--summary",
        ]);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        assert_eq!(cli.input, PathBuf::from("input.har"));
        assert_eq!(cli.output, Some(PathBuf::from("output.har")));
        assert!(cli.preserve_length);
        assert!(cli.summary);
    }

    #[test]
    fn test_output_format() {
        let cli = Cli::try_parse_from(["har-redact", "test.har", "-f", "compact"]);
        assert!(cli.is_ok());

        let cli = cli.unwrap();
        assert!(matches!(cli.format, OutputFormat::Compact));
    }

    #[test]
    fn test_use_stdout() {
        let cli_no_output = Cli::try_parse_from(["har-redact", "test.har"]).unwrap();
        assert!(cli_no_output.use_stdout());

        let cli_with_output =
            Cli::try_parse_from(["har-redact", "test.har", "-o", "output.har"]).unwrap();
        assert!(!cli_with_output.use_stdout());
    }

    #[test]
    fn test_should_pretty_print() {
        // Default (JSON to stdout) should pretty print
        let cli = Cli::try_parse_from(["har-redact", "test.har"]).unwrap();
        assert!(cli.should_pretty_print());

        // Compact format should not pretty print
        let cli = Cli::try_parse_from(["har-redact", "test.har", "-f", "compact"]).unwrap();
        assert!(!cli.should_pretty_print());

        // Explicit pretty flag
        let cli =
            Cli::try_parse_from(["har-redact", "test.har", "-o", "out.har", "--pretty"]).unwrap();
        assert!(cli.should_pretty_print());
    }
}
