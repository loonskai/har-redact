# HAR Redaction Tool

A high-performance Rust tool for sanitizing sensitive information from HTTP Archive (HAR) files. Redacts tokens, credentials, cookies, PII (Personally Identifiable Information), and other sensitive data while preserving the structure and useful debugging information.

## Features

- **Comprehensive Redaction**: Automatically redacts common sensitive patterns:
  - Authorization headers (Bearer tokens, Basic auth, API keys)
  - Authentication cookies
  - Query parameters (api_key, token, secret, password, etc.)
  - JWT tokens
  - Email addresses
  - Phone numbers
  - Credit card numbers
  - IP addresses (optional)

- **Flexible Configuration**:
  - YAML-based configuration files
  - Custom regex patterns with scoping
  - CLI flags for common options

- **Multiple Redaction Strategies**:
  - Complete redaction: `[REDACTED]`
  - Length preservation: `[REDACTED:12]`
  - Value hashing for correlation: `[HASH:e861b2eab679927c]`

- **Safe and Fast**:
  - Written in Rust for memory safety and performance
  - Preserves HAR structure and field order
  - Proper error handling with helpful messages

## Installation

```bash
# Build from source
cargo build --release

# The binary will be at target/release/har-redact
```

## Usage

### Basic Usage

```bash
# Redact a HAR file and write to stdout
har-redact input.har

# Redact and save to a file
har-redact input.har -o output.har

# Show redaction summary
har-redact input.har --summary
```

### Advanced Options

```bash
# Use custom configuration
har-redact input.har --config config.yaml

# Preserve length of redacted values
har-redact input.har --preserve-length

# Hash values for correlation
har-redact input.har --hash-values

# Dry run to see what would be redacted
har-redact input.har --dry-run --summary

# Verbose output
har-redact input.har -v
```

### CLI Options

```
Usage: har-redact [OPTIONS] <INPUT>

Arguments:
  <INPUT>  Input HAR file path

Options:
  -o, --output <OUTPUT>              Output file path (writes to stdout if not specified)
  -c, --config <CONFIG>              Configuration file path (YAML format)
      --preserve-length              Preserve length of redacted values (e.g., [REDACTED:12])
      --hash-values                  Hash values for correlation instead of complete redaction
      --strict                       Strict mode: fail on suspicious patterns
      --summary                      Show redaction summary after processing
      --dry-run                      Dry run: show what would be redacted without making changes
      --no-redact-emails             Disable email redaction
      --no-redact-phone-numbers      Disable phone number redaction
      --redact-ips                   Enable IP address redaction
      --no-redact-cookies            Disable cookie redaction
      --no-redact-auth-headers       Disable Authorization header redaction
      --no-redact-auth-params        Disable authentication query parameter redaction
  -f, --format <FORMAT>              Output format [default: json] [possible values: json, compact]
      --pretty                       Pretty-print JSON output
  -v, --verbose                      Verbose output (show detailed processing information)
  -h, --help                         Print help
  -V, --version                      Print version
```

## Configuration File

Create a YAML configuration file to customize redaction behavior:

```yaml
# Preserve the length of redacted values (e.g., [REDACTED:12])
preserve_length: false

# Hash values for correlation instead of complete redaction
hash_values: false

# Fail on suspicious patterns (strict mode)
strict_mode: false

# Built-in redaction options
redact_emails: true
redact_phone_numbers: true
redact_ips: false
redact_cookies: true
redact_auth_headers: true
redact_auth_params: true

# Custom redaction patterns
custom_patterns:
  # Redact Social Security Numbers
  - name: "SSN"
    pattern: '\b\d{3}-\d{2}-\d{4}\b'
    replacement: "[SSN-REDACTED]"
    scope: "all"
    case_insensitive: false

  # Redact AWS access keys
  - name: "AWS Access Key"
    pattern: 'AKIA[0-9A-Z]{16}'
    replacement: "[AWS-KEY-REDACTED]"
    scope: "all"
    case_insensitive: false

  # Redact Stripe API keys
  - name: "Stripe API Key"
    pattern: 'sk_live_[0-9a-zA-Z]{24,}'
    replacement: "[STRIPE-KEY-REDACTED]"
    scope: "all"
    case_insensitive: false

  # Redact passwords in JSON
  - name: "Password Field"
    pattern: '"password"\s*:\s*"[^"]*"'
    replacement: '"password":"[REDACTED]"'
    scope: "body"
    case_insensitive: false
```

### Scope Options

Custom patterns can be scoped to specific parts of the HAR file:

- `all`: Apply everywhere (default)
- `headers`: Apply only to HTTP headers
- `body`: Apply only to request/response bodies
- `urls`: Apply only to URLs and query parameters
- `cookies`: Apply only to cookies

### Replacement Placeholders

Custom replacements support placeholders:

- `{hash}`: Insert SHA256 hash of the matched value
- `{length}`: Insert length of the matched value

Example:
```yaml
custom_patterns:
  - name: "API Key with Hash"
    pattern: 'api_key_[a-zA-Z0-9]+'
    replacement: "[API-KEY:{hash}]"
    scope: "all"
```

## Examples

### Example 1: Basic Redaction

Input HAR:
```json
{
  "log": {
    "entries": [{
      "request": {
        "headers": [
          {"name": "Authorization", "value": "Bearer secret_token_123"}
        ],
        "cookies": [
          {"name": "session", "value": "abc123xyz"}
        ]
      }
    }]
  }
}
```

Output:
```json
{
  "log": {
    "entries": [{
      "request": {
        "headers": [
          {"name": "Authorization", "value": "[REDACTED]"}
        ],
        "cookies": [
          {"name": "session", "value": "[REDACTED]"}
        ]
      }
    }]
  }
}
```

### Example 2: Length Preservation

```bash
har-redact input.har --preserve-length
```

Output:
```json
{
  "headers": [
    {"name": "Authorization", "value": "[REDACTED:18]"}
  ]
}
```

### Example 3: Value Hashing

```bash
har-redact input.har --hash-values
```

Output:
```json
{
  "headers": [
    {"name": "Authorization", "value": "[HASH:e861b2eab679927c]"}
  ]
}
```

This allows correlation of the same values across multiple requests while maintaining anonymity.

## Architecture

The tool is structured into four main modules:

### `src/har.rs`
Defines HAR format structs following the HAR 1.2 specification:
- Full HAR structure with proper serde serialization
- Preserves field order with `serde_json` preserve_order feature
- Optional fields using `Option<T>`

### `src/config.rs`
Configuration management:
- `RedactionConfig` struct with builder pattern
- `RedactionRule` for custom patterns with regex compilation
- YAML file support via `serde_yaml`
- Validation and error handling

### `src/redactor.rs`
Core redaction engine:
- Pattern matching with compiled regex (via `lazy_static`)
- Efficient redaction with minimal cloning
- Statistics tracking
- Built-in patterns for common sensitive data

### `src/cli.rs`
Command-line interface:
- Argument parsing with `clap` derive macros
- Validation and helpful error messages
- Multiple output formats

## Built-in Patterns

The tool automatically detects and redacts:

1. **Authorization Headers**:
   - `Authorization`, `X-API-Key`, `X-Auth-Token`, `X-CSRF-Token`
   - `API-Key`, `Auth-Token`, `Access-Token`, `Session-ID`

2. **Authentication Patterns**:
   - Bearer tokens: `Bearer <token>`
   - Basic auth: `Basic <base64>`
   - JWT tokens: `eyJ...` format

3. **Query Parameters**:
   - `api_key`, `apikey`, `token`, `access_token`
   - `secret`, `password`, `pwd`, `session`, `auth`

4. **PII**:
   - Email addresses (RFC 5322 compliant)
   - Phone numbers (various formats including international)
   - Credit card numbers (Visa, MasterCard, Amex, etc.)

5. **Network**:
   - IPv4 addresses (optional)

## Testing

The tool includes comprehensive unit tests:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run a specific test
cargo test test_redact_header
```

Example test HAR file is provided in `tests/sample.har`.

## Performance

Built with Rust for:
- **Memory Safety**: No buffer overflows or use-after-free bugs
- **Performance**: Zero-cost abstractions and efficient regex
- **Concurrency**: Safe concurrent processing (future enhancement)

## Safety Considerations

- The tool always redacts JWT tokens and credit card numbers, even if configured otherwise
- Strict mode can be enabled to fail if no redactions are found (useful for validation)
- Dry run mode allows previewing changes before committing
- Original files are never modified in place

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please ensure:
- Code passes `cargo fmt` and `cargo clippy`
- All tests pass with `cargo test`
- New features include tests and documentation

## Future Enhancements

- [ ] Streaming support for very large HAR files
- [ ] Parallel processing of entries
- [ ] Additional output formats (YAML, CSV)
- [ ] Redaction reports in multiple formats
- [ ] Interactive mode for selective redaction
- [ ] HAR file merging and splitting
- [ ] Support for HAR 1.3+ extensions
