# HAR Redaction Examples

This document shows examples of the HAR redaction tool in action.

## Example 1: Authorization Header Redaction

### Before
```json
{
  "headers": [
    {
      "name": "Authorization",
      "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
    }
  ]
}
```

### After (Default)
```json
{
  "headers": [
    {
      "name": "Authorization",
      "value": "[REDACTED]"
    }
  ]
}
```

### After (--preserve-length)
```json
{
  "headers": [
    {
      "name": "Authorization",
      "value": "[REDACTED:74]"
    }
  ]
}
```

### After (--hash-values)
```json
{
  "headers": [
    {
      "name": "Authorization",
      "value": "[HASH:e861b2eab679927c]"
    }
  ]
}
```

## Example 2: Cookie Redaction

### Before
```json
{
  "cookies": [
    {
      "name": "session_id",
      "value": "abc123def456",
      "httpOnly": true,
      "secure": true
    },
    {
      "name": "user_token",
      "value": "xyz789",
      "httpOnly": false
    }
  ]
}
```

### After
```json
{
  "cookies": [
    {
      "name": "session_id",
      "value": "[REDACTED]",
      "httpOnly": true,
      "secure": true
    },
    {
      "name": "user_token",
      "value": "[REDACTED]",
      "httpOnly": false
    }
  ]
}
```

## Example 3: Query Parameter Redaction

### Before
```json
{
  "url": "https://api.example.com/users?api_key=sk_live_51234567890abcdefghijk&user_id=12345",
  "queryString": [
    {
      "name": "api_key",
      "value": "sk_live_51234567890abcdefghijk"
    },
    {
      "name": "user_id",
      "value": "12345"
    }
  ]
}
```

### After
```json
{
  "url": "https://api.example.com/users?api_key=sk_live_51234567890abcdefghijk&user_id=12345",
  "queryString": [
    {
      "name": "api_key",
      "value": "[REDACTED]"
    },
    {
      "name": "user_id",
      "value": "12345"
    }
  ]
}
```

Note: Only sensitive parameter names (api_key, token, secret, password, etc.) are redacted by default.

## Example 4: PII Redaction in Response Body

### Before
```json
{
  "content": {
    "text": "{\"user\":{\"id\":12345,\"email\":\"john.doe@example.com\",\"phone\":\"+1-555-123-4567\",\"credit_card\":\"4532015112830366\"}}"
  }
}
```

### After
```json
{
  "content": {
    "text": "{\"user\":{\"id\":12345,\"email\":\"[REDACTED]\",\"phone\":\"+[REDACTED]\",\"credit_card\":\"[REDACTED]\"}}"
  }
}
```

## Example 5: POST Data Redaction

### Before
```json
{
  "postData": {
    "mimeType": "application/json",
    "text": "{\"username\":\"user@company.com\",\"password\":\"MySecretPassword123!\",\"phone\":\"555-987-6543\"}"
  }
}
```

### After
```json
{
  "postData": {
    "mimeType": "application/json",
    "text": "{\"username\":\"[REDACTED]\",\"password\":\"MySecretPassword123!\",\"phone\":\"[REDACTED]\"}"
  }
}
```

## Example 6: Custom Pattern Redaction

### Config File (config.yaml)
```yaml
custom_patterns:
  - name: "SSN"
    pattern: '\b\d{3}-\d{2}-\d{4}\b'
    replacement: "[SSN-REDACTED]"
    scope: "all"
```

### Before
```json
{
  "text": "{\"profile\":{\"email\":\"jane.smith@company.org\",\"ssn\":\"123-45-6789\"}}"
}
```

### After
```bash
har-redact input.har --config config.yaml
```

```json
{
  "text": "{\"profile\":{\"email\":\"[REDACTED]\",\"ssn\":\"[SSN-REDACTED]\"}}"
}
```

## Example 7: Dry Run

```bash
$ har-redact tests/sample.har --dry-run --summary
```

Output:
```
Redaction Summary:
  - Headers redacted: 4
  - Cookies redacted: 4
  - Query parameters redacted: 3
  - Bodies redacted: 4
  - URLs redacted: 0
  - Total redactions: 15

Dry run complete. No changes written.
```

## Example 8: Verbose Output

```bash
$ har-redact tests/sample.har -o output.har --verbose --summary
```

Output:
```
Reading HAR file: "tests/sample.har"
Parsed HAR file with 3 entries
Configuration:
  - Preserve length: false
  - Hash values: false
  - Strict mode: false
  - Redact emails: true
  - Redact phone numbers: true
  - Redact IPs: false
  - Redact cookies: true
  - Redact auth headers: true
  - Redact auth params: true
Starting redaction process...

Redaction Summary:
  - Headers redacted: 4
  - Cookies redacted: 4
  - Query parameters redacted: 3
  - Bodies redacted: 4
  - URLs redacted: 0
  - Total redactions: 15
Writing output to: "output.har"
Output written successfully
```

## Example 9: Hash Values for Correlation

When you need to correlate values across multiple requests while maintaining anonymity:

```bash
$ har-redact input.har --hash-values
```

### Before
```json
{
  "entries": [
    {
      "request": {
        "cookies": [{"name": "session", "value": "abc123"}]
      }
    },
    {
      "request": {
        "cookies": [{"name": "session", "value": "abc123"}]
      }
    }
  ]
}
```

### After
```json
{
  "entries": [
    {
      "request": {
        "cookies": [{"name": "session", "value": "[HASH:e861b2eab679927c]"}]
      }
    },
    {
      "request": {
        "cookies": [{"name": "session", "value": "[HASH:e861b2eab679927c]"}]
      }
    }
  ]
}
```

Notice that the same value produces the same hash, allowing correlation analysis.

## Example 10: Selective Redaction

Disable specific redaction types:

```bash
$ har-redact input.har --no-redact-emails --no-redact-phone-numbers
```

This will redact auth tokens and cookies but preserve email addresses and phone numbers.

## Example 11: Complete Real-World Example

```bash
# Full command with all options
$ har-redact \
    network-trace.har \
    --config my-config.yaml \
    --output sanitized.har \
    --preserve-length \
    --summary \
    --verbose
```

This command:
1. Reads `network-trace.har`
2. Applies custom rules from `my-config.yaml`
3. Preserves lengths of redacted values
4. Shows verbose processing info
5. Displays summary statistics
6. Writes output to `sanitized.har`

## Built-in Patterns Summary

The tool automatically redacts:

| Category | Examples |
|----------|----------|
| **Headers** | Authorization, X-API-Key, X-Auth-Token, X-CSRF-Token, API-Key, Auth-Token, Access-Token, Session-ID |
| **Tokens** | Bearer tokens, Basic auth, JWT tokens (eyJ...) |
| **Query Params** | api_key, apikey, token, access_token, secret, password, pwd, session, auth |
| **PII** | Email addresses, Phone numbers (various formats) |
| **Financial** | Credit card numbers (Visa, MC, Amex, Discover) |
| **Network** | IPv4 addresses (optional, use --redact-ips) |

## Tips

1. **Always test with --dry-run first** to see what will be redacted
2. **Use --summary** to get statistics about redactions
3. **Use --hash-values** when you need to correlate values across requests
4. **Use --preserve-length** when the length of values is important for analysis
5. **Create custom patterns** for domain-specific sensitive data
6. **Use scoping** in custom patterns to avoid over-redaction
7. **Keep original files** as backups before running redaction
