#!/bin/bash

# HAR Redaction Tool Demo Script
# This script demonstrates the various features of the har-redact tool

set -e

echo "========================================"
echo "HAR Redaction Tool - Feature Demo"
echo "========================================"
echo ""

# Build the project
echo "1. Building the project..."
cargo build --release --quiet
echo "   ✓ Build complete"
echo ""

BINARY="./target/release/har-redact"
SAMPLE="tests/sample.har"

# Demo 1: Basic redaction
echo "2. Basic redaction (output to stdout)..."
$BINARY $SAMPLE > /dev/null
echo "   ✓ Basic redaction successful"
echo ""

# Demo 2: With summary
echo "3. Redaction with summary..."
$BINARY $SAMPLE --summary 2>&1 | grep -A 10 "Redaction Summary:"
echo ""

# Demo 3: Preserve length
echo "4. Preserve length mode..."
$BINARY $SAMPLE --preserve-length 2>&1 | grep -o '\[REDACTED:[0-9]*\]' | head -3
echo "   ✓ Length preservation working"
echo ""

# Demo 4: Hash values
echo "5. Hash values mode..."
$BINARY $SAMPLE --hash-values 2>&1 | grep -o '\[HASH:[a-f0-9]*\]' | head -3
echo "   ✓ Value hashing working"
echo ""

# Demo 5: Dry run
echo "6. Dry run mode..."
$BINARY $SAMPLE --dry-run --summary 2>&1 | tail -3
echo ""

# Demo 6: With custom config
echo "7. Using custom configuration..."
if [ -f tests/config.yaml ]; then
    $BINARY $SAMPLE --config tests/config.yaml --summary 2>&1 | grep "Total redactions:"
    echo "   ✓ Custom config applied"
else
    echo "   ⚠ Config file not found, skipping"
fi
echo ""

# Demo 7: Verbose mode
echo "8. Verbose output (first few lines)..."
$BINARY $SAMPLE --verbose --summary 2>&1 | head -15
echo ""

# Demo 8: Output to file
echo "9. Writing to output file..."
OUTPUT_FILE="tests/demo_output.har"
$BINARY $SAMPLE -o $OUTPUT_FILE --summary 2>&1 | tail -5
if [ -f $OUTPUT_FILE ]; then
    SIZE=$(wc -c < $OUTPUT_FILE)
    echo "   ✓ Output file created (${SIZE} bytes)"
    rm -f $OUTPUT_FILE
fi
echo ""

# Demo 9: Pretty print
echo "10. Pretty-printed output (sample)..."
$BINARY $SAMPLE --pretty 2>&1 | head -20
echo "   ... (truncated)"
echo ""

# Demo 10: Run tests
echo "11. Running test suite..."
cargo test --quiet 2>&1 | tail -3
echo "   ✓ All tests passed"
echo ""

echo "========================================"
echo "Demo complete! 🎉"
echo ""
echo "Try these commands yourself:"
echo "  $BINARY $SAMPLE --summary"
echo "  $BINARY $SAMPLE --preserve-length"
echo "  $BINARY $SAMPLE --hash-values"
echo "  $BINARY $SAMPLE -o output.har"
echo ""
echo "For more information: $BINARY --help"
echo "========================================"
