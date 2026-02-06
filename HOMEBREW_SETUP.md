# Homebrew Installation Setup

This guide will help you make `har-redact` installable via Homebrew.

## Quick Setup Steps

### 1. Create a GitHub Release

First, create a release on GitHub:

```bash
# Tag and push a release
git tag v0.1.0
git push origin v0.1.0
```

Then go to your GitHub repository and create a release from this tag.

### 2. Get the SHA256 Hash

After creating the release, GitHub automatically creates a source tarball. Get its SHA256:

```bash
# Get the SHA256 hash for the release
curl -L https://github.com/loonskai/har-redact/archive/refs/tags/v0.1.0.tar.gz | shasum -a 256
```

### 3. Create a Homebrew Tap Repository

Create a new GitHub repository named `homebrew-tap` (or `homebrew-<anything>`).

```bash
# Clone your new tap repository
git clone git@github.com:loonskai/homebrew-tap.git
cd homebrew-tap

# Copy the formula file
cp /path/to/har-redact/har-redact.rb Formula/har-redact.rb

# Update the formula with:
# - The correct SHA256 hash
# - Your license type

# Commit and push
git add Formula/har-redact.rb
git commit -m "Add har-redact formula"
git push
```

### 4. Install via Homebrew

Now anyone can install your tool:

```bash
# Add your tap
brew tap loonskai/tap

# Install the tool
brew install har-redact

# Now you can run it from anywhere
har-redact --help
```

## Updating the Formula for New Releases

When you release a new version:

1. Create a new GitHub release with a new tag (e.g., `v0.2.0`)
2. Get the SHA256 of the new tarball
3. Update `Formula/har-redact.rb` in your tap repository:
   - Change the `url` to the new version
   - Update the `sha256` hash
   - Update the version number if specified
4. Commit and push the changes

Users can then upgrade:
```bash
brew update
brew upgrade har-redact
```

## Formula Template Reference

The included `har-redact.rb` file is a template. You need to:

1. Replace `SHA256_HASH_HERE` with the actual SHA256 hash
2. Update the `license` field with your project's license

## Alternative: Local Testing

Before publishing, you can test the formula locally:

```bash
# Install from the local formula file
brew install --build-from-source ./har-redact.rb

# Test it works
har-redact --version

# Uninstall when done testing
brew uninstall har-redact
```

## Submitting to Homebrew Core (Optional)

If your project becomes popular, you can submit to the main Homebrew repository:

1. Your project should be stable with multiple releases
2. Have good documentation and tests
3. Follow the [Homebrew acceptable formulae guidelines](https://docs.brew.sh/Acceptable-Formulae)
4. Submit a PR to [homebrew-core](https://github.com/Homebrew/homebrew-core)

For most projects, a custom tap is sufficient and easier to maintain.
