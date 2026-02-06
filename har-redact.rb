class HarRedact < Formula
  desc "A tool to sanitize/redact sensitive information from HAR files"
  homepage "https://github.com/loonskai/har-redact"
  url "https://github.com/loonskai/har-redact/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "SHA256_HASH_HERE"
  license "MIT" # Update with your license

  depends_on "rust" => :build

  def install
    system "cargo", "install", "--locked", "--root", prefix, "--path", "."
  end

  test do
    system "#{bin}/har-redact", "--version"
  end
end
