# typed: true
# frozen_string_literal: true
#
# Formula/pkg-defender.rb
#
# Homebrew formula for pkg-defender.
#
# This is a custom tap formula (not in Homebrew/core).
# Install with:
#   brew tap divisionseven/pkg-defender
#   brew install pkg-defender
#
# SHA256 values must be updated per-release.
# Run: shasum -a 256 dist/pkgd-<platform>
#

class PkgDefender < Formula
  desc "Supply chain attack defense CLI — Stop malicious packages BEFORE they reach your machine or CI pipeline"
  homepage "https://github.com/divisionseven/pkg-defender"
  license "Apache-2.0"
  version "1.0.0"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/divisionseven/pkg-defender/releases/download/v1.0.0/pkgd-darwin-arm64"
    sha256 "PLACEHOLDER_"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/divisionseven/pkg-defender/releases/download/v1.0.0/pkgd-darwin-amd64"
    sha256 "PLACEHOLDER_"
  elsif OS.linux?
    url "https://github.com/divisionseven/pkg-defender/releases/download/v1.0.0/pkgd-linux-amd64"
    sha256 "PLACEHOLDER_"
  end

  def install
    binary = if OS.mac? && Hardware::CPU.arm?
      "pkgd-darwin-arm64"
    elsif OS.mac? && Hardware::CPU.intel?
      "pkgd-darwin-amd64"
    else
      "pkgd-linux-amd64"
    end
    bin.install binary => "pkgd"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pkgd --version")
  end
end
