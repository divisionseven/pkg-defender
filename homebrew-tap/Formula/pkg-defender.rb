# typed: true
# frozen_string_literal: true

#
# Formula/pkg-defender.rb
#
# Homebrew formula for pkg-defender.
# Tap: divisionseven/homebrew-pkg-defender
# Install with:
#   brew tap divisionseven/pkg-defender
#   brew install pkg-defender
#
# SHA256 values are placeholders; the release workflow auto-replaces them.
#

class PkgDefender < Formula
  desc "Supply chain attack defense CLI — Stop malicious packages BEFORE they reach your machine or CI pipeline"
  homepage "https://github.com/divisionseven/pkg-defender"
  version "1.0.0"
  license "Apache-2.0"

  livecheck do
    url :stable
    strategy :github_latest
  end

  on_macos do
    on_arm do
      url "https://github.com/divisionseven/pkg-defender/releases/download/v1.0.0/pkgd-darwin-arm64"
      sha256 "placeholder_"

      define_method(:install) do
        bin.install "pkgd-darwin-arm64" => "pkgd"
      end
    end

    on_intel do
      url "https://github.com/divisionseven/pkg-defender/releases/download/v1.0.0/pkgd-darwin-amd64"
      sha256 "placeholder_"

      define_method(:install) do
        bin.install "pkgd-darwin-amd64" => "pkgd"
      end
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/divisionseven/pkg-defender/releases/download/v1.0.0/pkgd-linux-amd64"
      sha256 "placeholder_"

      define_method(:install) do
        bin.install "pkgd-linux-amd64" => "pkgd"
      end
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pkgd --version")
  end
end
