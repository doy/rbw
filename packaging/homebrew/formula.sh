#!/bin/sh
# Prints the Homebrew formula for a release, using the .sha256 files the
# release workflow leaves in DIST.
#
# usage: packaging/homebrew/formula.sh VERSION DIST > rbw-ng.rb
set -eu

version="$1"
dist="$2"
base="${RBW_NG_DOWNLOAD_BASE:-https://github.com/TimotheFCN/rbw-ng/releases/download/$version}"

sum() {
    cut -d' ' -f1 "$dist/rbw-ng-$version-$1.tar.gz.sha256"
}

asset() {
    printf '      url "%s/rbw-ng-%s-%s.tar.gz"\n' "$base" "$version" "$1"
    printf '      sha256 "%s"\n' "$(sum "$1")"
}

cat <<RUBY
class RbwNg < Formula
  desc "Unofficial Bitwarden CLI, a maintained continuation of rbw"
  homepage "https://github.com/TimotheFCN/rbw-ng"
  license "MIT"

  on_macos do
    on_arm do
$(asset aarch64-apple-darwin)
    end
    on_intel do
$(asset x86_64-apple-darwin)
    end
  end

  on_linux do
    on_arm do
$(asset aarch64-unknown-linux-musl)
    end
    on_intel do
$(asset x86_64-unknown-linux-musl)
    end
  end

  conflicts_with "rbw", because: "both install the \`rbw\` and \`rbw-agent\` binaries"

  def install
    bin.install "rbw", "rbw-agent"
    bash_completion.install "completion/bash" => "rbw"
    zsh_completion.install "completion/zsh" => "_rbw"
    fish_completion.install "completion/fish" => "rbw.fish"
  end

  def caveats
    on_macos do
      <<~EOS
        rbw asks for your master password through pinentry. To use the macOS
        dialog, install pinentry-mac and select it:
          brew install pinentry-mac
          rbw config set pinentry pinentry-mac
      EOS
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/rbw --version")
  end
end
RUBY
