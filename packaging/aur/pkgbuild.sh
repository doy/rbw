#!/bin/sh
# Prints the PKGBUILD of the rbw-ng-bin AUR package for a release, using the
# .sha256 files the release workflow leaves in DIST.
#
# usage: packaging/aur/pkgbuild.sh VERSION DIST > PKGBUILD
set -eu

version="$1"
dist="$2"

sum() {
    cut -d' ' -f1 "$dist/rbw-ng-$version-$1-unknown-linux-musl.tar.gz.sha256"
}

cat <<PKGBUILD
# Maintainer: Timothe F <https://github.com/TimotheFCN>
pkgname=rbw-ng-bin
pkgver=$version
pkgrel=1
pkgdesc="Unofficial Bitwarden CLI, a maintained continuation of rbw"
arch=('x86_64' 'aarch64')
url="https://github.com/TimotheFCN/rbw-ng"
license=('MIT')
depends=('pinentry')
provides=("rbw=\$pkgver")
conflicts=('rbw')
options=('!debug')
source_x86_64=("\$url/releases/download/\$pkgver/rbw-ng-\$pkgver-x86_64-unknown-linux-musl.tar.gz")
source_aarch64=("\$url/releases/download/\$pkgver/rbw-ng-\$pkgver-aarch64-unknown-linux-musl.tar.gz")
sha256sums_x86_64=('$(sum x86_64)')
sha256sums_aarch64=('$(sum aarch64)')

package() {
  cd "rbw-ng-\$pkgver-\$CARCH-unknown-linux-musl"
  install -Dm755 rbw rbw-agent -t "\$pkgdir/usr/bin/"
  install -Dm644 completion/bash "\$pkgdir/usr/share/bash-completion/completions/rbw"
  install -Dm644 completion/zsh "\$pkgdir/usr/share/zsh/site-functions/_rbw"
  install -Dm644 completion/fish "\$pkgdir/usr/share/fish/vendor_completions.d/rbw.fish"
  install -Dm644 LICENSE "\$pkgdir/usr/share/licenses/\$pkgname/LICENSE"
}
PKGBUILD
