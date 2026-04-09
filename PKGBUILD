# Maintainer: Secfacts Team <team@secfacts.org>
pkgname=secfacts
pkgver=1.0.0
pkgrel=1
pkgdesc="High-performance security evidence normalization & correlation engine"
arch=('x86_64' 'aarch64')
url="https://github.com/secfacts/secfacts"
license=('Apache-2.0')
depends=('glibc')
makedepends=('go')
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('REPLACE_WITH_SHA256') # Generate with: makepkg -g

build() {
  cd "$pkgname-$pkgver/secfacts"
  export CGO_ENABLED=0
  go build -trimpath -ldflags "-s -w -X main.version=$pkgver" -o ../../$pkgname ./cmd/secfacts
}

package() {
  install -Dm755 "$pkgname" "$pkgdir/usr/bin/$pkgname"
  cd "$pkgname-$pkgver"
  install -Dm644 secfacts/README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
  install -Dm644 secfacts/LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
