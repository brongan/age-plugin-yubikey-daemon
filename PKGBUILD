# Maintainer: Brennan Tracy
pkgname=age-plugin-yubikey-agent
pkgver=0.1.0
pkgrel=1
pkgdesc='YubiKey PIN-caching daemon for age-plugin-yubikey — enter PIN once, touch to decrypt'
arch=('x86_64' 'aarch64')
url='https://github.com/brongan/age-plugin-yubikey-agent'
license=('MIT' 'Apache-2.0')
depends=('pcsclite' 'ccid')
makedepends=('cargo' 'pkg-config')
optdepends=('age: age encryption tool'
            'rage: Rust implementation of age'
            'passage: age-based password store')

source=("$pkgname::git+file://${startdir}")
sha256sums=('SKIP')

prepare() {
    cd "$pkgname"
    cargo fetch --locked
}

build() {
    cd "$pkgname"
    cargo build --frozen --release
}

check() {
    cd "$pkgname"
    cargo test --frozen
}

package() {
    cd "$pkgname"
    install -Dm755 "target/release/$pkgname" "$pkgdir/usr/bin/$pkgname"

    install -Dm644 "contrib/$pkgname.service" "$pkgdir/usr/lib/systemd/user/$pkgname.service"
    install -Dm644 "contrib/$pkgname.socket" "$pkgdir/usr/lib/systemd/user/$pkgname.socket"
    install -Dm644 LICENSE-MIT "$pkgdir/usr/share/licenses/$pkgname/LICENSE-MIT"
    install -Dm644 LICENSE-APACHE "$pkgdir/usr/share/licenses/$pkgname/LICENSE-APACHE"
}
