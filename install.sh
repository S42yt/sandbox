#!/bin/sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
GITHUB="${SANDBOX_GITHUB:-S42yt/sandbox}"
REPO="${SANDBOX_REPO:-https://github.com/$GITHUB.git}"
REF="${SANDBOX_REF:-main}"
VERSION="${SANDBOX_VERSION:-latest}"
BIN="$PREFIX/bin/sandbox"
STATE_DIR=/var/lib/sandbox

usage() {
    cat <<EOF
Universal Native Sandbox installer

Usage: install.sh [--source] [--version TAG] [--no-deps] [--prefix DIR] [--uninstall]

Installs the sandbox CLI to $BIN. By default a prebuilt static binary is
downloaded from the GitHub releases of $GITHUB; when no release matches,
or with --source, the CLI is built from source (from this checkout when run
inside one, otherwise from a fresh clone of $REPO).

Options:
  --source        build from source instead of downloading a release
  --version TAG   release tag to download (default: latest)
  --prefix DIR    install under DIR instead of /usr/local
  --no-deps       skip installing slirp4netns and nftables
  --uninstall     remove the binary (sandbox state in $STATE_DIR is kept)

Environment:
  SANDBOX_GITHUB              owner/repo for release downloads
  SANDBOX_REPO, SANDBOX_REF   repository and branch/tag to clone when building from source
EOF
}

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

UNINSTALL=0
DEPS=1
SOURCE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --uninstall) UNINSTALL=1 ;;
        --no-deps) DEPS=0 ;;
        --source) SOURCE=1 ;;
        --version) shift; VERSION="$1" ;;
        --prefix) shift; PREFIX="$1"; BIN="$PREFIX/bin/sandbox" ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
    shift
done

[ "$(uname -s)" = Linux ] || die "only Linux is supported at the moment"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "run as root or install sudo"
    SUDO=sudo
fi

if [ "$UNINSTALL" -eq 1 ]; then
    if [ -e "$BIN" ]; then
        $SUDO rm -f "$BIN"
        say "removed $BIN"
    else
        say "nothing installed at $BIN"
    fi
    say "sandbox state in $STATE_DIR was left in place; remove it with: sudo rm -rf $STATE_DIR"
    exit 0
fi

kernel_ok() {
    v="$(uname -r | cut -d- -f1)"
    major="${v%%.*}"
    rest="${v#*.}"
    minor="${rest%%.*}"
    [ "$major" -gt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -ge 19 ]; }
}

if kernel_ok; then
    say "kernel $(uname -r): idmapped mounts available"
else
    say "kernel $(uname -r) is older than 5.19: the sandbox will fall back to identity uid mapping (see docs/security.md)"
fi

install_deps() {
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update -qq
        $SUDO apt-get install -y -qq slirp4netns nftables
    elif command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y slirp4netns nftables
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -Sy --noconfirm --needed slirp4netns nftables
    elif command -v zypper >/dev/null 2>&1; then
        $SUDO zypper --non-interactive install slirp4netns nftables
    elif command -v apk >/dev/null 2>&1; then
        $SUDO apk add slirp4netns nftables
    else
        say "unknown package manager: install slirp4netns and nftables yourself for network support"
        return 0
    fi
}

if [ "$DEPS" -eq 1 ]; then
    if command -v slirp4netns >/dev/null 2>&1 && command -v nft >/dev/null 2>&1; then
        say "slirp4netns and nft already installed"
    else
        say "installing slirp4netns and nftables"
        install_deps
    fi
fi

arch_name() {
    case "$(uname -m)" in
        x86_64|amd64) echo x86_64 ;;
        aarch64|arm64) echo aarch64 ;;
        *) return 1 ;;
    esac
}

download_release() {
    command -v curl >/dev/null 2>&1 || return 1
    arch="$(arch_name)" || { say "no prebuilt binary for $(uname -m)"; return 1; }
    name="sandbox-$arch-linux-musl"
    if [ "$VERSION" = latest ]; then
        base="https://github.com/$GITHUB/releases/latest/download"
    else
        base="https://github.com/$GITHUB/releases/download/$VERSION"
    fi
    DL="$(mktemp -d)"
    say "downloading $name ($VERSION)"
    if ! curl -fsSL --retry 3 -o "$DL/$name.tar.gz" "$base/$name.tar.gz"; then
        rm -rf "$DL"
        return 1
    fi
    if curl -fsSL --retry 3 -o "$DL/$name.tar.gz.sha256" "$base/$name.tar.gz.sha256"; then
        if command -v sha256sum >/dev/null 2>&1; then
            (cd "$DL" && sha256sum -c "$name.tar.gz.sha256" >/dev/null) || die "checksum mismatch for $name.tar.gz"
        fi
    else
        say "no checksum published for this release; skipping verification"
    fi
    tar -C "$DL" -xzf "$DL/$name.tar.gz"
    BINARY="$DL/$name/sandbox"
    [ -x "$BINARY" ] || die "release archive did not contain the sandbox binary"
}

build_from_source() {
    if ! command -v cargo >/dev/null 2>&1; then
        if [ -x "$HOME/.cargo/bin/cargo" ]; then
            PATH="$HOME/.cargo/bin:$PATH"
        else
            say "Rust toolchain not found; installing with rustup"
            command -v curl >/dev/null 2>&1 || die "curl is required to install rustup"
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
            PATH="$HOME/.cargo/bin:$PATH"
        fi
    fi
    export PATH

    SRC=""
    if [ -f "$(dirname "$0")/Cargo.toml" ] && grep -q 'crates/cli' "$(dirname "$0")/Cargo.toml"; then
        SRC="$(cd "$(dirname "$0")" && pwd)"
        say "building from checkout $SRC"
    else
        command -v git >/dev/null 2>&1 || die "git is required to clone $REPO"
        SRC="$(mktemp -d)"
        CLONE="$SRC"
        say "cloning $REPO ($REF)"
        git clone --quiet --depth 1 --branch "$REF" "$REPO" "$SRC"
    fi

    say "compiling release binary"
    cargo build --release --manifest-path "$SRC/Cargo.toml" --quiet
    BINARY="$SRC/target/release/sandbox"
}

BINARY=""
DL=""
CLONE=""
trap 'rm -rf "$DL" "$CLONE"' EXIT
if [ "$SOURCE" -eq 0 ] && ! [ -f "$(dirname "$0")/Cargo.toml" ]; then
    download_release || say "no prebuilt release available; building from source"
fi
[ -n "$BINARY" ] || build_from_source

$SUDO install -d -m 755 "$PREFIX/bin"
$SUDO install -m 755 "$BINARY" "$BIN"
$SUDO install -d -m 700 "$STATE_DIR"
say "installed $BIN ($("$BIN" --version))"
for shell in bash zsh fish; do
    case "$shell" in
        bash) dir=/usr/share/bash-completion/completions; file=sandbox ;;
        zsh) dir=/usr/share/zsh/site-functions; file=_sandbox ;;
        fish) dir=/usr/share/fish/vendor_completions.d; file=sandbox.fish ;;
    esac
    if [ -d "$dir" ]; then
        "$BIN" completions "$shell" | $SUDO tee "$dir/$file" >/dev/null && say "installed $shell completions"
    fi
done

cat <<EOF

Get started:
  sudo sandbox create test --network internet
  sudo sandbox run test -- apt-get install -y cowsay
  sudo sandbox shell test
  sudo sandbox destroy test
EOF
