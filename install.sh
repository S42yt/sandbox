#!/bin/sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
REPO="${SANDBOX_REPO:-https://github.com/S42yt/sandbox.git}"
REF="${SANDBOX_REF:-main}"
BIN="$PREFIX/bin/sandbox"
STATE_DIR=/var/lib/sandbox

usage() {
    cat <<EOF
Universal Native Sandbox installer

Usage: install.sh [--uninstall] [--no-deps] [--prefix DIR]

Builds the sandbox CLI from source and installs it to $BIN.
Run from a checkout to build that tree, or standalone to clone $REPO.

Options:
  --prefix DIR   install under DIR instead of /usr/local
  --no-deps      skip installing slirp4netns and nftables
  --uninstall    remove the binary (sandbox state in $STATE_DIR is kept)

Environment:
  SANDBOX_REPO, SANDBOX_REF   repository and branch/tag to clone when not run from a checkout
EOF
}

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

UNINSTALL=0
DEPS=1
while [ $# -gt 0 ]; do
    case "$1" in
        --uninstall) UNINSTALL=1 ;;
        --no-deps) DEPS=0 ;;
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
    trap 'rm -rf "$SRC"' EXIT
    say "cloning $REPO ($REF)"
    git clone --quiet --depth 1 --branch "$REF" "$REPO" "$SRC"
fi

say "compiling release binary"
cargo build --release --manifest-path "$SRC/Cargo.toml" --quiet

$SUDO install -d -m 755 "$PREFIX/bin"
$SUDO install -m 755 "$SRC/target/release/sandbox" "$BIN"
$SUDO install -d -m 700 "$STATE_DIR"
say "installed $BIN ($("$BIN" --version))"

cat <<EOF

Get started:
  sudo sandbox create test --network internet
  sudo sandbox run test -- apt-get install -y cowsay
  sudo sandbox shell test
  sudo sandbox destroy test
EOF
