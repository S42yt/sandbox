# Universal Native Sandbox

Run untrusted applications in disposable environments that behave like their own computer, on top of native OS isolation primitives instead of a virtual machine.

```
sandbox create test
sandbox run test ./suspicious-app
sandbox destroy test
```

Inside the sandbox the application can install packages, spawn services, write anywhere it likes and crash. Outside, the host filesystem, processes, credentials and other sandboxes stay out of reach.

> Run it like you don't trust it. Delete it when you're done.

## Status

| Platform | State |
|----------|-------|
| Linux    | Phase 1 implemented: namespaces, idmapped overlay filesystem, seccomp, capabilities, cgroups, slirp4netns networking with nftables policy, snapshots, file transfer |
| Windows  | planned (AppContainer / restricted tokens / Job Objects) |
| macOS    | planned (Apple sandbox / lightweight virtualization) |

## Requirements (Linux)

* Kernel 5.19 or newer for idmapped overlay layers (older kernels fall back to an identity uid mapping, see [docs/security.md](docs/security.md)).
* Root. The runtime performs privileged mounts and then confines the sandbox below its own privileges; run it with `sudo`.
* `slirp4netns` for `internet`, `lan` and `host` network modes.
* `nft` (nftables) when LAN or host access is restricted while the internet is allowed.
* `cp` from coreutils (snapshots).

## Install

```
curl -fsSL https://raw.githubusercontent.com/S42yt/sandbox/main/install.sh | sh
```

The script installs `slirp4netns` and `nftables` with the system package manager, installs a Rust toolchain via rustup if none is present, builds the release binary and places it at `/usr/local/bin/sandbox`. From a checkout, `./install.sh` builds that tree instead of cloning. `./install.sh --uninstall` removes the binary; `--prefix DIR` and `--no-deps` are available, see `--help`.

Building by hand:

```
cargo install --path crates/cli
sudo ln -s ~/.cargo/bin/sandbox /usr/local/bin/sandbox
```

Sandbox state lives in `/var/lib/sandbox` (override with `--home` or `SANDBOX_HOME`).

## Usage

```
sudo sandbox create test --network internet --memory 4G --cpus 2
sudo sandbox run test -- apt-get install -y cowsay
sudo sandbox run test -- cowsay hello
sudo sandbox shell test
sudo sandbox shell test --user sandbox

sudo sandbox put test ./sample.bin /root/Downloads/sample.bin
sudo sandbox get test /root/Downloads/output.zip ./output.zip

sudo sandbox stop test
sudo sandbox start test
sudo sandbox status test
sudo sandbox list
sudo sandbox logs test

sudo sandbox config test
sudo sandbox config test --set network.mode=lan --set resources.memory=8G

sudo sandbox snapshot test clean
sudo sandbox restore test clean
sudo sandbox reset test
sudo sandbox destroy test
```

`sandbox run` starts the sandbox if it is not running and leaves it running afterwards, so background processes started by the application keep going until `sandbox stop`. If the first argument of `run` is a host path starting with `./` or `../`, the file is copied into the sandbox first and executed from there; absolute paths and bare command names resolve inside the sandbox.

Commands run as the sandbox's root user by default. A `sandbox` user with passwordless sudo exists as well (`--user sandbox`). Interactive commands get a pty inside the sandbox; piped input and output pass through unchanged. `put` and `get` accept files and directories.

## Configuration

Every sandbox has a TOML configuration at `<home>/sandboxes/<name>/config.toml`. `sandbox config <name>` prints it and `--set key=value` changes it (values are validated before they are written). Changes take effect on the next start.

```toml
name = "test"

[filesystem]
mode = "isolated"

[[filesystem.share]]
host = "/srv/samples"
path = "/mnt/samples"
readonly = true

[network]
internet = true
lan = false
host = false

[devices]
gpu = true
audio = true
microphone = false
camera = false
usb = false

[resources]
memory = "8G"
cpus = 8
processes = 4096

[security]
capabilities = "default"
nested_namespaces = false
uid_base = 100000

[env]
LANG = "C.UTF-8"
```

See [docs/configuration.md](docs/configuration.md) for every option and [docs/architecture.md](docs/architecture.md) for how the Linux backend is put together.

## Repository layout

```
crates/
  policy/          configuration model and validation (platform independent)
  core/            sandbox store, backend trait, shared types
  backend-linux/   Linux runtime: mounts, namespaces, seccomp, cgroups, networking, supervisor
  cli/             the `sandbox` binary and the integration test suite
docs/
```

## Development

```
cargo test --workspace                      # unit tests
sudo -E env PATH="$PATH" SANDBOX_INTEGRATION=1 SANDBOX_INTEGRATION_INTERNET=1 \
    cargo test -p sandbox-cli --test linux  # integration and escape tests (needs root)
cargo clippy --workspace --all-targets -- -D warnings
```

The integration tests create real sandboxes under a temporary directory, exercise the lifecycle, and probe the isolation boundary (host visibility, namespaces, mounts, sysctls, capability and seccomp state, resource limits).

## License

MIT
