# Configuration reference

Location: `<home>/sandboxes/<name>/config.toml`. Unknown keys are rejected. Changes apply on the next `start`.

Edit the file directly or use `sandbox config <name> --set <key>=<value>` with dotted keys (`network.mode=lan`, `resources.memory=8G`, `devices.gpu=true`, `env.LANG=C.UTF-8`). Values are parsed as booleans, numbers or TOML literals when they look like one and as strings otherwise; the result is validated before the file is written. `name` cannot be changed.

## Top level

| key | type | default | meaning |
|-----|------|---------|---------|
| `name` | string | required | 1-63 characters of `[A-Za-z0-9._-]`, must match the directory |

## `[filesystem]`

| key | default | meaning |
|-----|---------|---------|
| `mode` | `"isolated"` | only mode today: private copy-on-write view of the host system directories |

### `[[filesystem.share]]`

| key | default | meaning |
|-----|---------|---------|
| `host` | required | absolute host path (file or directory) |
| `path` | required | absolute path inside the sandbox; may not be `/` or under system directories |
| `readonly` | `true` | mount read-only |

CLI: `--share HOST:PATH[:rw]`.

## `[network]`

Either set `mode` or the three booleans.

| key | default | meaning |
|-----|---------|---------|
| `mode` | unset | `none`, `internet`, `lan`, `host`, `full` |
| `internet` | `false` | outbound internet through slirp4netns |
| `lan` | `false` | also allow private address ranges (requires `internet`) |
| `host` | `false` | also allow the host's own addresses and loopback services (requires `internet`) |

`full` shares the host network namespace and disables all filtering.

## `[devices]`

All default to `false`.

| key | effect |
|-----|--------|
| `gpu` | `/dev/dri`, NVIDIA and AMD KFD device nodes |
| `audio` | `/dev/snd`, PulseAudio/PipeWire sockets under `/run/display`, `PULSE_SERVER`/`PIPEWIRE_REMOTE` set |
| `microphone` | reserved; audio capture follows `audio` today |
| `camera` | `/dev/video*`, `/dev/media*` |
| `usb` | `/dev/bus/usb` |
| `bluetooth` | `/dev/rfkill*` |
| `controllers` | `/dev/input`, `/dev/hidraw*` |
| `display` | `/tmp/.X11-unix`, the first Wayland socket of the host user's runtime dir, `DISPLAY`/`WAYLAND_DISPLAY` set |

## `[resources]`

| key | default | meaning |
|-----|---------|---------|
| `memory` | unlimited | e.g. `"8G"`, `"512M"`; minimum 16M; swap is disabled when set |
| `cpus` | unlimited | fractional CPU quota, e.g. `2` or `0.5` |
| `processes` | `4096` | pid limit |

## `[security]`

| key | default | meaning |
|-----|---------|---------|
| `capabilities` | `"default"` | `"default"` keeps a Docker-like set; `"none"` drops every capability |
| `nested_namespaces` | `false` | allow `unshare`/`setns`/`clone` with namespace flags inside the sandbox |
| `uid_base` | `100000` | first host id used for the sandbox's 65536 ids; `0` selects identity mapping |

## `[env]`

String map of environment variables set for every process started with `run` or `shell`. `PATH`, `HOME`, `USER`, `TERM`, `SANDBOX` are always set.
