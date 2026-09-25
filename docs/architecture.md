# Architecture

## Crates

```
sandbox-policy   SandboxConfig, TOML parsing, validation, NetworkPolicy derivation
sandbox-core     Store (on-disk layout, locking), Sandbox, Command, SandboxBackend trait
sandbox-backend-linux
sandbox-cli      clap front end, backend selection per target OS
```

`SandboxBackend` is the platform seam:

```rust
pub trait SandboxBackend {
    fn create(&self, store: &Store, config: &SandboxConfig) -> Result<Sandbox>;
    fn start(&self, sandbox: &Sandbox) -> Result<()>;
    fn stop(&self, sandbox: &Sandbox) -> Result<()>;
    fn status(&self, sandbox: &Sandbox) -> Result<Status>;
    fn run(&self, sandbox: &Sandbox, command: &Command) -> Result<i32>;
    fn destroy(&self, sandbox: &Sandbox) -> Result<()>;
    fn put_file(&self, sandbox: &Sandbox, source: &Path, destination: &Path) -> Result<()>;
    fn get_file(&self, sandbox: &Sandbox, source: &Path, destination: &Path) -> Result<()>;
    fn snapshot(&self, sandbox: &Sandbox, snapshot: &str) -> Result<()>;
    fn restore(&self, sandbox: &Sandbox, snapshot: &str) -> Result<()>;
    fn delete_snapshot(&self, sandbox: &Sandbox, snapshot: &str) -> Result<()>;
    fn reset(&self, sandbox: &Sandbox) -> Result<()>;
}
```

## On-disk layout

```
/var/lib/sandbox/sandboxes/<name>/
  config.toml
  ovl/upper/<layer>/      every write the sandbox ever made (persistent, snapshotted)
  ovl/work/<layer>/       overlayfs scratch space
  snapshots/<snap>/upper/ copies of ovl/upper
  run/                    lock, state.json, supervisor.log, mount targets while running
```

Layers mirror the host's top-level system directories: `usr`, `etc`, `var`, `opt` (and `bin`, `sbin`, `lib*` on hosts without merged `/usr`), plus a `root` layer whose lower side is an empty skeleton holding `/home`, `/root`, `/tmp`, `/srv`, `/mnt`, `/media`, `/boot` and mountpoints. Host directories that are not layers (`/home`, `/root`, `/tmp`, ...) are never visible.

`reset` deletes `ovl/upper` and re-seeds it. `destroy` removes the whole directory. Snapshots copy `ovl/upper` with `cp -a --reflink=auto`, so on btrfs/xfs they are nearly free.

## Linux runtime

### Processes

```
sandbox start (CLI)
  └─ supervisor (daemon, host root, private mount namespace, child subreaper)
       ├─ launcher: joins the cgroup, unshare(mount|pid|net|ipc|uts|cgroup), forks init, exits
       │    └─ init (pid 1 of the sandbox)
       │         mounts /proc /sys /dev/pts /dev/shm, pivot_root, masks /proc
       │         unshare(user) → supervisor writes uid/gid maps
       │         seccomp filter, capability bounding set, becomes mapped uid 0
       │         reaps zombies, forwards SIGTERM to everything, exits when stopped
       └─ slirp4netns (host side of the network, killed with the sandbox)
```

The order matters. Init performs every mount while it still holds host privileges inside namespaces that belong to the initial user namespace; only then does it enter the sandbox user namespace. Consequently the sandbox's mount, pid, net, ipc, uts and cgroup namespaces are all owned by the initial user namespace, and nothing inside the sandbox holds `CAP_SYS_ADMIN` over them: no umount, no new mounts, no sysctl writes, no network reconfiguration.

`sandbox run` opens `/proc/<init>/ns/*` from the host, moves the new process into the sandbox cgroup, `setns()` into mount, pid, net, ipc, uts and cgroup namespaces, then into the user namespace, installs the same seccomp filter and capability set, switches to the requested user and `execve()`s. The command inherits the caller's terminal.

Stopping sends `SIGTERM` to the supervisor, which forwards it to init. Init signals everything in its pid namespace and exits; the kernel then kills every remaining process of the pid namespace, the supervisor kills what is left in the cgroup, tears down slirp4netns and removes the cgroup. `run/lock` is held with `flock` by the supervisor for as long as the sandbox runs, so state detection never depends on pid reuse.

### Filesystem

Each layer is an overlayfs mount:

```
lowerdir = idmapped, read-only bind of the host directory
upperdir = idmapped bind of ovl/upper/<layer>
workdir  = idmapped bind of ovl/work/<layer>
```

The id mapping is created with `mount_setattr(MOUNT_ATTR_IDMAP)` from a template user namespace that maps sandbox ids `0..65535` to host ids `uid_base..uid_base+65535`. Inside the sandbox, host-root-owned files look root-owned and package installs work; on the host, everything the sandbox writes ends up in `ovl/upper` owned by the ids recorded on disk, while the sandbox's processes run as unprivileged host ids. Overlay mounts are performed with `fsuid` set to the mapped root id (with `SECBIT_NO_SETUID_FIXUP` so capabilities are retained) because overlayfs performs its internal operations with the mounter's credentials.

Before mounting, the supervisor seeds and masks the upper layers:

* generated `/etc/passwd`, `group`, `shadow`, `gshadow`, `hostname`, `hosts`, `machine-id`, `fstab`, `resolv.conf`, `sudoers.d`; host human accounts are not copied
* overlay whiteouts for secrets and host-specific state under `/etc` (shadow backups, ssh host keys, TLS private keys, VPN/Wi-Fi configuration, package manager credentials, cron, systemd units, ...)
* `/var` is exposed through an allowlist (`lib`, `cache`, `local`, `opt`, ...), `/var/lib` and `/var/cache` through per-entry allowlists (`dpkg`, `apt`, `alternatives`, `dbus`, `rpm`, ...); everything else, including the sandbox store itself, is whited out
* empty opaque directories for `/var/log`, `/var/tmp`, `/var/mail`, `/var/spool`, `/var/backups`, `/var/crash`

Masks are re-applied on every start, so entries the host adds later stay hidden.

Runtime mounts: tmpfs `/run` and `/dev` (with `null`, `zero`, `full`, `random`, `urandom`, `tty`, `pts`, `shm`, `mqueue`), `proc` (with `/proc/sys`, `sysrq-trigger`, `irq`, `bus`, `fs` read-only and `kcore`, `keys`, `timer_list`, `sched_debug` masked), read-only `sysfs`, a private `devpts`, and device or socket bind mounts as enabled in `[devices]`. Shares are idmapped bind mounts at the requested path.

### Network

| mode | implementation |
|------|----------------|
| `none` | private network namespace with only `lo` |
| `internet` | slirp4netns user-mode networking; nftables rules inside the namespace reject RFC1918, link-local and multicast destinations; the host loopback gateway is disabled |
| `lan` | as above without the private-range rule; the host's own addresses and the gateway are rejected |
| `host` | slirp4netns with host loopback enabled |
| `full` | no network namespace at all; the host stack is shared |

The nftables rules live in the sandbox's network namespace, which is owned by the initial user namespace, so no sandbox process can list or change them. DNS goes through slirp's built-in resolver at `10.0.2.3`.

### Resources

cgroup v2 (`/sys/fs/cgroup/sandbox/<name>`) with `memory.max`, `cpu.max` and `pids.max`; on cgroup v1 hosts the `memory`, `cpu` and `pids` hierarchies are used. On v2 hosts the sandbox sees its own cgroup subtree mounted at `/sys/fs/cgroup`.

### Syscall and capability policy

A hand-assembled classic BPF seccomp filter kills on a foreign architecture or the x32 ABI and returns `EPERM` for mount/namespace/module/reboot/time/key/bpf/perf/io_uring/quota/numa/process_vm syscalls (`ENOSYS` for `clone3` so libc falls back to `clone`, whose namespace flags are checked). The filter is installed without `no_new_privs`, which keeps setuid binaries such as `sudo` usable inside the sandbox.

The capability bounding set is reduced to the Docker-like default (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `SETGID`, `SETUID`, `SETPCAP`, `NET_BIND_SERVICE`, `SYS_CHROOT`, `AUDIT_WRITE`, `SETFCAP`) or to nothing with `capabilities = "none"`. `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_MKNOD` and `CAP_NET_RAW` are never granted. All of these capabilities are relative to the sandbox user namespace anyway.
