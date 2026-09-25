# Security model

The application does not control its own boundary. Every restriction is applied by the supervisor or by init before the first sandboxed instruction runs, from namespaces the sandbox has no authority over.

## Threat model

The sandboxed program is assumed to be malicious. It may spawn arbitrary process trees, install software, use setuid binaries, and try any syscall. The goal is that ordinary malware behaviour (reading credentials, persisting on the host, tampering with other processes, reaching the LAN) fails, with the smallest attack surface the kernel allows.

Out of scope: kernel, hypervisor, firmware or hardware vulnerabilities; side channels; denial of service against shared hardware; a compromised host.

## Layers

| Layer | Mechanism | Sandbox cannot |
|-------|-----------|----------------|
| Identity | user namespace, ids mapped to `uid_base+` | act as any host id, own host files, use capabilities outside the namespace |
| Filesystem | overlayfs over read-only idmapped binds, pivot_root, masked and whited-out paths | see `/home`, `/root`, the sandbox store, secrets under `/etc`, or `/var` beyond the allowlist; modify the host |
| Mounts | mount namespace owned by the initial user namespace | mount, unmount, remount, or reveal what is under a mask |
| Processes | pid namespace, `/proc` from that namespace | see or signal host processes; ptrace outside its tree |
| Network | net namespace, slirp4netns, nftables | reconfigure interfaces, change firewall rules, reach the LAN or host unless allowed |
| Syscalls | seccomp allowlist-with-denylist filter | mount, load modules, create namespaces, keyring/bpf/perf/io_uring, change the clock, reboot |
| Capabilities | bounding set | regain `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `MKNOD`, `NET_RAW` even via setuid binaries |
| Kernel interfaces | read-only `/proc/sys`, masked `/proc` and `/sys` entries, `nodev` on writable filesystems, no `CAP_MKNOD` | change sysctls, read kernel memory, create device nodes |
| Resources | cgroup memory, cpu and pids limits | exhaust host memory or the pid space |
| Devices | explicit bind mounts only | reach GPU, audio, USB, camera, input devices unless enabled |

## What the integration tests verify

`crates/cli/tests/linux.rs` runs real sandboxes and asserts, among other things, that:

* host home directories, the sandbox store, ssh host keys and the real shadow file are not visible
* host processes are not visible and `/proc/kcore` does not exist
* `mount`, `umount`, `unshare` (user, mount, pid), `mknod`, sysctl writes, `setns` into pid 1 and `setuid` to an unmapped id all fail
* the capability bounding set and seccomp mode are exactly as configured
* fork bombs stop at `pids.max` and large allocations are OOM-killed at `memory.max`
* symlinks planted inside the sandbox cannot redirect `put`/`get` to host paths, and directory transfers preserve modes and symlinks in both directions
* interactive commands run on a pty owned by the requested user inside the sandbox, and `sudo` works on it
* stopping a sandbox kills every process it started
* `none` mode has only `lo` and no DNS; `internet` mode reaches the internet but not `10.0.2.2` or private ranges

## Known limitations

* **Kernels older than 5.19** lack idmapped overlay layers. The runtime then maps sandbox ids to the same host ids (`uid_base = 0` behaviour). Namespaces, seccomp, capabilities, mounts and cgroups still apply, but a kernel bug that leaks a file descriptor to the host tree would leak it with host root ownership.
* **Root is required.** A rootless mode would need `newuidmap` and a private rootfs instead of the host's `/usr`; it is not implemented.
* **Shared kernel.** Any local privilege escalation in the kernel breaks all namespace-based sandboxes. Use `full`-mode networking and device passthrough only when needed; each adds attack surface (`/sys` of the host is bind-mounted in `full` mode).
* **Devices are bind mounts.** GPU and other device nodes are the real host devices; a driver vulnerability is reachable when they are enabled. `controllers = true` exposes `/dev/input`, which includes keyboards.
* **Display sockets** (`display = true`) give the sandbox an X11/Wayland connection with the usual X11 caveats (input snooping between clients of the same server). Prefer a nested compositor.
* **`/etc` masking is a denylist.** Unusual secret locations under `/etc` may be exposed read-only; put them in `[[filesystem.share]]`-style reviews or extend `ETC_DENY` in `seed.rs`. `/var` is allowlisted and `/usr`, `/opt` are shown entirely.
* **Terminal output is still terminal output.** Interactive commands get a pty that lives in the sandbox's own `devpts`, and the host side only relays bytes, but a malicious program can still print escape sequences that your terminal emulator interprets. Use a terminal that guards against dangerous sequences.
* **cgroup v1 hosts** do not get a cgroup filesystem inside the sandbox.
