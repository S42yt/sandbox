use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

use sandbox_core::{IoContext, Result, Sandbox};
use sandbox_policy::{normalize_sandbox_path, DeviceConfig, Share};

use crate::layout::{host_layers, rel, Layout, ROOT_LAYER};
use crate::mount;
use crate::ns::IdMap;
use crate::seed;
use crate::sys;

pub struct Build<'a> {
    pub sandbox: &'a Sandbox,
    pub layout: &'a Layout,
    pub map: IdMap,
    pub userns: Option<RawFd>,
    pub full: bool,
}

pub const DISPLAY_DIR: &str = "/run/display";

fn layer_upper_for(layout: &Layout, path: &Path) -> PathBuf {
    let r = rel(path);
    let mut comps = r.components();
    if let Some(first) = comps.next() {
        let first = first.as_os_str().to_string_lossy().to_string();
        if host_layers().iter().any(|l| l.name == first) {
            return layout.layer_upper(&first).join(comps.as_path());
        }
    }
    layout.layer_upper(ROOT_LAYER).join(r)
}

pub fn precreate(layout: &Layout, path: &Path, dir: bool, mode: u32) -> Result<()> {
    let p = layer_upper_for(layout, path);
    if fs::symlink_metadata(&p).is_ok() {
        return Ok(());
    }
    if dir {
        sys::mkdir_p(&p, mode)?;
        sys::chmod(&p, mode)
    } else {
        if let Some(parent) = p.parent() {
            sys::mkdir_p(parent, 0o755)?;
        }
        fs::File::create(&p)
            .map(drop)
            .with_ctx(|| format!("creating {}", p.display()))
    }
}

fn attach_lower(b: &Build, host: &Path, target: &Path) -> Result<()> {
    match b.userns {
        Some(fd) => mount::idmapped_bind(host, target, fd, true),
        None => {
            sys::mkdir_p(target, 0o755)?;
            mount::bind(host, target, true, false)
        }
    }
}

fn attach_share(b: &Build, share: &Share, rootfs: &Path) -> Result<()> {
    let inner = normalize_sandbox_path(&share.path)?;
    let host_meta = fs::metadata(&share.host).with_ctx(|| format!("share {}", share.host.display()))?;
    let target = rootfs.join(rel(&inner));
    if host_meta.is_dir() {
        sys::mkdir_p(&target, 0o755)?;
    }
    match b.userns {
        Some(fd) if host_meta.is_dir() => mount::idmapped_bind(&share.host, &target, fd, share.readonly),
        _ => mount::bind(&share.host, &target, share.readonly, true),
    }
}

pub fn build(b: &Build) -> Result<()> {
    let layout = b.layout;
    let rootfs = layout.rootfs();
    let idmap = layout.idmap();
    for d in [&rootfs, &idmap] {
        if d.exists() {
            fs::remove_dir_all(d).with_ctx(|| format!("clearing {}", d.display()))?;
        }
        sys::mkdir_p(d, 0o755)?;
    }
    seed::build_skeleton(&layout.skel())?;
    for share in &b.sandbox.config.filesystem.shares {
        let inner = normalize_sandbox_path(&share.path)?;
        let is_dir = fs::metadata(&share.host).map(|m| m.is_dir()).unwrap_or(true);
        precreate(layout, &inner, is_dir, 0o755)?;
    }
    if b.full && b.sandbox.config.devices.display {
        precreate(layout, Path::new("/tmp/.X11-unix"), true, 0o1777)?;
    }

    let ovl = idmap.join("ovl");
    match b.userns {
        Some(fd) => mount::idmapped_bind(&layout.ovl(), &ovl, fd, false)?,
        None => {
            sys::mkdir_p(&ovl, 0o755)?;
            mount::bind(&layout.ovl(), &ovl, false, false)?;
        }
    }

    let mut layers = vec![(ROOT_LAYER.to_string(), layout.skel(), rootfs.clone())];
    for layer in host_layers() {
        layers.push((layer.name.clone(), layer.host.clone(), rootfs.join(&layer.name)));
    }
    for (name, host, _) in &layers {
        attach_lower(b, host, &idmap.join("lower").join(name))?;
        sys::mkdir_p(layout.work().join(name), 0o700)?;
        sys::mkdir_p(layout.layer_upper(name), 0o755)?;
    }
    let _fs_ids = b
        .userns
        .map(|_| sys::FsIds::switch(b.map.host_uid(0)))
        .transpose()?;
    for (name, _, target) in &layers {
        mount::overlay(
            target,
            &idmap.join("lower").join(name),
            &ovl.join("upper").join(name),
            &ovl.join("work").join(name),
            libc::MS_NODEV,
        )?;
    }
    drop(_fs_ids);

    if !b.full {
        return Ok(());
    }

    let uid = b.map.host_uid(0);
    mount::tmpfs(&rootfs.join("run"), 0o755, uid, "")?;
    let lock = rootfs.join("run/lock");
    sys::mkdir_p(&lock, 0o1777)?;
    sys::chmod(&lock, 0o1777)?;
    sys::lchown(&lock, uid, uid)?;

    let dev = rootfs.join("dev");
    sys::mkdir_p(&dev, 0o755)?;
    mount::mount(
        "tmpfs",
        &dev,
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("mode=755,size=64k,nr_inodes=1024"),
    )?;
    for (name, minor) in [
        ("null", 3),
        ("zero", 5),
        ("full", 7),
        ("random", 8),
        ("urandom", 9),
    ] {
        sys::mknod(dev.join(name), libc::S_IFCHR | 0o666, libc::makedev(1, minor))?;
    }
    sys::mknod(dev.join("tty"), libc::S_IFCHR | 0o666, libc::makedev(5, 0))?;
    for d in ["pts", "shm", "mqueue"] {
        sys::mkdir_p(dev.join(d), 0o755)?;
    }
    for (link, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
        ("ptmx", "pts/ptmx"),
    ] {
        symlink(target, dev.join(link)).with_ctx(|| format!("creating /dev/{link}"))?;
    }

    let net = b.sandbox.config.network.policy()?;
    if !net.isolated {
        let sysdir = rootfs.join("sys");
        mount::bind(Path::new("/sys"), &sysdir, true, true)?;
        for m in [
            "firmware",
            "kernel/debug",
            "kernel/tracing",
            "fs/pstore",
            "power",
            "kernel/security",
        ] {
            let _ = mount::mask_file(&sysdir.join(m));
        }
    }

    attach_devices(&b.sandbox.config.devices, &dev, &rootfs, uid)?;
    for share in &b.sandbox.config.filesystem.shares {
        attach_share(b, share, &rootfs)?;
    }
    Ok(())
}

fn bind_dev_dir(dev: &Path, name: &str) -> Result<()> {
    let host = Path::new("/dev").join(name);
    if !host.is_dir() {
        return Ok(());
    }
    let target = dev.join(name);
    sys::mkdir_p(&target, 0o755)?;
    mount::bind(&host, &target, false, true)
}

fn bind_dev_glob(dev: &Path, prefix: &str) -> Result<()> {
    let Ok(rd) = fs::read_dir("/dev") else {
        return Ok(());
    };
    for e in rd.flatten() {
        let n = e.file_name();
        let n = n.to_string_lossy();
        if n.starts_with(prefix) && n[prefix.len()..].chars().all(|c| c.is_ascii_digit()) {
            let target = dev.join(&*n);
            mount::ensure_mountpoint(&target, false)?;
            mount::bind(&e.path(), &target, false, false)?;
        }
    }
    Ok(())
}

fn host_user_runtime_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(d));
    }
    if let Some(uid) = std::env::var("SUDO_UID").ok().and_then(|u| u.parse::<u32>().ok()) {
        let p = PathBuf::from(format!("/run/user/{uid}"));
        if p.is_dir() {
            return Some(p);
        }
    }
    fs::read_dir("/run/user")
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| p.is_dir())
}

fn attach_devices(devices: &DeviceConfig, dev: &Path, rootfs: &Path, uid: u32) -> Result<()> {
    if devices.gpu {
        bind_dev_dir(dev, "dri")?;
        bind_dev_glob(dev, "nvidia")?;
        for n in [
            "nvidiactl",
            "nvidia-modeset",
            "nvidia-uvm",
            "nvidia-uvm-tools",
            "kfd",
        ] {
            let host = Path::new("/dev").join(n);
            if host.exists() {
                let t = dev.join(n);
                mount::ensure_mountpoint(&t, false)?;
                mount::bind(&host, &t, false, false)?;
            }
        }
    }
    if devices.audio {
        bind_dev_dir(dev, "snd")?;
    }
    if devices.usb {
        sys::mkdir_p(dev.join("bus"), 0o755)?;
        bind_dev_dir(dev, "bus/usb")?;
    }
    if devices.camera {
        bind_dev_glob(dev, "video")?;
        bind_dev_glob(dev, "media")?;
    }
    if devices.controllers {
        bind_dev_dir(dev, "input")?;
        bind_dev_glob(dev, "hidraw")?;
    }
    if devices.bluetooth {
        bind_dev_glob(dev, "rfkill")?;
    }
    if devices.display || devices.audio {
        let disp = rootfs.join(rel(Path::new(DISPLAY_DIR)));
        sys::mkdir_p(&disp, 0o755)?;
        sys::lchown(&disp, uid, uid)?;
        if let Some(rt) = host_user_runtime_dir() {
            let mut sockets: Vec<(PathBuf, &str)> = Vec::new();
            if devices.display {
                if let Ok(rd) = fs::read_dir(&rt) {
                    for e in rd.flatten() {
                        let n = e.file_name().to_string_lossy().to_string();
                        if n.starts_with("wayland-") && !n.ends_with(".lock") {
                            sockets.push((e.path(), "wayland-0"));
                            break;
                        }
                    }
                }
            }
            if devices.audio {
                sockets.push((rt.join("pulse/native"), "pulse"));
                sockets.push((rt.join("pipewire-0"), "pipewire-0"));
            }
            for (src, name) in sockets {
                if src.exists() {
                    let t = disp.join(name);
                    mount::ensure_mountpoint(&t, false)?;
                    mount::bind(&src, &t, false, false)?;
                }
            }
        }
        if devices.display {
            let x11 = Path::new("/tmp/.X11-unix");
            if x11.is_dir() {
                mount::bind(x11, &rootfs.join("tmp/.X11-unix"), false, true)?;
            }
        }
    }
    Ok(())
}

pub fn display_env(devices: &DeviceConfig) -> Vec<(String, String)> {
    let mut env = Vec::new();
    if devices.display {
        if let Ok(d) = std::env::var("DISPLAY") {
            env.push(("DISPLAY".into(), d));
        }
        env.push(("WAYLAND_DISPLAY".into(), format!("{DISPLAY_DIR}/wayland-0")));
    }
    if devices.audio {
        env.push(("PULSE_SERVER".into(), format!("unix:{DISPLAY_DIR}/pulse")));
        env.push(("PIPEWIRE_REMOTE".into(), format!("{DISPLAY_DIR}/pipewire-0")));
    }
    env.push(("XDG_RUNTIME_DIR".into(), DISPLAY_DIR.into()));
    env
}

pub fn mask_proc() -> Result<()> {
    for f in [
        "kcore",
        "keys",
        "timer_list",
        "sched_debug",
        "latency_stats",
        "timer_stats",
    ] {
        let _ = mount::mask_file(&Path::new("/proc").join(f));
    }
    for d in ["sys", "sysrq-trigger", "irq", "bus", "fs"] {
        let p = Path::new("/proc").join(d);
        if p.exists() {
            mount::bind(&p, &p, true, false)?;
        }
    }
    Ok(())
}
