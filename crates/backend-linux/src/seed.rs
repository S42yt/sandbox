use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;

use sandbox_core::{IoContext, Result, Sandbox};
use sandbox_policy::NetworkPolicy;

use crate::layout::{host_layers, Layout, ROOT_LAYER};
use crate::sys;

pub const SANDBOX_USER: &str = "sandbox";
pub const SANDBOX_UID: u32 = 1000;

const ETC_DENY: &[&str] = &[
    "shadow",
    "shadow-",
    "gshadow",
    "gshadow-",
    "passwd-",
    "group-",
    "subuid",
    "subgid",
    "ssh/ssh_host_*",
    "ssl/private",
    "pki/tls/private",
    "security/opasswd",
    "NetworkManager/system-connections",
    "wpa_supplicant",
    "wireguard",
    "openvpn",
    "ppp",
    "krb5.keytab",
    "letsencrypt",
    "apt/auth.conf",
    "apt/auth.conf.d",
    "netplan",
    "iscsi",
    "samba/smbpasswd",
    "docker",
    "rancher",
    "kubernetes",
    "cni",
    "crypttab",
    "fstab",
    "machine-id",
    "hostname",
    "hosts",
    "resolv.conf",
    "sudoers.d",
    "cups/ppd",
    "salt",
    "chef",
    "puppet",
    "ansible",
    "systemd/system",
    "systemd/user",
    "cron.d",
    "cron.daily",
    "cron.hourly",
    "cron.weekly",
    "cron.monthly",
    "crontab",
    "sandbox",
];

const VAR_ALLOW: &[&str] = &["lib", "cache", "local", "opt", "games", "www", "run", "lock"];

const VAR_LIB_ALLOW: &[&str] = &[
    "dpkg",
    "apt",
    "ucf",
    "misc",
    "alternatives",
    "dbus",
    "locales",
    "pam",
    "python",
    "python3",
    "shells.state",
    "ca-certificates",
    "rpm",
    "yum",
    "dnf",
    "pacman",
    "xkb",
    "emacsen-common",
    "vim",
    "man-db",
    "sgml-base",
    "xml-core",
    "texmf",
    "dictionaries-common",
    "ispell",
    "aspell",
    "ghostscript",
    "tex-common",
    "x11",
    "systemd",
    "usbutils",
    "ubuntu-advantage",
    "command-not-found",
    "os-prober",
    "logrotate",
    "initramfs-tools",
    "polkit-1",
    "dhcp",
    "mlocate",
    "plocate",
    "git",
    "gems",
    "cargo",
    "flatpak",
    "AccountsService",
    "app-info",
    "swcatalog",
    "fontconfig",
    "mime",
    "mono",
    "nodejs",
    "npm",
    "php",
    "perl",
    "perl5",
    "ruby",
    "shim-signed",
    "grub",
    "update-notifier",
    "update-manager",
    "python3-*",
    "belocs",
    "libuuid",
    "bluetooth",
    "hp",
    "colord",
    "avahi-autoipd",
    "ntp",
    "chrony",
    "snmp",
    "sudo",
    "sshguard",
    "fail2ban",
    "unattended-upgrades",
    "apt-listchanges",
    "aptitude",
    "debconf",
];

const VAR_CACHE_ALLOW: &[&str] = &[
    "apt",
    "debconf",
    "ldconfig",
    "man",
    "fontconfig",
    "fonts",
    "dnf",
    "yum",
    "pacman",
    "pip",
    "swcatalog",
    "app-info",
    "dictionaries-common",
    "cracklib",
    "PackageKit",
    "apparmor",
    "cups",
    "locale",
    "texmf",
    "flatpak",
    "gdm",
    "lightdm",
    "mandb",
];

const VAR_SEED_DIRS: &[(&str, u32)] = &[
    ("log", 0o755),
    ("log/apt", 0o755),
    ("tmp", 0o1777),
    ("mail", 0o2775),
    ("spool", 0o755),
    ("backups", 0o755),
    ("crash", 0o3777),
    ("lib/private", 0o700),
    ("lib/systemd/timers", 0o755),
    ("lib/systemd/coredump", 0o755),
    ("cache/private", 0o700),
];

fn matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == pattern,
    }
}

fn upper_has(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn hide(upper: &Path, rel: &str) -> Result<()> {
    let target = upper.join(rel);
    if upper_has(&target) {
        return Ok(());
    }
    if let Some(p) = target.parent() {
        sys::mkdir_p(p, 0o755)?;
    }
    sys::whiteout(&target)
}

fn hide_pattern(host: &Path, upper: &Path, pattern: &str) -> Result<()> {
    if let Some((dir, pat)) = pattern.rsplit_once('/').filter(|(_, p)| p.ends_with('*')) {
        if let Ok(rd) = fs::read_dir(host.join(dir)) {
            for e in rd.flatten() {
                let n = e.file_name();
                let n = n.to_string_lossy();
                if matches(pat, &n) {
                    hide(upper, &format!("{dir}/{n}"))?;
                }
            }
        }
        return Ok(());
    }
    if pattern.ends_with('*') {
        return hide_pattern(host, upper, &format!("./{pattern}"));
    }
    if fs::symlink_metadata(host.join(pattern)).is_ok() {
        hide(upper, pattern)?;
    }
    Ok(())
}

fn hide_except(host: &Path, upper: &Path, dir: &str, allow: &[&str]) -> Result<()> {
    let Ok(rd) = fs::read_dir(host.join(dir)) else {
        return Ok(());
    };
    let updir = upper.join(dir);
    for e in rd.flatten() {
        let n = e.file_name();
        let n = n.to_string_lossy();
        let allowed = allow.iter().any(|a| matches(a, &n));
        let is_symlink = e.file_type().map(|t| t.is_symlink()).unwrap_or(false);
        let up = updir.join(&*n);
        if allowed || is_symlink {
            continue;
        }
        if !upper_has(&up) {
            hide(upper, &format!("{dir}/{n}"))?;
        } else if up.is_dir() && !is_opaque(&up) {
            let _ = sys::set_xattr(&up, "trusted.overlay.opaque", b"y");
        }
    }
    Ok(())
}

fn is_opaque(p: &Path) -> bool {
    let c = match sys::cstr(p) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let name = c"trusted.overlay.opaque";
    let mut buf = [0u8; 4];
    let r = unsafe { libc::lgetxattr(c.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    r > 0 && buf[0] == b'y'
}

pub fn apply_masks(layout: &Layout, store_root: &Path) -> Result<()> {
    for layer in host_layers() {
        let upper = layout.layer_upper(&layer.name);
        sys::mkdir_p(&upper, 0o755)?;
        match layer.name.as_str() {
            "etc" => {
                for p in ETC_DENY {
                    hide_pattern(&layer.host, &upper, p)?;
                }
            }
            "var" => {
                hide_except(&layer.host, &upper, ".", VAR_ALLOW)?;
                hide_except(&layer.host, &upper, "lib", VAR_LIB_ALLOW)?;
                hide_except(&layer.host, &upper, "cache", VAR_CACHE_ALLOW)?;
            }
            _ => {}
        }
        if let Ok(rel) = store_root.strip_prefix(&layer.host) {
            if let Some(s) = rel.to_str().filter(|s| !s.is_empty()) {
                hide(&upper, s)?;
            }
        }
    }
    Ok(())
}

fn write_if_missing(path: &Path, content: &str, mode: u32) -> Result<()> {
    if upper_has(path) {
        return Ok(());
    }
    if let Some(p) = path.parent() {
        sys::mkdir_p(p, 0o755)?;
    }
    sys::write_file(path, content)?;
    sys::chmod(path, mode)
}

fn is_system_account(line: &str) -> bool {
    match line.split(':').nth(2).and_then(|u| u.parse::<u32>().ok()) {
        Some(id) => id < 1000 || id == 65534,
        None => false,
    }
}

fn human_accounts() -> Vec<String> {
    fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .filter(|l| !is_system_account(l))
        .filter_map(|l| l.split(':').next().map(str::to_string))
        .collect()
}

fn strip_members(line: &str, humans: &[String]) -> String {
    let f: Vec<&str> = line.split(':').collect();
    if f.len() < 4 {
        return format!("{line}\n");
    }
    let members: Vec<&str> = f[3]
        .split(',')
        .filter(|m| !m.is_empty() && !humans.iter().any(|h| h == m))
        .collect();
    format!("{}:{}:{}:{}\n", f[0], f[1], f[2], members.join(","))
}

pub fn seed(sb: &Sandbox, layout: &Layout) -> Result<()> {
    let root = layout.layer_upper(ROOT_LAYER);
    sys::mkdir_p(&root, 0o755)?;
    sys::mkdir_p(layout.work(), 0o700)?;
    sys::mkdir_p(layout.run(), 0o700)?;
    for l in host_layers() {
        sys::mkdir_p(layout.layer_upper(&l.name), 0o755)?;
    }

    let home = root.join("home").join(SANDBOX_USER);
    let rootdir = root.join("root");
    for (d, mode, uid) in [
        (root.join("tmp"), 0o1777, 0),
        (rootdir.clone(), 0o700, 0),
        (root.join("home"), 0o755, 0),
        (home.clone(), 0o750, SANDBOX_UID),
    ] {
        if !upper_has(&d) {
            sys::mkdir_p(&d, mode)?;
            sys::chmod(&d, mode)?;
            copy_skel(&d, uid)?;
            sys::lchown(&d, uid, uid)?;
        }
    }

    let etc = layout.layer_upper("etc");
    let etc_exists = |n: &str| upper_has(&etc.join(n));
    if !etc_exists("passwd") {
        let mut passwd: String = fs::read_to_string("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .filter(|l| is_system_account(l))
            .map(|l| format!("{l}\n"))
            .collect();
        passwd.push_str(&format!(
            "{SANDBOX_USER}:x:{SANDBOX_UID}:{SANDBOX_UID}:Sandbox User:/home/{SANDBOX_USER}:/bin/bash\n"
        ));
        write_if_missing(&etc.join("passwd"), &passwd, 0o644)?;
    }
    if !etc_exists("group") {
        let humans = human_accounts();
        let mut group: String = fs::read_to_string("/etc/group")
            .unwrap_or_default()
            .lines()
            .filter(|l| is_system_account(l))
            .map(|l| strip_members(l, &humans))
            .collect();
        group.push_str(&format!("{SANDBOX_USER}:x:{SANDBOX_UID}:\n"));
        write_if_missing(&etc.join("group"), &group, 0o644)?;
    }
    if !etc_exists("shadow") {
        let mut shadow = String::new();
        let users: Vec<String> = fs::read_to_string(etc.join("passwd"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split(':').next().map(str::to_string))
            .collect();
        for u in users {
            let pw = if u == "root" || u == SANDBOX_USER { "" } else { "*" };
            shadow.push_str(&format!("{u}:{pw}:19000:0:99999:7:::\n"));
        }
        write_if_missing(&etc.join("shadow"), &shadow, 0o640)?;
        let shadow_gid = fs::read_to_string(etc.join("group"))
            .ok()
            .and_then(|g| {
                g.lines()
                    .find(|l| l.starts_with("shadow:"))
                    .and_then(|l| l.split(':').nth(2))
                    .and_then(|s| s.parse::<u32>().ok())
            })
            .unwrap_or(42);
        sys::lchown(etc.join("shadow"), 0, shadow_gid)?;
    }
    write_if_missing(&etc.join("gshadow"), "root:*::\n", 0o640)?;
    write_if_missing(&etc.join("hostname"), &format!("{}\n", sb.name), 0o644)?;
    write_if_missing(
        &etc.join("hosts"),
        &format!(
            "127.0.0.1\tlocalhost\n127.0.1.1\t{}\n::1\tlocalhost ip6-localhost ip6-loopback\n",
            sb.name
        ),
        0o644,
    )?;
    write_if_missing(&etc.join("machine-id"), &format!("{}\n", random_hex(32)), 0o444)?;
    write_if_missing(&etc.join("fstab"), "", 0o644)?;
    let sudoers_d = etc.join("sudoers.d");
    if !upper_has(&sudoers_d) {
        sys::opaque_dir(&sudoers_d, 0o755)?;
    }
    write_if_missing(
        &sudoers_d.join("90-sandbox"),
        &format!("{SANDBOX_USER} ALL=(ALL:ALL) NOPASSWD: ALL\n"),
        0o440,
    )?;
    write_if_missing(&sudoers_d.join("README"), "", 0o440)?;

    let var = layout.layer_upper("var");
    for (d, mode) in VAR_SEED_DIRS {
        let p = var.join(d);
        if !upper_has(&p) {
            sys::opaque_dir(&p, *mode)?;
        }
    }
    let mail = var.join("mail");
    let mail_gid = fs::read_to_string(etc.join("group")).ok().and_then(|g| {
        g.lines()
            .find(|l| l.starts_with("mail:"))
            .and_then(|l| l.split(':').nth(2))
            .and_then(|s| s.parse::<u32>().ok())
    });
    if let Some(gid) = mail_gid {
        let _ = sys::lchown(&mail, 0, gid);
    }
    Ok(())
}

fn copy_skel(dest: &Path, uid: u32) -> Result<()> {
    let Ok(rd) = fs::read_dir("/etc/skel") else {
        return Ok(());
    };
    for e in rd.flatten() {
        let src = e.path();
        let dst = dest.join(e.file_name());
        let meta = match fs::symlink_metadata(&src) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_file() {
            fs::copy(&src, &dst).with_ctx(|| format!("copying {}", src.display()))?;
            fs::set_permissions(&dst, fs::Permissions::from_mode(meta.mode() & 0o777)).ok();
            sys::lchown(&dst, uid, uid)?;
        } else if meta.file_type().is_symlink() {
            if let Ok(t) = fs::read_link(&src) {
                let _ = symlink(t, &dst);
                let _ = sys::lchown(&dst, uid, uid);
            }
        }
    }
    Ok(())
}

pub fn write_resolv_conf(layout: &Layout, policy: &NetworkPolicy) -> Result<()> {
    let etc = layout.layer_upper("etc");
    sys::mkdir_p(&etc, 0o755)?;
    let content = if !policy.isolated {
        host_resolv_conf()
    } else if policy.internet {
        "nameserver 10.0.2.3\noptions ndots:0\n".to_string()
    } else {
        String::new()
    };
    let p = etc.join("resolv.conf");
    let _ = fs::remove_file(&p);
    sys::write_file(&p, content)?;
    sys::chmod(&p, 0o644)
}

fn host_resolv_conf() -> String {
    for p in ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
        if let Ok(s) = fs::read_to_string(p) {
            let ns: Vec<&str> = s.lines().filter(|l| l.starts_with("nameserver")).collect();
            if !ns.is_empty() {
                return s;
            }
        }
    }
    "nameserver 1.1.1.1\nnameserver 8.8.8.8\n".into()
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n / 2];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn build_skeleton(skel: &Path) -> Result<()> {
    if skel.exists() {
        fs::remove_dir_all(skel).with_ctx(|| format!("clearing {}", skel.display()))?;
    }
    sys::mkdir_p(skel, 0o755)?;
    for (d, mode) in crate::layout::SKEL_DIRS {
        let p = skel.join(d);
        sys::mkdir_p(&p, *mode)?;
        sys::chmod(&p, *mode)?;
    }
    for (name, target) in crate::layout::host_symlinks() {
        symlink(&target, skel.join(&name)).with_ctx(|| format!("creating symlink {name}"))?;
    }
    for l in host_layers() {
        let p = skel.join(&l.name);
        sys::mkdir_p(&p, 0o755)?;
    }
    Ok(())
}
