use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use sandbox_core::{Command, Error, IoContext, Result, Sandbox};
use sandbox_policy::normalize_sandbox_path;

use crate::cgroup::Cgroup;
use crate::layout::Layout;
use crate::mount;
use crate::ns::{self, IdMap};
use crate::rootfs::{self, Build};
use crate::supervisor::State;
use crate::sys::{self, Fork};
use crate::{caps, seccomp};

pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub groups: Vec<u32>,
}

fn lookup_user(spec: &str) -> Result<User> {
    let passwd = fs::read_to_string("/etc/passwd").ctx("reading /etc/passwd")?;
    let by_uid = spec.parse::<u32>().ok();
    let line = passwd
        .lines()
        .find(|l| {
            let mut f = l.split(':');
            let name = f.next().unwrap_or("");
            let uid = f.nth(1).and_then(|u| u.parse::<u32>().ok());
            name == spec || (by_uid.is_some() && uid == by_uid)
        })
        .ok_or_else(|| Error::Runtime(format!("user `{spec}` does not exist in the sandbox")))?;
    let f: Vec<&str> = line.split(':').collect();
    if f.len() < 7 {
        return Err(Error::Runtime("malformed /etc/passwd entry".into()));
    }
    let user = User {
        name: f[0].to_string(),
        uid: f[2].parse().map_err(|_| Error::Runtime("malformed uid".into()))?,
        gid: f[3].parse().map_err(|_| Error::Runtime("malformed gid".into()))?,
        home: if f[5].is_empty() {
            "/".into()
        } else {
            f[5].to_string()
        },
        shell: if f[6].is_empty() {
            "/bin/sh".into()
        } else {
            f[6].to_string()
        },
        groups: Vec::new(),
    };
    let groups = fs::read_to_string("/etc/group").unwrap_or_default();
    let mut gids: Vec<u32> = groups
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let gid = f.get(2)?.parse::<u32>().ok()?;
            let members = f.get(3).copied().unwrap_or("");
            members.split(',').any(|m| m == user.name).then_some(gid)
        })
        .collect();
    gids.push(user.gid);
    gids.dedup();
    Ok(User { groups: gids, ..user })
}

fn env_for(sb: &Sandbox, user: &User, cmd: &Command) -> Vec<CString> {
    let mut env: Vec<(String, String)> = vec![
        (
            "PATH".into(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        ),
        ("HOME".into(), user.home.clone()),
        ("USER".into(), user.name.clone()),
        ("LOGNAME".into(), user.name.clone()),
        ("SHELL".into(), user.shell.clone()),
        ("SANDBOX".into(), sb.name.clone()),
        (
            "TERM".into(),
            std::env::var("TERM").unwrap_or_else(|_| "xterm".into()),
        ),
    ];
    for k in ["LANG", "LC_ALL", "COLORTERM"] {
        if let Ok(v) = std::env::var(k) {
            env.push((k.into(), v));
        }
    }
    env.extend(rootfs::display_env(&sb.config.devices));
    env.extend(sb.config.env.iter().map(|(k, v)| (k.clone(), v.clone())));
    env.extend(cmd.env.iter().cloned());
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in env {
        out.retain(|(ek, _)| *ek != k);
        out.push((k, v));
    }
    out.into_iter()
        .filter_map(|(k, v)| CString::new(format!("{k}={v}")).ok())
        .collect()
}

fn exec_in_sandbox(sb: &Sandbox, cmd: &Command, user_spec: &str) -> Result<()> {
    let user = lookup_user(user_spec)?;
    let cwd = cmd.cwd.clone().unwrap_or_else(|| PathBuf::from(&user.home));
    let envp = env_for(sb, &user, cmd);
    let argv: Vec<CString> = cmd.argv.iter().map(sys::cstr).collect::<Result<_>>()?;
    if argv.is_empty() {
        return Err(Error::Runtime("no command given".into()));
    }
    seccomp::install(sb.config.security.nested_namespaces)?;
    caps::confine(sb.config.security.capabilities)?;
    let gids: Vec<libc::gid_t> = user.groups.iter().map(|g| *g as libc::gid_t).collect();
    sys::check_i(unsafe { libc::setgroups(gids.len(), gids.as_ptr()) }, || {
        "setgroups".into()
    })?;
    sys::check_i(unsafe { libc::setgid(user.gid) }, || "setgid".into())?;
    sys::check_i(unsafe { libc::setuid(user.uid) }, || "setuid".into())?;
    if std::env::set_current_dir(&cwd).is_err() {
        let _ = std::env::set_current_dir("/");
    }
    sys::unblock_all_signals();
    let mut argv_p: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    let mut env_p: Vec<*const libc::c_char> = envp.iter().map(|a| a.as_ptr()).collect();
    env_p.push(std::ptr::null());
    let path = envp
        .iter()
        .find_map(|e| e.to_str().ok()?.strip_prefix("PATH=").map(str::to_string))
        .unwrap_or_default();
    let prog = argv[0].to_str().unwrap_or("");
    let resolved = if prog.contains('/') {
        PathBuf::from(prog)
    } else {
        path.split(':')
            .map(|d| Path::new(d).join(prog))
            .find(|p| p.is_file())
            .ok_or_else(|| Error::Runtime(format!("command not found in sandbox: {prog}")))?
    };
    let resolved = sys::cstr(&resolved)?;
    unsafe { libc::execve(resolved.as_ptr(), argv_p.as_ptr(), env_p.as_ptr()) };
    let e = sys::errno();
    Err(Error::Io {
        context: format!("executing {prog}"),
        source: e,
    })
}

pub fn run(sb: &Sandbox, state: &State, cmd: &Command, user: &str) -> Result<i32> {
    let nsfds = ns::open_ns(state.init_pid, false)?;
    let cg = Cgroup::open(&sb.name);
    match sys::fork()? {
        Fork::Child => {
            let r = (|| -> Result<i32> {
                cg.add_pid(sys::getpid())?;
                nsfds.enter()?;
                match sys::fork()? {
                    Fork::Child => {
                        if let Err(e) = exec_in_sandbox(sb, cmd, user) {
                            eprintln!("sandbox: {e}");
                            sys::exit(126);
                        }
                        unreachable!()
                    }
                    Fork::Parent(pid) => sys::waitpid(pid),
                }
            })();
            match r {
                Ok(code) => sys::exit(code),
                Err(e) => {
                    eprintln!("sandbox: {e}");
                    sys::exit(125);
                }
            }
        }
        Fork::Parent(pid) => sys::waitpid(pid),
    }
}

fn enter_fs(state: &State) -> Result<()> {
    let user = File::open(format!("/proc/{}/ns/user", state.init_pid)).ctx("opening user namespace")?;
    let mnt = File::open(format!("/proc/{}/ns/mnt", state.init_pid)).ctx("opening mount namespace")?;
    sys::setns(mnt.as_raw_fd(), libc::CLONE_NEWNS)?;
    sys::setns(user.as_raw_fd(), libc::CLONE_NEWUSER)?;
    sys::become_uid(0)
}

fn offline_fs(sb: &Sandbox, layout: &Layout) -> Result<()> {
    sys::unshare(libc::CLONE_NEWNS)?;
    mount::make_private_root()?;
    rootfs::build(&Build {
        sandbox: sb,
        layout,
        map: IdMap::identity(),
        userns: None,
        full: false,
    })?;
    mount::chroot(&layout.rootfs())
}

pub fn with_fs<F: FnOnce() -> Result<()>>(
    sb: &Sandbox,
    layout: &Layout,
    state: Option<&State>,
    f: F,
) -> Result<()> {
    sys::run_child("file transfer", move || {
        match state {
            Some(s) => enter_fs(s)?,
            None => offline_fs(sb, layout)?,
        }
        f()
    })
}

fn copy_fd(src: &File, dst: &File) -> io::Result<()> {
    let mut r = src;
    let mut w = dst;
    io::copy(&mut r, &mut w).map(drop)
}

pub fn put(sb: &Sandbox, layout: &Layout, state: Option<&State>, source: &Path, dest: &Path) -> Result<()> {
    let dest = normalize_sandbox_path(dest)?;
    let src = File::open(source).with_ctx(|| format!("opening {}", source.display()))?;
    let meta = src.metadata().ctx("stat")?;
    if meta.is_dir() {
        return Err(Error::Runtime(
            "directories are not supported yet; transfer an archive instead".into(),
        ));
    }
    let mode = meta.mode() & 0o777;
    with_fs(sb, layout, state, move || {
        let target = if dest.is_dir() {
            dest.join(
                source
                    .file_name()
                    .ok_or_else(|| Error::Runtime("source has no file name".into()))?,
            )
        } else {
            dest
        };
        if let Some(p) = target.parent() {
            fs::create_dir_all(p).with_ctx(|| format!("creating {}", p.display()))?;
        }
        let out = File::create(&target).with_ctx(|| format!("creating {} in sandbox", target.display()))?;
        copy_fd(&src, &out).with_ctx(|| format!("copying to {}", target.display()))?;
        fs::set_permissions(&target, fs::Permissions::from_mode(mode)).ok();
        Ok(())
    })
}

pub fn get(sb: &Sandbox, layout: &Layout, state: Option<&State>, source: &Path, dest: &Path) -> Result<()> {
    let source = normalize_sandbox_path(source)?;
    let dest = if dest.is_dir() {
        dest.join(
            source
                .file_name()
                .ok_or_else(|| Error::Runtime("source has no file name".into()))?,
        )
    } else {
        dest.to_path_buf()
    };
    let existed = dest.exists();
    let out = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&dest)
        .with_ctx(|| format!("opening {}", dest.display()))?;
    let r = with_fs(sb, layout, state, move || {
        let src = File::open(&source).with_ctx(|| format!("opening {} in sandbox", source.display()))?;
        let meta = src.metadata().ctx("stat")?;
        if meta.is_dir() {
            return Err(Error::Runtime(
                "directories are not supported yet; transfer an archive instead".into(),
            ));
        }
        out.set_len(0).ctx("truncating destination")?;
        copy_fd(&src, &out).with_ctx(|| format!("copying {}", source.display()))?;
        let _ = out.set_permissions(fs::Permissions::from_mode(meta.mode() & 0o777));
        Ok(())
    });
    if r.is_err() && !existed {
        let _ = fs::remove_file(&dest);
    }
    r
}
