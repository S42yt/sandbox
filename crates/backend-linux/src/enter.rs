use std::ffi::CString;
use std::fs::{self, File};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use sandbox_core::{Command, Error, IoContext, Result, Sandbox};
use sandbox_policy::normalize_sandbox_path;

use crate::cgroup::Cgroup;
use crate::copy;
use crate::layout::Layout;
use crate::mount;
use crate::ns::{self, IdMap};
use crate::rootfs::{self, Build};
use crate::supervisor::State;
use crate::sys::{self, Fork};
use crate::{caps, pty, seccomp};

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

fn exec_in_sandbox(sb: &Sandbox, cmd: &Command, user_spec: &str, slave: Option<&str>) -> Result<()> {
    let user = lookup_user(user_spec)?;
    let cwd = cmd.cwd.clone().unwrap_or_else(|| PathBuf::from(&user.home));
    let envp = env_for(sb, &user, cmd);
    let argv: Vec<CString> = cmd.argv.iter().map(sys::cstr).collect::<Result<_>>()?;
    if argv.is_empty() {
        return Err(Error::Runtime("no command given".into()));
    }
    if let Some(path) = slave {
        pty::attach_slave(path, user.uid)?;
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
                sys::become_uid(0)?;
                let master = if pty::interactive() {
                    Some(pty::open_master()?)
                } else {
                    None
                };
                match sys::fork()? {
                    Fork::Child => {
                        let slave = master.as_ref().map(|m| m.slave.as_str());
                        if let Err(e) = exec_in_sandbox(sb, cmd, user, slave) {
                            eprintln!("sandbox: {e}");
                            sys::exit(126);
                        }
                        unreachable!()
                    }
                    Fork::Parent(pid) => match master {
                        Some(m) => pty::proxy(&m.fd, pid),
                        None => sys::waitpid(pid),
                    },
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

fn enter_or_mount(sb: &Sandbox, layout: &Layout, state: Option<&State>) -> Result<()> {
    match state {
        Some(s) => enter_fs(s),
        None => offline_fs(sb, layout),
    }
}

#[derive(Clone, Copy)]
enum Direction {
    HostToSandbox,
    SandboxToHost,
}

fn transfer<H, S>(
    sb: &Sandbox,
    layout: &Layout,
    state: Option<&State>,
    direction: Direction,
    host_side: H,
    sandbox_side: S,
) -> Result<()>
where
    H: FnOnce(File) -> Result<()>,
    S: FnOnce(File) -> Result<()>,
{
    let pipe = sys::pipe()?;
    let errors = sys::pipe()?;
    let read_end = File::from(pipe.read);
    let write_end = File::from(pipe.write);
    let (host_fd, sandbox_fd) = match direction {
        Direction::HostToSandbox => (write_end, read_end),
        Direction::SandboxToHost => (read_end, write_end),
    };
    let host_pid = match sys::fork()? {
        Fork::Child => {
            drop(sandbox_fd);
            drop(errors.read);
            finish(host_side(host_fd), &errors.write)
        }
        Fork::Parent(pid) => pid,
    };
    drop(host_fd);
    let sandbox_pid = match sys::fork()? {
        Fork::Child => {
            drop(errors.read);
            let r = enter_or_mount(sb, layout, state).and_then(|()| sandbox_side(sandbox_fd));
            finish(r, &errors.write)
        }
        Fork::Parent(pid) => pid,
    };
    drop(sandbox_fd);
    let pids = [host_pid, sandbox_pid];
    drop(errors.write);
    let msg = sys::read_all(&errors.read).unwrap_or_default();
    let mut failed = false;
    for pid in pids {
        failed |= sys::waitpid(pid)? != 0;
    }
    if failed {
        let m = String::from_utf8_lossy(&msg);
        let first = m.lines().next().unwrap_or("transfer failed").to_string();
        return Err(Error::Runtime(first));
    }
    Ok(())
}

fn finish(r: Result<()>, errors: &std::os::unix::io::OwnedFd) -> ! {
    if let Err(e) = r {
        let _ = sys::write_all(errors, format!("{e}\n").as_bytes());
        sys::exit(1);
    }
    sys::exit(0)
}

fn split_target(path: &Path) -> Result<(PathBuf, CString)> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::Runtime(format!("`{}` has no file name", path.display())))?;
    let parent = path.parent().unwrap_or(Path::new("/")).to_path_buf();
    Ok((parent, sys::cstr(name)?))
}

pub fn put(sb: &Sandbox, layout: &Layout, state: Option<&State>, source: &Path, dest: &Path) -> Result<()> {
    let dest = normalize_sandbox_path(dest)?;
    let source = source
        .canonicalize()
        .with_ctx(|| format!("reading {}", source.display()))?;
    let (src_parent, src_name) = split_target(&source)?;
    let src_dir = copy::open_dir(&src_parent)?;
    let base = source.file_name().map(|n| n.to_os_string());
    transfer(
        sb,
        layout,
        state,
        Direction::HostToSandbox,
        move |mut out| copy::pack(src_dir.as_raw_fd(), &src_name, &mut out),
        move |mut input| {
            let target = match base {
                Some(b) if dest.is_dir() => dest.join(b),
                _ => dest,
            };
            let (parent, name) = split_target(&target)?;
            fs::create_dir_all(&parent).with_ctx(|| format!("creating {} in sandbox", parent.display()))?;
            let parent_fd = copy::open_dir(&parent)?;
            copy::unpack(parent_fd.as_raw_fd(), &name, &mut input)
        },
    )
}

pub fn get(sb: &Sandbox, layout: &Layout, state: Option<&State>, source: &Path, dest: &Path) -> Result<()> {
    let source = normalize_sandbox_path(source)?;
    let target = match source.file_name() {
        Some(b) if dest.is_dir() => dest.join(b),
        _ => dest.to_path_buf(),
    };
    let (parent, name) = split_target(&target)?;
    let parent_fd = copy::open_dir(&parent)?;
    let existed = fs::symlink_metadata(&target).is_ok();
    let (src_parent, src_name) = split_target(&source)?;
    let r = transfer(
        sb,
        layout,
        state,
        Direction::SandboxToHost,
        move |mut input| copy::unpack(parent_fd.as_raw_fd(), &name, &mut input),
        move |mut out| {
            let src_dir = copy::open_dir(&src_parent)?;
            copy::pack(src_dir.as_raw_fd(), &src_name, &mut out)
        },
    );
    if r.is_err() && !existed {
        let _ = fs::remove_file(&target);
        let _ = fs::remove_dir_all(&target);
    }
    r
}
