use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::{Duration, Instant};

use sandbox_core::{Error, IoContext, Result};

pub fn cstr(p: impl AsRef<OsStr>) -> Result<CString> {
    CString::new(p.as_ref().as_bytes())
        .map_err(|_| Error::Runtime(format!("path contains NUL: {:?}", p.as_ref())))
}

pub fn errno() -> io::Error {
    io::Error::last_os_error()
}

pub fn check(ret: libc::c_long, what: impl FnOnce() -> String) -> Result<libc::c_long> {
    if ret < 0 {
        Err(Error::Io {
            context: what(),
            source: errno(),
        })
    } else {
        Ok(ret)
    }
}

pub fn check_i(ret: libc::c_int, what: impl FnOnce() -> String) -> Result<libc::c_int> {
    check(ret as libc::c_long, what).map(|r| r as libc::c_int)
}

pub fn write_file(path: impl AsRef<Path>, data: impl AsRef<[u8]>) -> Result<()> {
    let path = path.as_ref();
    fs::write(path, data).with_ctx(|| format!("writing {}", path.display()))
}

pub fn mkdir_p(path: impl AsRef<Path>, mode: u32) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let path = path.as_ref();
    if path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(parent)
            .with_ctx(|| format!("creating {}", parent.display()))?;
    }
    match fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(e) => Err(Error::Io {
            context: format!("creating {}", path.display()),
            source: e,
        }),
    }
}

pub fn chmod(path: impl AsRef<Path>, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = path.as_ref();
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_ctx(|| format!("chmod {}", path.display()))
}

pub fn lchown(path: impl AsRef<Path>, uid: u32, gid: u32) -> Result<()> {
    let path = path.as_ref();
    let c = cstr(path)?;
    check_i(unsafe { libc::lchown(c.as_ptr(), uid, gid) }, || {
        format!("chown {}", path.display())
    })?;
    Ok(())
}

pub fn set_xattr(path: impl AsRef<Path>, name: &str, value: &[u8]) -> Result<()> {
    let path = path.as_ref();
    let c = cstr(path)?;
    let n = CString::new(name).expect("static name");
    check_i(
        unsafe { libc::lsetxattr(c.as_ptr(), n.as_ptr(), value.as_ptr().cast(), value.len(), 0) },
        || format!("setting {name} on {}", path.display()),
    )?;
    Ok(())
}

pub fn mknod(path: impl AsRef<Path>, mode: u32, dev: libc::dev_t) -> Result<()> {
    let path = path.as_ref();
    let c = cstr(path)?;
    check_i(unsafe { libc::mknod(c.as_ptr(), mode, dev) }, || {
        format!("mknod {}", path.display())
    })?;
    Ok(())
}

pub fn whiteout(path: impl AsRef<Path>) -> Result<()> {
    mknod(path, libc::S_IFCHR, libc::makedev(0, 0))
}

pub fn opaque_dir(path: impl AsRef<Path>, mode: u32) -> Result<()> {
    let path = path.as_ref();
    mkdir_p(path, mode)?;
    chmod(path, mode)?;
    set_xattr(path, "trusted.overlay.opaque", b"y")
}

pub fn sethostname(name: &str) -> Result<()> {
    check_i(
        unsafe { libc::sethostname(name.as_ptr().cast(), name.len()) },
        || "setting hostname".into(),
    )?;
    Ok(())
}

pub fn unshare(flags: libc::c_int) -> Result<()> {
    check_i(unsafe { libc::unshare(flags) }, || {
        format!("unshare(0x{flags:x})")
    })?;
    Ok(())
}

pub fn setns(fd: RawFd, nstype: libc::c_int) -> Result<()> {
    check_i(unsafe { libc::setns(fd, nstype) }, || {
        format!("setns(0x{nstype:x})")
    })?;
    Ok(())
}

pub fn prctl(
    option: libc::c_int,
    a2: libc::c_ulong,
    a3: libc::c_ulong,
    a4: libc::c_ulong,
    a5: libc::c_ulong,
) -> Result<libc::c_int> {
    check_i(unsafe { libc::prctl(option, a2, a3, a4, a5) }, || {
        format!("prctl({option})")
    })
}

pub fn set_subreaper() -> Result<()> {
    prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0).map(drop)
}

pub fn set_pdeathsig(sig: libc::c_int) -> Result<()> {
    prctl(libc::PR_SET_PDEATHSIG, sig as libc::c_ulong, 0, 0, 0).map(drop)
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn getpid() -> libc::pid_t {
    unsafe { libc::getpid() }
}

pub struct Pipe {
    pub read: OwnedFd,
    pub write: OwnedFd,
}

pub fn pipe() -> Result<Pipe> {
    let mut fds = [0; 2];
    check_i(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, || {
        "pipe".into()
    })?;
    Ok(Pipe {
        read: unsafe { OwnedFd::from_raw_fd(fds[0]) },
        write: unsafe { OwnedFd::from_raw_fd(fds[1]) },
    })
}

pub fn read_all(fd: &OwnedFd) -> Result<Vec<u8>> {
    let mut f = unsafe { File::from_raw_fd(fd.as_raw_fd()) };
    let mut buf = Vec::new();
    let r = f.read_to_end(&mut buf);
    std::mem::forget(f);
    r.ctx("reading pipe")?;
    Ok(buf)
}

pub fn read_byte(fd: &OwnedFd) -> Result<Option<u8>> {
    let mut b = [0u8; 1];
    loop {
        let n = unsafe { libc::read(fd.as_raw_fd(), b.as_mut_ptr().cast(), 1) };
        if n < 0 {
            let e = errno();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Io {
                context: "reading pipe".into(),
                source: e,
            });
        }
        return Ok(if n == 0 { None } else { Some(b[0]) });
    }
}

pub fn write_all(fd: &OwnedFd, data: &[u8]) -> Result<()> {
    let mut f = unsafe { File::from_raw_fd(fd.as_raw_fd()) };
    let r = f.write_all(data);
    std::mem::forget(f);
    r.ctx("writing pipe")
}

pub enum Fork {
    Parent(libc::pid_t),
    Child,
}

pub fn fork() -> Result<Fork> {
    let pid = check_i(unsafe { libc::fork() }, || "fork".into())?;
    Ok(if pid == 0 { Fork::Child } else { Fork::Parent(pid) })
}

pub fn exit(code: i32) -> ! {
    unsafe { libc::_exit(code) }
}

pub fn exit_status(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

pub fn waitpid(pid: libc::pid_t) -> Result<i32> {
    let mut status = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r < 0 {
            let e = errno();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Io {
                context: format!("waiting for pid {pid}"),
                source: e,
            });
        }
        return Ok(exit_status(status));
    }
}

pub fn try_wait(pid: libc::pid_t) -> Result<Option<i32>> {
    let mut status = 0;
    let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if r < 0 {
        let e = errno();
        if e.raw_os_error() == Some(libc::ECHILD) {
            return Ok(Some(1));
        }
        return Err(Error::Io {
            context: format!("waiting for pid {pid}"),
            source: e,
        });
    }
    Ok((r == pid).then(|| exit_status(status)))
}

pub fn reap_any() {
    loop {
        let r = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        if r <= 0 {
            break;
        }
    }
}

pub fn kill(pid: libc::pid_t, sig: libc::c_int) -> bool {
    unsafe { libc::kill(pid, sig) == 0 }
}

pub fn alive(pid: libc::pid_t) -> bool {
    pid > 0 && Path::new(&format!("/proc/{pid}")).exists()
}

pub fn wait_pid_gone(pid: libc::pid_t, timeout: Duration) -> bool {
    let start = Instant::now();
    while alive(pid) {
        if start.elapsed() > timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

pub fn run_child<F: FnOnce() -> Result<()>>(what: &str, f: F) -> Result<()> {
    let p = pipe()?;
    match fork()? {
        Fork::Child => {
            drop(p.read);
            let code = match f() {
                Ok(()) => 0,
                Err(e) => {
                    let _ = write_all(&p.write, e.to_string().as_bytes());
                    1
                }
            };
            exit(code)
        }
        Fork::Parent(pid) => {
            drop(p.write);
            let msg = read_all(&p.read).unwrap_or_default();
            let code = waitpid(pid)?;
            if code == 0 {
                Ok(())
            } else if msg.is_empty() {
                Err(Error::Runtime(format!(
                    "{what}: helper exited with status {code}"
                )))
            } else {
                Err(Error::Runtime(String::from_utf8_lossy(&msg).into_owned()))
            }
        }
    }
}

pub fn block_signals(sigs: &[libc::c_int]) -> Result<libc::sigset_t> {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in sigs {
            libc::sigaddset(&mut set, *s);
        }
        check_i(
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
            || "blocking signals".into(),
        )?;
        Ok(set)
    }
}

pub fn unblock_all_signals() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
    }
}

pub fn wait_signal(set: &libc::sigset_t, timeout: Option<Duration>) -> Option<libc::c_int> {
    let ts = timeout.map(|t| libc::timespec {
        tv_sec: t.as_secs() as _,
        tv_nsec: t.subsec_nanos() as libc::c_long,
    });
    let r = unsafe {
        libc::sigtimedwait(
            set,
            std::ptr::null_mut(),
            ts.as_ref().map_or(std::ptr::null(), |t| t as *const _),
        )
    };
    (r > 0).then_some(r)
}

pub fn dup2(from: RawFd, to: RawFd) -> Result<()> {
    check_i(unsafe { libc::dup2(from, to) }, || "dup2".into())?;
    Ok(())
}

pub fn redirect_stdio(stdin: &Path, out: &Path) -> Result<()> {
    let i = File::open(stdin).with_ctx(|| format!("opening {}", stdin.display()))?;
    let o = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(out)
        .with_ctx(|| format!("opening {}", out.display()))?;
    dup2(i.as_raw_fd(), 0)?;
    dup2(o.as_raw_fd(), 1)?;
    dup2(o.as_raw_fd(), 2)?;
    Ok(())
}

pub fn setsid() -> Result<()> {
    check_i(unsafe { libc::setsid() }, || "setsid".into())?;
    Ok(())
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let extra = [
        "/usr/sbin",
        "/sbin",
        "/usr/bin",
        "/bin",
        "/usr/local/sbin",
        "/usr/local/bin",
    ];
    std::env::split_paths(&path)
        .chain(extra.iter().map(std::path::PathBuf::from))
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

pub fn poll_readable(fd: &OwnedFd, timeout_ms: i32) -> bool {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    unsafe { libc::poll(&mut p, 1, timeout_ms) > 0 }
}

pub fn read_line(fd: &OwnedFd) -> Result<String> {
    let mut buf = Vec::new();
    while let Some(b) = read_byte(fd)? {
        if b == b'\n' {
            break;
        }
        buf.push(b);
        if buf.len() > 65536 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

const SECBIT_NO_SETUID_FIXUP: libc::c_ulong = 0x4;

pub struct FsIds;

impl FsIds {
    pub fn switch(uid: u32) -> Result<Self> {
        prctl(libc::PR_SET_SECUREBITS, SECBIT_NO_SETUID_FIXUP, 0, 0, 0)?;
        unsafe {
            libc::setfsuid(uid);
            libc::setfsgid(uid);
        }
        Ok(Self)
    }
}

impl Drop for FsIds {
    fn drop(&mut self) {
        unsafe {
            libc::setfsuid(0);
            libc::setfsgid(0);
        }
        let _ = prctl(libc::PR_SET_SECUREBITS, 0, 0, 0, 0);
    }
}

pub fn umask(mask: libc::mode_t) {
    unsafe {
        libc::umask(mask);
    }
}

pub fn become_uid(uid: u32) -> Result<()> {
    let gids = [uid as libc::gid_t];
    check_i(unsafe { libc::setgroups(1, gids.as_ptr()) }, || {
        "setgroups".into()
    })?;
    check_i(unsafe { libc::setgid(uid) }, || "setgid".into())?;
    check_i(unsafe { libc::setuid(uid) }, || "setuid".into())?;
    Ok(())
}

pub fn poll_hup(fd: &OwnedFd) -> bool {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    unsafe { libc::poll(&mut p, 1, 0) > 0 && p.revents & libc::POLLHUP != 0 }
}
