use std::ffi::CStr;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

use sandbox_core::{Error, Result};

use crate::sys::{self, check_i};

static WINCH: AtomicBool = AtomicBool::new(false);

extern "C" fn on_winch(_: libc::c_int) {
    WINCH.store(true, Ordering::SeqCst);
}

pub fn interactive() -> bool {
    unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 }
}

pub struct Master {
    pub fd: OwnedFd,
    pub slave: String,
}

pub fn open_master() -> Result<Master> {
    let fd = check_i(
        unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) },
        || "opening /dev/ptmx in the sandbox".into(),
    )?;
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    check_i(unsafe { libc::grantpt(fd.as_raw_fd()) }, || "grantpt".into())?;
    check_i(unsafe { libc::unlockpt(fd.as_raw_fd()) }, || "unlockpt".into())?;
    let mut buf = [0 as libc::c_char; 64];
    check_i(
        unsafe { libc::ptsname_r(fd.as_raw_fd(), buf.as_mut_ptr(), buf.len()) },
        || "ptsname".into(),
    )?;
    let slave = unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    copy_winsize(0, fd.as_raw_fd());
    Ok(Master { fd, slave })
}

pub fn attach_slave(path: &str, uid: u32) -> Result<()> {
    check_i(unsafe { libc::setsid() }, || "setsid".into())?;
    let p = sys::cstr(path)?;
    let slave = check_i(
        unsafe { libc::open(p.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) },
        || format!("opening {path}"),
    )?;
    check_i(unsafe { libc::ioctl(slave, libc::TIOCSCTTY as _, 0) }, || {
        "TIOCSCTTY".into()
    })?;
    unsafe {
        libc::fchown(slave, uid, 5);
        libc::fchmod(slave, 0o620);
    }
    for target in 0..3 {
        sys::dup2(slave, target)?;
    }
    unsafe { libc::close(slave) };
    Ok(())
}

fn copy_winsize(from: RawFd, to: RawFd) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(from, libc::TIOCGWINSZ as _, &mut ws) } == 0 {
        unsafe { libc::ioctl(to, libc::TIOCSWINSZ as _, &ws) };
    }
}

struct RawMode {
    saved: Option<libc::termios>,
}

impl RawMode {
    fn enable() -> Self {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(0, &mut t) } != 0 {
            return Self { saved: None };
        }
        let saved = t;
        unsafe {
            libc::cfmakeraw(&mut t);
            libc::tcsetattr(0, libc::TCSANOW, &t);
        }
        Self { saved: Some(saved) }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if let Some(t) = &self.saved {
            unsafe { libc::tcsetattr(0, libc::TCSANOW, t) };
        }
    }
}

fn write_fully(fd: RawFd, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        data = &data[n as usize..];
    }
    Ok(())
}

fn read_some(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

pub fn proxy(master: &OwnedFd, child: libc::pid_t) -> Result<i32> {
    let _raw = RawMode::enable();
    unsafe {
        libc::signal(libc::SIGWINCH, on_winch as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
        libc::signal(libc::SIGTSTP, libc::SIG_IGN);
    }
    let m = master.as_raw_fd();
    let mut buf = vec![0u8; 65536];
    let mut stdin_open = true;
    let mut status = None;
    loop {
        if WINCH.swap(false, Ordering::SeqCst) {
            copy_winsize(0, m);
        }
        let mut fds = [
            libc::pollfd {
                fd: m,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if stdin_open { 0 } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout = if status.is_some() { 0 } else { 200 };
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Io {
                context: "terminal proxy".into(),
                source: e,
            });
        }
        if fds[0].revents != 0 {
            match read_some(m, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if write_fully(1, &buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        if fds[1].revents != 0 {
            match read_some(0, &mut buf) {
                Ok(0) | Err(_) => {
                    stdin_open = false;
                    let eof = [0x04u8];
                    let _ = write_fully(m, &eof);
                }
                Ok(n) => {
                    if write_fully(m, &buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        if status.is_none() {
            status = sys::try_wait(child)?;
        } else if r == 0 {
            break;
        }
    }
    match status {
        Some(s) => Ok(s),
        None => sys::waitpid(child),
    }
}
