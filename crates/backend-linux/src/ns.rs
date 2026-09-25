use std::fs::File;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::path::PathBuf;

use sandbox_core::{Error, IoContext, Result};

use crate::sys::{self, Fork};

pub const UID_COUNT: u32 = 65536;

#[derive(Debug, Clone, Copy)]
pub struct IdMap {
    pub base: u32,
    pub count: u32,
}

impl IdMap {
    pub fn identity() -> Self {
        Self {
            base: 0,
            count: UID_COUNT,
        }
    }

    pub fn host_uid(&self, sandbox_uid: u32) -> u32 {
        self.base.wrapping_add(sandbox_uid)
    }
}

pub fn write_maps(pid: libc::pid_t, map: IdMap) -> Result<()> {
    let line = format!("0 {} {}\n", map.base, map.count);
    let base = PathBuf::from(format!("/proc/{pid}"));
    sys::write_file(base.join("setgroups"), "allow\n")?;
    sys::write_file(base.join("uid_map"), &line)?;
    sys::write_file(base.join("gid_map"), &line)?;
    Ok(())
}

pub fn template_userns(map: IdMap) -> Result<OwnedFd> {
    let to_parent = sys::pipe()?;
    let to_child = sys::pipe()?;
    match sys::fork()? {
        Fork::Child => {
            drop(to_parent.read);
            drop(to_child.write);
            let ok = sys::unshare(libc::CLONE_NEWUSER).is_ok();
            let _ = sys::write_all(&to_parent.write, &[u8::from(ok)]);
            drop(to_parent.write);
            let _ = sys::read_byte(&to_child.read);
            sys::exit(0)
        }
        Fork::Parent(pid) => {
            drop(to_parent.write);
            drop(to_child.read);
            let ok = sys::read_byte(&to_parent.read)?;
            let result = if ok == Some(1) {
                write_maps(pid, map).and_then(|()| {
                    File::open(format!("/proc/{pid}/ns/user"))
                        .with_ctx(|| "opening template user namespace".to_string())
                        .map(OwnedFd::from)
                })
            } else {
                Err(Error::Runtime("cannot create user namespaces on this host (check kernel.unprivileged_userns_clone / user.max_user_namespaces)".into()))
            };
            drop(to_child.write);
            let _ = sys::waitpid(pid);
            result
        }
    }
}

pub const NS_ALL: &[(&str, libc::c_int)] = &[
    ("mnt", libc::CLONE_NEWNS),
    ("pid", libc::CLONE_NEWPID),
    ("net", libc::CLONE_NEWNET),
    ("ipc", libc::CLONE_NEWIPC),
    ("uts", libc::CLONE_NEWUTS),
    ("cgroup", libc::CLONE_NEWCGROUP),
    ("user", libc::CLONE_NEWUSER),
];

pub struct NsFds {
    fds: Vec<(libc::c_int, OwnedFd)>,
}

pub fn open_ns(pid: libc::pid_t, skip_net: bool) -> Result<NsFds> {
    let mut fds = Vec::new();
    for (name, flag) in NS_ALL {
        if skip_net && *flag == libc::CLONE_NEWNET {
            continue;
        }
        let p = format!("/proc/{pid}/ns/{name}");
        let f = File::open(&p).with_ctx(|| format!("opening {p}"))?;
        fds.push((*flag, OwnedFd::from(f)));
    }
    Ok(NsFds { fds })
}

impl NsFds {
    pub fn enter(&self) -> Result<()> {
        for (flag, fd) in &self.fds {
            sys::setns(fd.as_raw_fd(), *flag)?;
        }
        Ok(())
    }
}
