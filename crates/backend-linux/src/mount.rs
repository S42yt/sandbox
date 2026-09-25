use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use sandbox_core::{Error, Result};

use crate::sys::{check, check_i, cstr, errno, mkdir_p};

pub const MS_RO: libc::c_ulong = libc::MS_RDONLY;
pub const STD_NOEXEC: libc::c_ulong = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;

pub fn mount(src: &str, target: &Path, fstype: &str, flags: libc::c_ulong, data: Option<&str>) -> Result<()> {
    let s = cstr(src)?;
    let t = cstr(target)?;
    let f = cstr(fstype)?;
    let d = data.map(cstr).transpose()?;
    check_i(
        unsafe {
            libc::mount(
                s.as_ptr(),
                t.as_ptr(),
                f.as_ptr(),
                flags,
                d.as_ref().map_or(std::ptr::null(), |d| d.as_ptr().cast()),
            )
        },
        || format!("mounting {fstype} on {}", target.display()),
    )?;
    Ok(())
}

pub fn bind(src: &Path, target: &Path, readonly: bool, recursive: bool) -> Result<()> {
    let s = cstr(src)?;
    let t = cstr(target)?;
    let mut flags = libc::MS_BIND;
    if recursive {
        flags |= libc::MS_REC;
    }
    check_i(
        unsafe { libc::mount(s.as_ptr(), t.as_ptr(), std::ptr::null(), flags, std::ptr::null()) },
        || format!("bind-mounting {} on {}", src.display(), target.display()),
    )?;
    if readonly {
        remount_ro(target, recursive)?;
    }
    Ok(())
}

pub fn remount_ro(target: &Path, recursive: bool) -> Result<()> {
    let t = cstr(target)?;
    let mut flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;
    if recursive {
        flags |= libc::MS_REC;
    }
    check_i(
        unsafe {
            libc::mount(
                std::ptr::null(),
                t.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            )
        },
        || format!("making {} read-only", target.display()),
    )?;
    Ok(())
}

pub fn make_private_root() -> Result<()> {
    let t = cstr("/")?;
    check_i(
        unsafe {
            libc::mount(
                std::ptr::null(),
                t.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        || "making mounts private".into(),
    )?;
    Ok(())
}

pub fn tmpfs(target: &Path, mode: u32, uid: u32, extra: &str) -> Result<()> {
    mkdir_p(target, 0o755)?;
    let data = format!("mode={mode:o},uid={uid},gid={uid}{extra}");
    mount(
        "tmpfs",
        target,
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        Some(&data),
    )
}

pub fn overlay(target: &Path, lower: &Path, upper: &Path, work: &Path, flags: libc::c_ulong) -> Result<()> {
    let data = format!(
        "lowerdir={},upperdir={},workdir={}",
        escape(lower),
        escape(upper),
        escape(work)
    );
    mount("overlay", target, "overlay", flags, Some(&data))
}

fn escape(p: &Path) -> String {
    let mut out = String::new();
    for c in p.to_string_lossy().chars() {
        if matches!(c, ',' | ':' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_NOSUID: u64 = 0x2;
const MOUNT_ATTR_NODEV: u64 = 0x4;
const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;
const OPEN_TREE_CLONE: libc::c_uint = 1;
const AT_RECURSIVE: libc::c_uint = 0x8000;
const AT_EMPTY_PATH: libc::c_uint = 0x1000;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;

pub fn open_tree_clone(src: &Path, recursive: bool) -> Result<OwnedFd> {
    let s = cstr(src)?;
    let mut flags = OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint;
    if recursive {
        flags |= AT_RECURSIVE;
    }
    let fd = check(
        unsafe { libc::syscall(libc::SYS_open_tree, libc::AT_FDCWD, s.as_ptr(), flags) },
        || format!("open_tree({})", src.display()),
    )?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

pub fn set_idmap(tree: &OwnedFd, userns: RawFd, readonly: bool) -> Result<()> {
    let mut attr = MountAttr {
        attr_set: MOUNT_ATTR_IDMAP | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
        attr_clr: 0,
        propagation: 0,
        userns_fd: userns as u64,
    };
    if readonly {
        attr.attr_set |= MOUNT_ATTR_RDONLY;
    }
    let empty = cstr("")?;
    check(
        unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                tree.as_raw_fd(),
                empty.as_ptr(),
                AT_EMPTY_PATH,
                &attr as *const MountAttr,
                std::mem::size_of::<MountAttr>(),
            )
        },
        || "mount_setattr(idmap)".into(),
    )?;
    Ok(())
}

pub fn attach(tree: OwnedFd, target: &Path) -> Result<()> {
    let empty = cstr("")?;
    let t = cstr(target)?;
    check(
        unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                tree.as_raw_fd(),
                empty.as_ptr(),
                libc::AT_FDCWD,
                t.as_ptr(),
                MOVE_MOUNT_F_EMPTY_PATH,
            )
        },
        || format!("attaching mount at {}", target.display()),
    )?;
    Ok(())
}

pub fn idmap_supported() -> bool {
    let r = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            -1,
            std::ptr::null::<u8>(),
            0,
            std::ptr::null::<u8>(),
            0,
        )
    };
    r >= 0 || errno().raw_os_error() != Some(libc::ENOSYS)
}

pub fn idmapped_bind(src: &Path, target: &Path, userns: RawFd, readonly: bool) -> Result<()> {
    mkdir_p(target, 0o755)?;
    let tree = open_tree_clone(src, false)?;
    set_idmap(&tree, userns, readonly)?;
    attach(tree, target)
}

pub fn pivot_into(rootfs: &Path) -> Result<()> {
    let r = cstr(rootfs)?;
    check_i(unsafe { libc::chdir(r.as_ptr()) }, || {
        format!("chdir {}", rootfs.display())
    })?;
    let dot = cstr(".")?;
    check(
        unsafe { libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), dot.as_ptr()) },
        || "pivot_root".into(),
    )?;
    check_i(unsafe { libc::umount2(dot.as_ptr(), libc::MNT_DETACH) }, || {
        "detaching old root".into()
    })?;
    let root = cstr("/")?;
    check_i(unsafe { libc::chdir(root.as_ptr()) }, || "chdir /".into())?;
    Ok(())
}

pub fn chroot(path: &Path) -> Result<()> {
    let p = cstr(path)?;
    check_i(unsafe { libc::chroot(p.as_ptr()) }, || {
        format!("chroot {}", path.display())
    })?;
    let root = cstr("/")?;
    check_i(unsafe { libc::chdir(root.as_ptr()) }, || "chdir /".into())?;
    Ok(())
}

pub fn mask_file(target: &Path) -> Result<()> {
    if !target.exists() {
        return Ok(());
    }
    if target.is_dir() {
        mount(
            "tmpfs",
            target,
            "tmpfs",
            STD_NOEXEC | MS_RO,
            Some("mode=755,size=4k"),
        )
    } else {
        bind(Path::new("/dev/null"), target, true, false)
    }
}

pub fn ensure_mountpoint(target: &Path, dir: bool) -> Result<()> {
    if dir {
        mkdir_p(target, 0o755)
    } else if target.exists() {
        Ok(())
    } else {
        if let Some(p) = target.parent() {
            mkdir_p(p, 0o755)?;
        }
        std::fs::File::create(target).map(drop).map_err(|e| Error::Io {
            context: format!("creating {}", target.display()),
            source: e,
        })
    }
}
