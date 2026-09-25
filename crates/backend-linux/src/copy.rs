use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::process::Command;

use sandbox_core::{Error, IoContext, Result};

use crate::sys::{check_i, cstr, errno};

pub fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let out = Command::new("cp")
        .args(["-a", "--reflink=auto", "-T", "--"])
        .arg(src)
        .arg(dst)
        .output()
        .ctx("running cp")?;
    if out.status.success() {
        Ok(())
    } else {
        Err(Error::Runtime(format!(
            "copying {} to {} failed: {}",
            src.display(),
            dst.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

pub fn remove_tree(path: &Path) -> Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io {
            context: format!("removing {}", path.display()),
            source: e,
        }),
    }
}

pub fn open_dir(path: &Path) -> Result<OwnedFd> {
    let c = cstr(path)?;
    let fd = check_i(
        unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) },
        || format!("opening directory {}", path.display()),
    )?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_dir_at(dir: RawFd, name: &CStr, follow: bool) -> Result<OwnedFd> {
    let nofollow = if follow { 0 } else { libc::O_NOFOLLOW };
    let fd = check_i(
        unsafe {
            libc::openat(
                dir,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | nofollow | libc::O_CLOEXEC,
            )
        },
        || format!("opening directory {}", name.to_string_lossy()),
    )?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn mkdir_at(dir: RawFd, name: &CStr, mode: u32) -> Result<()> {
    let r = unsafe { libc::mkdirat(dir, name.as_ptr(), mode) };
    if r < 0 && errno().raw_os_error() != Some(libc::EEXIST) {
        return Err(Error::Io {
            context: format!("creating directory {}", name.to_string_lossy()),
            source: errno(),
        });
    }
    Ok(())
}

fn create_at(dir: RawFd, name: &CStr, mode: u32) -> Result<File> {
    let fd = check_i(
        unsafe {
            libc::openat(
                dir,
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        },
        || format!("creating {}", name.to_string_lossy()),
    )?;
    unsafe { libc::fchmod(fd, mode) };
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_at(dir: RawFd, name: &CStr, follow: bool) -> Result<File> {
    let nofollow = if follow { 0 } else { libc::O_NOFOLLOW };
    let fd = check_i(
        unsafe { libc::openat(dir, name.as_ptr(), libc::O_RDONLY | nofollow | libc::O_CLOEXEC) },
        || format!("opening {}", name.to_string_lossy()),
    )?;
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn stat_at(dir: RawFd, name: &CStr, follow: bool) -> Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
    check_i(
        unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, flags) },
        || format!("stat {}", name.to_string_lossy()),
    )?;
    Ok(st)
}

struct DirStream(*mut libc::DIR);

impl Drop for DirStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

fn entries(dir: RawFd) -> Result<Vec<CString>> {
    let dup = check_i(unsafe { libc::dup(dir) }, || "dup".into())?;
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        unsafe { libc::close(dup) };
        return Err(Error::Io {
            context: "reading directory".into(),
            source: errno(),
        });
    }
    let stream = DirStream(stream);
    let mut out = Vec::new();
    loop {
        let ent = unsafe { libc::readdir(stream.0) };
        if ent.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            out.push(name.to_owned());
        }
    }
    out.sort();
    Ok(out)
}

const FILE: u8 = b'F';
const LINK: u8 = b'L';
const DIR: u8 = b'D';
const UP: u8 = b'U';

fn header(out: &mut impl Write, kind: u8, mode: u32, name: &[u8], len: u64) -> io::Result<()> {
    out.write_all(&[kind])?;
    out.write_all(&mode.to_le_bytes())?;
    out.write_all(&(name.len() as u32).to_le_bytes())?;
    out.write_all(name)?;
    out.write_all(&len.to_le_bytes())
}

pub fn pack(dir: RawFd, name: &CStr, out: &mut impl Write) -> Result<()> {
    pack_entry(dir, name, out, true)
}

fn pack_entry(dir: RawFd, name: &CStr, out: &mut impl Write, follow: bool) -> Result<()> {
    let st = stat_at(dir, name, follow)?;
    let mode = st.st_mode & 0o7777;
    let what = || format!("packing {}", name.to_string_lossy());
    match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => {
            let mut f = open_at(dir, name, follow)?;
            let len = f.metadata().with_ctx(what)?.len();
            header(out, FILE, mode, name.to_bytes(), len).with_ctx(what)?;
            let copied = io::copy(&mut (&mut f).take(len), out).with_ctx(what)?;
            if copied < len {
                out.write_all(&vec![0u8; (len - copied) as usize])
                    .with_ctx(what)?;
            }
        }
        libc::S_IFLNK => {
            let mut buf = vec![0u8; 4096];
            let n = unsafe { libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
            check_i(n as libc::c_int, what)?;
            buf.truncate(n as usize);
            header(out, LINK, mode, name.to_bytes(), buf.len() as u64).with_ctx(what)?;
            out.write_all(&buf).with_ctx(what)?;
        }
        libc::S_IFDIR => {
            header(out, DIR, mode, name.to_bytes(), 0).with_ctx(what)?;
            let sub = open_dir_at(dir, name, follow)?;
            for e in entries(sub.as_raw_fd())? {
                pack_entry(sub.as_raw_fd(), &e, out, false)?;
            }
            header(out, UP, 0, b"", 0).with_ctx(what)?;
        }
        _ => {}
    }
    Ok(())
}

fn read_header(input: &mut impl Read) -> Result<Option<(u8, u32, CString, u64)>> {
    let mut kind = [0u8; 1];
    match input.read_exact(&mut kind) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).ctx("reading transfer stream"),
    }
    let mut w = [0u8; 4];
    input.read_exact(&mut w).ctx("reading transfer stream")?;
    let mode = u32::from_le_bytes(w);
    input.read_exact(&mut w).ctx("reading transfer stream")?;
    let mut name = vec![0u8; u32::from_le_bytes(w) as usize];
    input.read_exact(&mut name).ctx("reading transfer stream")?;
    let mut l = [0u8; 8];
    input.read_exact(&mut l).ctx("reading transfer stream")?;
    let name = CString::new(name).map_err(|_| Error::Runtime("invalid name in transfer stream".into()))?;
    if name.to_bytes().contains(&b'/') || name.to_bytes() == b".." || name.to_bytes() == b"." {
        return Err(Error::Runtime("invalid name in transfer stream".into()));
    }
    Ok(Some((kind[0], mode, name, u64::from_le_bytes(l))))
}

pub fn unpack(parent: RawFd, rename_root: &CStr, input: &mut impl Read) -> Result<()> {
    let mut stack: Vec<OwnedFd> = Vec::new();
    let mut modes: Vec<u32> = Vec::new();
    let mut first = true;
    while let Some((kind, mode, name, len)) = read_header(input)? {
        let name = if first { rename_root.to_owned() } else { name };
        first = false;
        let dir = stack.last().map_or(parent, |d| d.as_raw_fd());
        match kind {
            FILE => {
                let mut f = create_at(dir, &name, mode)?;
                io::copy(&mut input.take(len), &mut f)
                    .with_ctx(|| format!("writing {}", name.to_string_lossy()))?;
            }
            LINK => {
                let mut target = vec![0u8; len as usize];
                input.read_exact(&mut target).ctx("reading transfer stream")?;
                let target = CString::new(target).map_err(|_| Error::Runtime("bad symlink target".into()))?;
                unsafe { libc::unlinkat(dir, name.as_ptr(), 0) };
                check_i(
                    unsafe { libc::symlinkat(target.as_ptr(), dir, name.as_ptr()) },
                    || format!("creating symlink {}", name.to_string_lossy()),
                )?;
            }
            DIR => {
                mkdir_at(dir, &name, mode | 0o700)?;
                stack.push(open_dir_at(dir, &name, false)?);
                modes.push(mode);
            }
            UP => {
                if let (Some(d), Some(m)) = (stack.pop(), modes.pop()) {
                    unsafe { libc::fchmod(d.as_raw_fd(), m) };
                }
            }
            _ => return Err(Error::Runtime("corrupt transfer stream".into())),
        }
    }
    Ok(())
}
