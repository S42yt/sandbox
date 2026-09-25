use std::path::Path;
use std::process::Command;

use sandbox_core::{Error, IoContext, Result};

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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io {
            context: format!("removing {}", path.display()),
            source: e,
        }),
    }
}
