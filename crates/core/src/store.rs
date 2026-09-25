use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use sandbox_policy::{validate_name, SandboxConfig};

use crate::{Error, IoContext, Result, Sandbox};

#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

pub struct Lock {
    _file: File,
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn from_env() -> Result<Self> {
        if let Some(p) = std::env::var_os("SANDBOX_HOME").filter(|p| !p.is_empty()) {
            return Ok(Self::new(p));
        }
        if unsafe { libc::geteuid() } == 0 {
            return Ok(Self::new("/var/lib/sandbox"));
        }
        if let Some(p) = std::env::var_os("XDG_DATA_HOME").filter(|p| !p.is_empty()) {
            return Ok(Self::new(PathBuf::from(p).join("sandbox")));
        }
        match std::env::var_os("HOME").filter(|p| !p.is_empty()) {
            Some(h) => Ok(Self::new(PathBuf::from(h).join(".local/share/sandbox"))),
            None => Err(Error::Runtime(
                "cannot locate data directory: set SANDBOX_HOME or HOME".into(),
            )),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn sandboxes_dir(&self) -> PathBuf {
        self.root.join("sandboxes")
    }

    pub fn dir_of(&self, name: &str) -> Result<PathBuf> {
        validate_name(name)?;
        Ok(self.sandboxes_dir().join(name))
    }

    pub fn ensure(&self) -> Result<()> {
        for d in [&self.root, &self.sandboxes_dir()] {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(d)
                .with_ctx(|| format!("creating {}", d.display()))?;
        }
        Ok(())
    }

    pub fn exists(&self, name: &str) -> Result<bool> {
        Ok(self.dir_of(name)?.join("config.toml").is_file())
    }

    pub fn open(&self, name: &str) -> Result<Sandbox> {
        let dir = self.dir_of(name)?;
        let path = dir.join("config.toml");
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Error::NotFound(name.into())),
            Err(e) => return Err(e).with_ctx(|| format!("reading {}", path.display())),
        };
        let config = SandboxConfig::from_toml(&text)?;
        if config.name != name {
            return Err(Error::Runtime(format!(
                "{} declares name `{}`, expected `{name}`",
                path.display(),
                config.name
            )));
        }
        Ok(Sandbox {
            name: name.into(),
            dir,
            config,
        })
    }

    pub fn list(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let rd = match fs::read_dir(self.sandboxes_dir()) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e).ctx("listing sandboxes"),
        };
        for e in rd {
            let e = e.ctx("listing sandboxes")?;
            if let Some(n) = e.file_name().to_str() {
                if validate_name(n).is_ok() && e.path().join("config.toml").is_file() {
                    out.push(n.to_string());
                }
            }
        }
        out.sort();
        Ok(out)
    }

    pub fn lock(&self, name: &str) -> Result<Lock> {
        self.ensure()?;
        let path = self.sandboxes_dir().join(format!(".{name}.lock"));
        validate_name(name)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&path)
            .with_ctx(|| format!("opening {}", path.display()))?;
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(Lock { _file: file });
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err).with_ctx(|| format!("locking {}", path.display()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_list() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path());
        assert!(store.list().unwrap().is_empty());
        store.ensure().unwrap();
        let dir = store.dir_of("alpha").unwrap();
        fs::create_dir(&dir).unwrap();
        fs::write(
            dir.join("config.toml"),
            SandboxConfig::new("alpha").to_toml().unwrap(),
        )
        .unwrap();
        fs::create_dir(store.dir_of("junk").unwrap()).unwrap();
        assert_eq!(store.list().unwrap(), vec!["alpha"]);
        assert_eq!(store.open("alpha").unwrap().config.name, "alpha");
        assert!(matches!(store.open("beta"), Err(Error::NotFound(_))));
        assert!(store.dir_of("../etc").is_err());
    }

    #[test]
    fn rejects_mismatched_name() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path());
        store.ensure().unwrap();
        let dir = store.dir_of("a").unwrap();
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("config.toml"), "name = \"b\"").unwrap();
        assert!(store.open("a").is_err());
    }
}
