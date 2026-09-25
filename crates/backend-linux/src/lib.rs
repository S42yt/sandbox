use std::fs;
use std::path::Path;

use sandbox_core::{Command, Error, Result, Sandbox, SandboxBackend, Status, Store};
use sandbox_policy::SandboxConfig;

mod caps;
mod cgroup;
mod copy;
mod enter;
mod layout;
mod mount;
mod net;
mod ns;
mod pty;
mod rootfs;
mod seccomp;
mod seed;
mod supervisor;
mod sys;

use layout::Layout;

pub struct LinuxBackend {
    store_root: std::path::PathBuf,
}

impl LinuxBackend {
    pub fn new(store: &Store) -> Self {
        Self {
            store_root: store.root().to_path_buf(),
        }
    }

    fn require_root() -> Result<()> {
        if sys::is_root() {
            Ok(())
        } else {
            Err(Error::Runtime(
                "the Linux backend needs root privileges; run it with sudo".into(),
            ))
        }
    }

    fn require_stopped(sb: &Sandbox) -> Result<Layout> {
        let layout = Layout::of(sb);
        if supervisor::is_running(&layout)? {
            return Err(Error::Running(sb.name.clone()));
        }
        Ok(layout)
    }

    fn run_as(&self, sb: &Sandbox, cmd: &Command, user: &str) -> Result<i32> {
        Self::require_root()?;
        let layout = Layout::of(sb);
        let state = match supervisor::running_state(&layout)? {
            Some(s) => s,
            None => {
                eprintln!("sandbox: starting {}", sb.name);
                supervisor::start(sb, &self.store_root)?;
                supervisor::running_state(&layout)?
                    .ok_or_else(|| Error::Runtime("sandbox did not start".into()))?
            }
        };
        enter::run(sb, &state, cmd, user)
    }
}

impl SandboxBackend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn create(&self, store: &Store, config: &SandboxConfig) -> Result<Sandbox> {
        Self::require_root()?;
        config.validate()?;
        store.ensure()?;
        let _lock = store.lock(&config.name)?;
        if store.exists(&config.name)? {
            return Err(Error::AlreadyExists(config.name.clone()));
        }
        let dir = store.dir_of(&config.name)?;
        sys::mkdir_p(&dir, 0o700)?;
        let sb = Sandbox {
            name: config.name.clone(),
            dir,
            config: config.clone(),
        };
        let layout = Layout::of(&sb);
        let r = (|| {
            seed::seed(&sb, &layout)?;
            sys::write_file(sb.config_path(), config.to_toml()?)
        })();
        if let Err(e) = r {
            let _ = fs::remove_dir_all(&sb.dir);
            return Err(e);
        }
        Ok(sb)
    }

    fn start(&self, sb: &Sandbox) -> Result<()> {
        Self::require_root()?;
        supervisor::start(sb, &self.store_root)
    }

    fn stop(&self, sb: &Sandbox) -> Result<()> {
        Self::require_root()?;
        supervisor::stop(sb)
    }

    fn status(&self, sb: &Sandbox) -> Result<Status> {
        supervisor::status(sb)
    }

    fn run(&self, sb: &Sandbox, cmd: &Command) -> Result<i32> {
        self.run_as(sb, cmd, cmd.user.as_deref().unwrap_or("root"))
    }

    fn destroy(&self, sb: &Sandbox) -> Result<()> {
        Self::require_root()?;
        supervisor::stop(sb)?;
        let layout = Self::require_stopped(sb)?;
        cgroup::Cgroup::open(&sb.name).remove();
        let _ = fs::remove_file(layout.lock());
        copy::remove_tree(&sb.dir)
    }

    fn put_file(&self, sb: &Sandbox, source: &Path, destination: &Path) -> Result<()> {
        Self::require_root()?;
        let layout = Layout::of(sb);
        let state = supervisor::running_state(&layout)?;
        enter::put(sb, &layout, state.as_ref(), source, destination)
    }

    fn get_file(&self, sb: &Sandbox, source: &Path, destination: &Path) -> Result<()> {
        Self::require_root()?;
        let layout = Layout::of(sb);
        let state = supervisor::running_state(&layout)?;
        enter::get(sb, &layout, state.as_ref(), source, destination)
    }

    fn snapshot(&self, sb: &Sandbox, snapshot: &str) -> Result<()> {
        Self::require_root()?;
        let layout = Self::require_stopped(sb)?;
        let dir = sb.snapshot_dir(snapshot)?;
        if dir.exists() {
            return Err(Error::SnapshotExists(sb.name.clone(), snapshot.into()));
        }
        sys::mkdir_p(layout.snapshots(), 0o700)?;
        let tmp = layout.snapshots().join(format!(".{snapshot}.tmp"));
        copy::remove_tree(&tmp)?;
        sys::mkdir_p(&tmp, 0o700)?;
        let r = copy::copy_tree(&layout.upper(), &tmp.join("upper"));
        if let Err(e) = r {
            let _ = copy::remove_tree(&tmp);
            return Err(e);
        }
        fs::rename(&tmp, &dir).map_err(|e| Error::Io {
            context: "finalizing snapshot".into(),
            source: e,
        })
    }

    fn restore(&self, sb: &Sandbox, snapshot: &str) -> Result<()> {
        Self::require_root()?;
        let layout = Self::require_stopped(sb)?;
        let src = sb.snapshot_dir(snapshot)?.join("upper");
        if !src.is_dir() {
            return Err(Error::SnapshotNotFound(sb.name.clone(), snapshot.into()));
        }
        copy::remove_tree(&layout.upper())?;
        copy::remove_tree(&layout.work())?;
        copy::copy_tree(&src, &layout.upper())?;
        seed::seed(sb, &layout)
    }

    fn delete_snapshot(&self, sb: &Sandbox, snapshot: &str) -> Result<()> {
        Self::require_root()?;
        let dir = sb.snapshot_dir(snapshot)?;
        if !dir.is_dir() {
            return Err(Error::SnapshotNotFound(sb.name.clone(), snapshot.into()));
        }
        copy::remove_tree(&dir)
    }

    fn logs(&self, sb: &Sandbox) -> Result<String> {
        let path = Layout::of(sb).log();
        match fs::read_to_string(&path) {
            Ok(s) => Ok(s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(Error::Io {
                context: format!("reading {}", path.display()),
                source: e,
            }),
        }
    }

    fn reset(&self, sb: &Sandbox) -> Result<()> {
        Self::require_root()?;
        let layout = Self::require_stopped(sb)?;
        copy::remove_tree(&layout.upper())?;
        copy::remove_tree(&layout.work())?;
        seed::seed(sb, &layout)
    }
}
