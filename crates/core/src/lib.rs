use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub use sandbox_policy as policy;
use sandbox_policy::{validate_name, PolicyError, SandboxConfig};

mod store;

pub use store::{Lock, Store};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("sandbox `{0}` does not exist")]
    NotFound(String),
    #[error("sandbox `{0}` already exists")]
    AlreadyExists(String),
    #[error("sandbox `{0}` is running; stop it first")]
    Running(String),
    #[error("snapshot `{1}` of sandbox `{0}` does not exist")]
    SnapshotNotFound(String, String),
    #[error("snapshot `{1}` of sandbox `{0}` already exists")]
    SnapshotExists(String, String),
    #[error("{0} is not supported on this platform")]
    Unsupported(String),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("{0}")]
    Runtime(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait IoContext<T> {
    fn ctx<C: Into<String>>(self, context: C) -> Result<T>;
    fn with_ctx<C: Into<String>, F: FnOnce() -> C>(self, f: F) -> Result<T>;
}

impl<T> IoContext<T> for io::Result<T> {
    fn ctx<C: Into<String>>(self, context: C) -> Result<T> {
        self.map_err(|source| Error::Io {
            context: context.into(),
            source,
        })
    }

    fn with_ctx<C: Into<String>, F: FnOnce() -> C>(self, f: F) -> Result<T> {
        self.map_err(|source| Error::Io {
            context: f().into(),
            source,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Sandbox {
    pub name: String,
    pub dir: PathBuf,
    pub config: SandboxConfig,
}

impl Sandbox {
    pub fn config_path(&self) -> PathBuf {
        self.dir.join("config.toml")
    }

    pub fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    pub fn snapshots_dir(&self) -> PathBuf {
        self.dir.join("snapshots")
    }

    pub fn snapshot_dir(&self, snapshot: &str) -> Result<PathBuf> {
        validate_name(snapshot)?;
        Ok(self.snapshots_dir().join(snapshot))
    }

    pub fn snapshots(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        match fs::read_dir(self.snapshots_dir()) {
            Ok(rd) => {
                for e in rd {
                    let e = e.ctx("reading snapshots")?;
                    if let Some(n) = e.file_name().to_str() {
                        if validate_name(n).is_ok() {
                            out.push(n.to_string());
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).ctx("reading snapshots"),
        }
        out.sort();
        Ok(out)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Command {
    pub argv: Vec<OsString>,
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    pub user: Option<String>,
}

impl Command {
    pub fn new<I, S>(argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Running,
    Stopped,
}

impl std::fmt::Display for RunState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
        })
    }
}

#[derive(Debug, Clone)]
pub struct Status {
    pub state: RunState,
    pub init_pid: Option<i32>,
    pub details: Vec<(String, String)>,
}

pub trait SandboxBackend {
    fn name(&self) -> &'static str;
    fn create(&self, store: &Store, config: &SandboxConfig) -> Result<Sandbox>;
    fn start(&self, sandbox: &Sandbox) -> Result<()>;
    fn stop(&self, sandbox: &Sandbox) -> Result<()>;
    fn status(&self, sandbox: &Sandbox) -> Result<Status>;
    fn run(&self, sandbox: &Sandbox, command: &Command) -> Result<i32>;
    fn destroy(&self, sandbox: &Sandbox) -> Result<()>;
    fn put_file(&self, sandbox: &Sandbox, source: &Path, destination: &Path) -> Result<()>;
    fn get_file(&self, sandbox: &Sandbox, source: &Path, destination: &Path) -> Result<()>;
    fn snapshot(&self, sandbox: &Sandbox, snapshot: &str) -> Result<()>;
    fn restore(&self, sandbox: &Sandbox, snapshot: &str) -> Result<()>;
    fn delete_snapshot(&self, sandbox: &Sandbox, snapshot: &str) -> Result<()>;
    fn reset(&self, sandbox: &Sandbox) -> Result<()>;
}
