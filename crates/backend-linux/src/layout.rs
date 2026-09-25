use std::fs;
use std::path::{Path, PathBuf};

use sandbox_core::Sandbox;

pub const ROOT_LAYER: &str = "root";
pub const LAYER_CANDIDATES: &[&str] = &[
    "usr", "etc", "var", "opt", "bin", "sbin", "lib", "lib32", "lib64", "libx32",
];
pub const SKEL_DIRS: &[(&str, u32)] = &[
    ("usr", 0o755),
    ("etc", 0o755),
    ("var", 0o755),
    ("opt", 0o755),
    ("home", 0o755),
    ("root", 0o700),
    ("tmp", 0o1777),
    ("srv", 0o755),
    ("mnt", 0o755),
    ("media", 0o755),
    ("boot", 0o755),
    ("proc", 0o555),
    ("sys", 0o555),
    ("dev", 0o755),
    ("run", 0o755),
];

#[derive(Debug, Clone)]
pub struct Layer {
    pub name: String,
    pub host: PathBuf,
}

pub fn host_layers() -> Vec<Layer> {
    LAYER_CANDIDATES
        .iter()
        .map(|n| Layer {
            name: n.to_string(),
            host: PathBuf::from("/").join(n),
        })
        .filter(|l| fs::symlink_metadata(&l.host).map(|m| m.is_dir()).unwrap_or(false))
        .collect()
}

pub fn host_symlinks() -> Vec<(String, PathBuf)> {
    LAYER_CANDIDATES
        .iter()
        .filter_map(|n| {
            let p = PathBuf::from("/").join(n);
            fs::read_link(&p).ok().map(|t| (n.to_string(), t))
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct Layout {
    pub dir: PathBuf,
}

impl Layout {
    pub fn of(sb: &Sandbox) -> Self {
        Self { dir: sb.dir.clone() }
    }

    pub fn ovl(&self) -> PathBuf {
        self.dir.join("ovl")
    }

    pub fn upper(&self) -> PathBuf {
        self.ovl().join("upper")
    }

    pub fn work(&self) -> PathBuf {
        self.ovl().join("work")
    }

    pub fn layer_upper(&self, name: &str) -> PathBuf {
        self.upper().join(name)
    }

    pub fn run(&self) -> PathBuf {
        self.dir.join("run")
    }

    pub fn rootfs(&self) -> PathBuf {
        self.run().join("rootfs")
    }

    pub fn idmap(&self) -> PathBuf {
        self.run().join("idmap")
    }

    pub fn skel(&self) -> PathBuf {
        self.run().join("skel")
    }

    pub fn lock(&self) -> PathBuf {
        self.run().join("lock")
    }

    pub fn state(&self) -> PathBuf {
        self.run().join("state.json")
    }

    pub fn log(&self) -> PathBuf {
        self.run().join("supervisor.log")
    }

    pub fn snapshots(&self) -> PathBuf {
        self.dir.join("snapshots")
    }
}

pub fn rel(p: &Path) -> &Path {
    p.strip_prefix("/").unwrap_or(p)
}
