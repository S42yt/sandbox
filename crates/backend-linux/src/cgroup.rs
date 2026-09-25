use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sandbox_core::{Error, Result};
use sandbox_policy::ResourceConfig;

use crate::sys;

const ROOT: &str = "/sys/fs/cgroup";
const V1_CONTROLLERS: &[&str] = &["memory", "pids", "cpu"];

#[derive(Debug, Clone)]
pub enum Cgroup {
    V2 { path: PathBuf },
    V1 { paths: Vec<PathBuf> },
    None,
}

pub fn is_v2() -> bool {
    Path::new(ROOT).join("cgroup.controllers").exists()
}

pub fn v2_path(name: &str) -> PathBuf {
    Path::new(ROOT).join("sandbox").join(name)
}

impl Cgroup {
    pub fn create(name: &str, res: &ResourceConfig) -> Result<Self> {
        if is_v2() {
            let parent = Path::new(ROOT).join("sandbox");
            let path = parent.join(name);
            sys::mkdir_p(&path, 0o755)?;
            let available =
                fs::read_to_string(Path::new(ROOT).join("cgroup.controllers")).unwrap_or_default();
            for dir in [Path::new(ROOT), parent.as_path()] {
                for c in available
                    .split_whitespace()
                    .filter(|c| V1_CONTROLLERS.contains(c))
                {
                    let _ = fs::write(dir.join("cgroup.subtree_control"), format!("+{c}"));
                }
            }
            let cg = Self::V2 { path };
            cg.apply(res)?;
            return Ok(cg);
        }
        let mut paths = Vec::new();
        for c in V1_CONTROLLERS {
            let base = Path::new(ROOT).join(c);
            if base.join("tasks").exists() {
                let p = base.join("sandbox").join(name);
                sys::mkdir_p(&p, 0o755)?;
                paths.push(p);
            }
        }
        if paths.is_empty() {
            return Ok(Self::None);
        }
        let cg = Self::V1 { paths };
        cg.apply(res)?;
        Ok(cg)
    }

    fn apply(&self, res: &ResourceConfig) -> Result<()> {
        match self {
            Self::V2 { path } => {
                if let Some(m) = res.memory {
                    write_limit(&path.join("memory.max"), &m.0.to_string())?;
                    let _ = fs::write(path.join("memory.swap.max"), "0");
                }
                if let Some(c) = res.cpus {
                    write_limit(
                        &path.join("cpu.max"),
                        &format!("{} 100000", (c * 100000.0).round() as u64),
                    )?;
                }
                write_limit(&path.join("pids.max"), &res.processes.to_string())?;
            }
            Self::V1 { paths } => {
                for p in paths {
                    let ctrl = p
                        .strip_prefix(ROOT)
                        .ok()
                        .and_then(|r| r.iter().next())
                        .and_then(|s| s.to_str())
                        .unwrap_or("");
                    match ctrl {
                        "memory" => {
                            if let Some(m) = res.memory {
                                write_limit(&p.join("memory.limit_in_bytes"), &m.0.to_string())?;
                            }
                        }
                        "cpu" => {
                            if let Some(c) = res.cpus {
                                write_limit(&p.join("cpu.cfs_period_us"), "100000")?;
                                write_limit(
                                    &p.join("cpu.cfs_quota_us"),
                                    &((c * 100000.0).round() as u64).to_string(),
                                )?;
                            }
                        }
                        "pids" => write_limit(&p.join("pids.max"), &res.processes.to_string())?,
                        _ => {}
                    }
                }
            }
            Self::None => {}
        }
        Ok(())
    }

    pub fn add_pid(&self, pid: libc::pid_t) -> Result<()> {
        let s = pid.to_string();
        match self {
            Self::V2 { path } => sys::write_file(path.join("cgroup.procs"), &s),
            Self::V1 { paths } => paths
                .iter()
                .try_for_each(|p| sys::write_file(p.join("cgroup.procs"), &s)),
            Self::None => Ok(()),
        }
    }

    pub fn open(name: &str) -> Self {
        if is_v2() {
            let path = v2_path(name);
            return if path.is_dir() {
                Self::V2 { path }
            } else {
                Self::None
            };
        }
        let paths: Vec<PathBuf> = V1_CONTROLLERS
            .iter()
            .map(|c| Path::new(ROOT).join(c).join("sandbox").join(name))
            .filter(|p| p.is_dir())
            .collect();
        if paths.is_empty() {
            Self::None
        } else {
            Self::V1 { paths }
        }
    }

    pub fn procs(&self) -> Vec<libc::pid_t> {
        let file = match self {
            Self::V2 { path } => path.join("cgroup.procs"),
            Self::V1 { paths } => paths[0].join("cgroup.procs"),
            Self::None => return Vec::new(),
        };
        fs::read_to_string(file)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    }

    pub fn kill_all(&self) {
        if let Self::V2 { path } = self {
            if fs::write(path.join("cgroup.kill"), "1").is_ok() {
                let start = Instant::now();
                while !self.procs().is_empty() && start.elapsed() < Duration::from_secs(5) {
                    std::thread::sleep(Duration::from_millis(20));
                }
                return;
            }
        }
        for _ in 0..50 {
            let procs = self.procs();
            if procs.is_empty() {
                return;
            }
            for p in procs {
                sys::kill(p, libc::SIGKILL);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn remove(&self) {
        match self {
            Self::V2 { path } => {
                let _ = fs::remove_dir(path);
            }
            Self::V1 { paths } => {
                for p in paths {
                    let _ = fs::remove_dir(p);
                }
            }
            Self::None => {}
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::V2 { path } => format!("v2 {}", path.display()),
            Self::V1 { paths } => format!("v1 ({} controllers)", paths.len()),
            Self::None => "unavailable".into(),
        }
    }
}

fn write_limit(path: &Path, value: &str) -> Result<()> {
    fs::write(path, value).map_err(|e| Error::Io {
        context: format!("setting {} to {value}", path.display()),
        source: e,
    })
}

pub fn memory_usage(cg: &Cgroup) -> Option<u64> {
    let f = match cg {
        Cgroup::V2 { path } => path.join("memory.current"),
        Cgroup::V1 { paths } => paths
            .iter()
            .find(|p| p.to_string_lossy().contains("/memory/"))?
            .join("memory.usage_in_bytes"),
        Cgroup::None => return None,
    };
    fs::read_to_string(f).ok()?.trim().parse().ok()
}

pub fn read_pids_current(cg: &Cgroup) -> Option<u64> {
    let f = match cg {
        Cgroup::V2 { path } => path.join("pids.current"),
        Cgroup::V1 { paths } => paths
            .iter()
            .find(|p| p.to_string_lossy().contains("/pids/"))?
            .join("pids.current"),
        Cgroup::None => return None,
    };
    fs::read_to_string(f).ok()?.trim().parse().ok()
}
