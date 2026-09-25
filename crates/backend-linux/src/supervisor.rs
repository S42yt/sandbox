use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

use sandbox_core::{Error, IoContext, Result, RunState, Sandbox, Status};
use serde::{Deserialize, Serialize};

use crate::cgroup::{self, Cgroup};
use crate::layout::Layout;
use crate::mount::{self, STD_NOEXEC};
use crate::net::Network;
use crate::ns::{self, IdMap};
use crate::rootfs::{self, Build};
use crate::sys::{self, Fork};
use crate::{caps, seccomp, seed};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub supervisor_pid: i32,
    pub init_pid: i32,
    pub uid_base: u32,
    pub idmapped: bool,
    pub network: String,
    pub started_at: u64,
}

pub fn try_lock(layout: &Layout) -> Result<Option<File>> {
    sys::mkdir_p(layout.run(), 0o700)?;
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(layout.lock())
        .with_ctx(|| "opening lock".to_string())?;
    let r = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if r == 0 {
        Ok(Some(f))
    } else if sys::errno().raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(None)
    } else {
        Err(sys::errno()).ctx("locking")
    }
}

pub fn is_running(layout: &Layout) -> Result<bool> {
    Ok(try_lock(layout)?.is_none())
}

pub fn read_state(layout: &Layout) -> Result<Option<State>> {
    match fs::read_to_string(layout.state()) {
        Ok(s) => Ok(serde_json::from_str(&s).ok()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).ctx("reading state"),
    }
}

pub fn running_state(layout: &Layout) -> Result<Option<State>> {
    if !is_running(layout)? {
        return Ok(None);
    }
    for _ in 0..100 {
        if let Some(s) = read_state(layout)? {
            if sys::alive(s.init_pid) {
                return Ok(Some(s));
            }
        }
        if !is_running(layout)? {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(None)
}

pub fn status(sb: &Sandbox) -> Result<Status> {
    let layout = Layout::of(sb);
    let mut details = Vec::new();
    details.push(("network".into(), sb.config.network.describe()));
    match running_state(&layout)? {
        Some(s) => {
            details.push(("supervisor".into(), s.supervisor_pid.to_string()));
            details.push((
                "uid mapping".into(),
                if s.idmapped {
                    format!("0-65535 -> {}-{}", s.uid_base, s.uid_base + 65535)
                } else {
                    "identity".into()
                },
            ));
            let cg = Cgroup::open(&sb.name);
            details.push(("cgroup".into(), cg.describe()));
            if let Some(n) = cgroup::read_pids_current(&cg) {
                details.push(("processes".into(), n.to_string()));
            }
            if let Some(m) = cgroup::memory_usage(&cg) {
                details.push(("memory".into(), format!("{} MiB", m >> 20)));
            }
            Ok(Status {
                state: RunState::Running,
                init_pid: Some(s.init_pid),
                details,
            })
        }
        None => Ok(Status {
            state: RunState::Stopped,
            init_pid: None,
            details,
        }),
    }
}

pub fn start(sb: &Sandbox, store_root: &Path) -> Result<()> {
    let layout = Layout::of(sb);
    if is_running(&layout)? {
        return Ok(());
    }
    sys::mkdir_p(layout.run(), 0o700)?;
    let ready = sys::pipe()?;
    match sys::fork()? {
        Fork::Child => {
            drop(ready.read);
            if sys::setsid().is_err() {
                sys::exit(1);
            }
            match sys::fork() {
                Ok(Fork::Child) => {
                    let code = match supervise(sb, &layout, store_root, &ready.write) {
                        Ok(()) => 0,
                        Err(e) => {
                            let _ = sys::write_all(&ready.write, format!("error: {e}\n").as_bytes());
                            eprintln!("supervisor failed: {e}");
                            1
                        }
                    };
                    sys::exit(code)
                }
                Ok(Fork::Parent(_)) => sys::exit(0),
                Err(_) => sys::exit(1),
            }
        }
        Fork::Parent(pid) => {
            drop(ready.write);
            let _ = sys::waitpid(pid);
            let msg = sys::read_line(&ready.read)?;
            if msg.trim() == "ok" {
                Ok(())
            } else if let Some(e) = msg.strip_prefix("error: ") {
                Err(Error::Runtime(e.trim().to_string()))
            } else {
                Err(Error::Runtime(format!(
                    "supervisor exited without reporting; see {}",
                    layout.log().display()
                )))
            }
        }
    }
}

pub fn stop(sb: &Sandbox) -> Result<()> {
    let layout = Layout::of(sb);
    let Some(state) = running_state(&layout)? else {
        return Ok(());
    };
    sys::kill(state.supervisor_pid, libc::SIGTERM);
    let start = Instant::now();
    while is_running(&layout)? {
        if start.elapsed() > Duration::from_secs(20) {
            sys::kill(state.init_pid, libc::SIGKILL);
            sys::kill(state.supervisor_pid, libc::SIGKILL);
            Cgroup::open(&sb.name).kill_all();
            if start.elapsed() > Duration::from_secs(25) {
                return Err(Error::Runtime("sandbox did not stop".into()));
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn log(msg: &str) {
    eprintln!("[{}] {msg}", sys::now_unix());
}

fn supervise(sb: &Sandbox, layout: &Layout, store_root: &Path, ready: &OwnedFd) -> Result<()> {
    let _ = sys::redirect_stdio(Path::new("/dev/null"), &layout.log());
    let _lock = try_lock(layout)?.ok_or_else(|| Error::Running(sb.name.clone()))?;
    sys::umask(0);
    let _ = fs::remove_file(layout.state());
    log(&format!("starting sandbox {}", sb.name));
    let sigs = sys::block_signals(&[libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGCHLD])?;
    sys::set_subreaper()?;
    sys::unshare(libc::CLONE_NEWNS)?;
    mount::make_private_root()?;

    let policy = sb.config.network.policy()?;
    let cfg_base = sb.config.security.uid_base;
    let (map, userns, idmapped) = if cfg_base == 0 {
        (IdMap::identity(), None, false)
    } else if mount::idmap_supported() {
        let map = IdMap {
            base: cfg_base,
            count: ns::UID_COUNT,
        };
        (map, Some(ns::template_userns(map)?), true)
    } else {
        log("kernel lacks idmapped mounts (needs 5.19+); falling back to identity uid mapping");
        (IdMap::identity(), None, false)
    };
    let template = match &userns {
        Some(_) => userns,
        None => Some(ns::template_userns(map)?),
    };
    let template_fd = template.as_ref().map(|f| f.as_raw_fd());

    let cg = Cgroup::create(&sb.name, &sb.config.resources)?;
    let result = run_sandbox(
        sb,
        layout,
        store_root,
        ready,
        &sigs,
        map,
        template_fd.filter(|_| idmapped),
        &cg,
        &policy,
    );
    cg.kill_all();
    cg.remove();
    let _ = fs::remove_file(layout.state());
    log("sandbox stopped");
    result
}

#[allow(clippy::too_many_arguments)]
fn run_sandbox(
    sb: &Sandbox,
    layout: &Layout,
    store_root: &Path,
    ready: &OwnedFd,
    sigs: &libc::sigset_t,
    map: IdMap,
    userns: Option<libc::c_int>,
    cg: &Cgroup,
    policy: &sandbox_policy::NetworkPolicy,
) -> Result<()> {
    seed::seed(sb, layout)?;
    seed::apply_masks(layout, store_root)?;
    seed::write_resolv_conf(layout, policy)?;
    rootfs::build(&Build {
        sandbox: sb,
        layout,
        map,
        userns,
        full: true,
    })?;

    let init_ready = sys::pipe()?;
    let init_pid = launch(sb, layout, map, cg, policy, &init_ready.write)?;
    drop(init_ready.write);
    log(&format!("init pid {init_pid}"));

    let start = Instant::now();
    loop {
        if sys::poll_readable(&init_ready.read, 100) {
            match sys::read_byte(&init_ready.read)? {
                Some(b'1') => break,
                _ => {
                    let _ = sys::try_wait(init_pid);
                    return Err(Error::Runtime(format!(
                        "sandbox init failed; see {}",
                        layout.log().display()
                    )));
                }
            }
        }
        if let Some(code) = sys::try_wait(init_pid)? {
            return Err(Error::Runtime(format!(
                "sandbox init exited with status {code}; see {}",
                layout.log().display()
            )));
        }
        if start.elapsed() > Duration::from_secs(30) {
            sys::kill(init_pid, libc::SIGKILL);
            return Err(Error::Runtime("sandbox init timed out".into()));
        }
    }

    let mut network = match Network::start(policy, init_pid, &layout.log()) {
        Ok(n) => n,
        Err(e) => {
            sys::kill(init_pid, libc::SIGKILL);
            let _ = sys::waitpid(init_pid);
            return Err(e);
        }
    };

    let state = State {
        supervisor_pid: sys::getpid(),
        init_pid,
        uid_base: map.base,
        idmapped: userns.is_some(),
        network: sb.config.network.describe(),
        started_at: sys::now_unix(),
    };
    let json = serde_json::to_string_pretty(&state).map_err(|e| Error::Runtime(e.to_string()))?;
    sys::write_file(layout.state(), json)?;
    sys::write_all(ready, b"ok\n")?;
    log("ready");

    let mut stopping: Option<Instant> = None;
    loop {
        match sys::wait_signal(sigs, Some(Duration::from_millis(500))) {
            Some(libc::SIGCHLD) => {
                if let Some(pid) = network.pid() {
                    if let Ok(Some(code)) = sys::try_wait(pid) {
                        log(&format!("slirp4netns exited with status {code}"));
                    }
                }
                sys::reap_any();
            }
            Some(_) if stopping.is_none() => {
                log("stop requested");
                stopping = Some(Instant::now());
                sys::kill(init_pid, libc::SIGTERM);
            }
            _ => {}
        }
        if !sys::alive(init_pid) {
            break;
        }
        if let Some(t) = stopping {
            if t.elapsed() > Duration::from_secs(10) {
                log("init did not exit; killing");
                sys::kill(init_pid, libc::SIGKILL);
                cg.kill_all();
            }
        }
    }
    sys::reap_any();
    network.stop();
    Ok(())
}

fn launch(
    sb: &Sandbox,
    layout: &Layout,
    map: IdMap,
    cg: &Cgroup,
    policy: &sandbox_policy::NetworkPolicy,
    init_ready: &OwnedFd,
) -> Result<libc::pid_t> {
    let to_sup = sys::pipe()?;
    let to_init = sys::pipe()?;
    let mut flags = libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWCGROUP;
    if policy.isolated {
        flags |= libc::CLONE_NEWNET;
    }
    match sys::fork()? {
        Fork::Child => {
            drop(to_sup.read);
            drop(to_init.write);
            let r = (|| -> Result<()> {
                cg.add_pid(sys::getpid())?;
                sys::unshare(flags)?;
                mount::make_private_root()?;
                match sys::fork()? {
                    Fork::Child => init_main(sb, layout, policy, &to_sup.write, &to_init.read, init_ready),
                    Fork::Parent(pid) => sys::write_all(&to_sup.write, &pid.to_ne_bytes()),
                }
            })();
            if let Err(e) = r {
                eprintln!("launcher failed: {e}");
                sys::exit(1);
            }
            sys::exit(0)
        }
        Fork::Parent(launcher) => {
            drop(to_sup.write);
            drop(to_init.read);
            let mut pid_bytes = [0u8; 4];
            for b in pid_bytes.iter_mut() {
                *b = sys::read_byte(&to_sup.read)?
                    .ok_or_else(|| Error::Runtime("launcher failed to start init".into()))?;
            }
            let code = sys::waitpid(launcher)?;
            if code != 0 {
                return Err(Error::Runtime(format!(
                    "launcher exited with status {code}; see {}",
                    layout.log().display()
                )));
            }
            let init_pid = libc::pid_t::from_ne_bytes(pid_bytes);
            if sys::read_byte(&to_sup.read)? != Some(b'u') {
                let _ = sys::try_wait(init_pid);
                return Err(Error::Runtime(format!(
                    "sandbox init failed; see {}",
                    layout.log().display()
                )));
            }
            ns::write_maps(init_pid, map)?;
            sys::write_all(&to_init.write, b"g")?;
            Ok(init_pid)
        }
    }
}

fn init_main(
    sb: &Sandbox,
    layout: &Layout,
    policy: &sandbox_policy::NetworkPolicy,
    to_sup: &OwnedFd,
    from_sup: &OwnedFd,
    ready: &OwnedFd,
) -> Result<()> {
    let r = init_setup(sb, layout, policy).and_then(|()| {
        sys::unshare(libc::CLONE_NEWUSER)?;
        sys::write_all(to_sup, b"u")?;
        if sys::read_byte(from_sup)? != Some(b'g') {
            return Err(Error::Runtime("supervisor went away".into()));
        }
        sys::become_uid(0)?;
        seccomp::install(sb.config.security.nested_namespaces)?;
        caps::confine(sb.config.security.capabilities)
    });
    if let Err(e) = &r {
        eprintln!("init setup failed: {e}");
        sys::exit(1);
    }
    sys::write_all(ready, b"1")?;
    init_loop()
}

fn init_setup(sb: &Sandbox, layout: &Layout, policy: &sandbox_policy::NetworkPolicy) -> Result<()> {
    let _ = sys::setsid();
    sys::sethostname(&sb.name)?;
    let rootfs = layout.rootfs();
    mount::mount("proc", &rootfs.join("proc"), "proc", STD_NOEXEC, None)?;
    if policy.isolated {
        mount::mount(
            "sysfs",
            &rootfs.join("sys"),
            "sysfs",
            STD_NOEXEC | libc::MS_RDONLY,
            None,
        )?;
    }
    let cgdir = rootfs.join("sys/fs/cgroup");
    if cgroup::is_v2() {
        mount::mount("cgroup2", &cgdir, "cgroup2", STD_NOEXEC, None)?;
    } else if cgdir.exists() {
        mount::mount(
            "tmpfs",
            &cgdir,
            "tmpfs",
            STD_NOEXEC | libc::MS_RDONLY,
            Some("mode=755,size=4k"),
        )?;
    }
    mount::mount(
        "devpts",
        &rootfs.join("dev/pts"),
        "devpts",
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
    )?;
    mount::mount(
        "tmpfs",
        &rootfs.join("dev/shm"),
        "tmpfs",
        STD_NOEXEC,
        Some("mode=1777"),
    )?;
    let _ = mount::mount("mqueue", &rootfs.join("dev/mqueue"), "mqueue", STD_NOEXEC, None);
    mount::pivot_into(&rootfs)?;
    if policy.isolated {
        let _ = fs::write("/proc/sys/net/ipv4/ping_group_range", "0 65535");
    }
    rootfs::mask_proc()?;
    let _ = fs::create_dir_all("/run/user");
    Ok(())
}

fn init_loop() -> Result<()> {
    let sigs = sys::block_signals(&[libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGCHLD])?;
    let mut stopping: Option<Instant> = None;
    loop {
        match sys::wait_signal(&sigs, Some(Duration::from_millis(500))) {
            Some(libc::SIGCHLD) => sys::reap_any(),
            Some(_) if stopping.is_none() => {
                stopping = Some(Instant::now());
                sys::kill(-1, libc::SIGTERM);
            }
            _ => {}
        }
        if let Some(t) = stopping {
            sys::reap_any();
            if !has_children() {
                sys::exit(0);
            }
            if t.elapsed() > Duration::from_secs(8) {
                sys::kill(-1, libc::SIGKILL);
                sys::reap_any();
                sys::exit(0);
            }
        }
    }
}

fn has_children() -> bool {
    fs::read_dir("/proc")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()))
                .any(|p| p != 1)
        })
        .unwrap_or(false)
}
