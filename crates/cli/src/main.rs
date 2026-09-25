use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use sandbox_core::{Command as SandboxCommand, RunState, Sandbox, SandboxBackend, Store};
use sandbox_policy::{ByteSize, NetworkConfig, NetworkMode, SandboxConfig, Share};

#[derive(Parser)]
#[command(
    name = "sandbox",
    version,
    about = "Run applications in disposable, isolated environments"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        env = "SANDBOX_HOME",
        help = "Directory holding sandbox state"
    )]
    home: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(about = "Create a new sandbox")]
    Create {
        name: String,
        #[command(flatten)]
        opts: CreateOpts,
    },
    #[command(about = "Start a sandbox in the background")]
    Start { name: String },
    #[command(about = "Stop a running sandbox and all of its processes")]
    Stop { name: String },
    #[command(
        about = "Run a command inside a sandbox (starts it if needed)",
        trailing_var_arg = true
    )]
    Run {
        name: String,
        #[command(flatten)]
        exec: ExecOpts,
        #[arg(required = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
    #[command(about = "Open an interactive shell inside a sandbox")]
    Shell {
        name: String,
        #[command(flatten)]
        exec: ExecOpts,
    },
    #[command(about = "List sandboxes")]
    List,
    #[command(about = "Show the state of a sandbox")]
    Status { name: String },
    #[command(about = "Print or change the configuration of a sandbox")]
    Config {
        name: String,
        #[arg(
            long,
            value_name = "KEY=VALUE",
            help = "Set a value, e.g. network.mode=lan or resources.memory=8G"
        )]
        set: Vec<String>,
    },
    #[command(about = "Print the supervisor log of a sandbox")]
    Logs { name: String },
    #[command(about = "Copy a file from the host into a sandbox")]
    Put {
        name: String,
        source: PathBuf,
        destination: PathBuf,
    },
    #[command(about = "Copy a file out of a sandbox to the host")]
    Get {
        name: String,
        source: PathBuf,
        destination: PathBuf,
    },
    #[command(about = "Take a snapshot of a stopped sandbox, or list snapshots")]
    Snapshot {
        name: String,
        snapshot: Option<String>,
        #[arg(long, help = "Delete the snapshot instead of creating it")]
        delete: bool,
    },
    #[command(about = "Restore a stopped sandbox from a snapshot")]
    Restore { name: String, snapshot: String },
    #[command(about = "Return a stopped sandbox to its pristine state")]
    Reset { name: String },
    #[command(about = "Stop a sandbox and delete everything it owns")]
    Destroy { name: String },
}

#[derive(Args)]
struct ExecOpts {
    #[arg(
        long,
        short,
        default_value = "root",
        help = "User inside the sandbox to run as"
    )]
    user: String,
    #[arg(long, help = "Working directory inside the sandbox")]
    cwd: Option<PathBuf>,
    #[arg(
        long = "env",
        short = 'e',
        value_name = "KEY=VALUE",
        help = "Extra environment variables"
    )]
    env: Vec<String>,
}

#[derive(Args)]
struct CreateOpts {
    #[arg(
        long,
        value_name = "FILE",
        help = "Load the full configuration from a TOML file"
    )]
    from: Option<PathBuf>,
    #[arg(
        long,
        value_name = "MODE",
        help = "Network access: none, internet, lan, host or full"
    )]
    network: Option<NetworkMode>,
    #[arg(long, value_name = "SIZE", help = "Memory limit, e.g. 8G")]
    memory: Option<ByteSize>,
    #[arg(long, help = "CPU limit, e.g. 4 or 0.5")]
    cpus: Option<f64>,
    #[arg(long, value_name = "N", help = "Maximum number of processes")]
    processes: Option<u64>,
    #[arg(
        long,
        value_name = "HOST:SANDBOX[:rw]",
        help = "Share a host directory (read-only unless :rw)"
    )]
    share: Vec<String>,
    #[arg(long)]
    gpu: bool,
    #[arg(long)]
    audio: bool,
    #[arg(long)]
    microphone: bool,
    #[arg(long)]
    camera: bool,
    #[arg(long)]
    usb: bool,
    #[arg(long)]
    bluetooth: bool,
    #[arg(long)]
    controllers: bool,
    #[arg(long, help = "Expose the host display (X11/Wayland sockets)")]
    display: bool,
    #[arg(
        long = "env",
        short = 'e',
        value_name = "KEY=VALUE",
        help = "Environment variables for every process"
    )]
    env: Vec<String>,
    #[arg(long, help = "Allow the sandbox to create nested namespaces")]
    nested_namespaces: bool,
}

fn build_config(name: &str, o: &CreateOpts) -> Result<SandboxConfig> {
    let mut cfg = match &o.from {
        Some(p) => {
            let text = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
            let mut c = SandboxConfig::from_toml(&text)?;
            c.name = name.to_string();
            c
        }
        None => SandboxConfig::new(name),
    };
    if let Some(m) = o.network {
        cfg.network = NetworkConfig::from_mode(m);
    }
    if o.memory.is_some() {
        cfg.resources.memory = o.memory;
    }
    if o.cpus.is_some() {
        cfg.resources.cpus = o.cpus;
    }
    if let Some(p) = o.processes {
        cfg.resources.processes = p;
    }
    for s in &o.share {
        let parts: Vec<&str> = s.split(':').collect();
        let (host, path, readonly) = match parts.as_slice() {
            [h, p] => (h, p, true),
            [h, p, "rw"] => (h, p, false),
            [h, p, "ro"] => (h, p, true),
            _ => bail!("invalid --share `{s}`: expected HOST:SANDBOX[:rw]"),
        };
        cfg.filesystem.shares.push(Share {
            host: std::fs::canonicalize(host).with_context(|| format!("share {host}"))?,
            path: PathBuf::from(path),
            readonly,
        });
    }
    let d = &mut cfg.devices;
    d.gpu |= o.gpu;
    d.audio |= o.audio;
    d.microphone |= o.microphone;
    d.camera |= o.camera;
    d.usb |= o.usb;
    d.bluetooth |= o.bluetooth;
    d.controllers |= o.controllers;
    d.display |= o.display;
    for (k, v) in parse_env(&o.env)? {
        cfg.env.insert(k, v);
    }
    cfg.security.nested_namespaces |= o.nested_namespaces;
    cfg.validate()?;
    Ok(cfg)
}

fn parse_env(items: &[String]) -> Result<Vec<(String, String)>> {
    items
        .iter()
        .map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| anyhow!("invalid environment entry `{kv}`: expected KEY=VALUE"))
        })
        .collect()
}

fn backend(store: &Store) -> Result<Box<dyn SandboxBackend>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(sandbox_backend_linux::LinuxBackend::new(store)))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = store;
        bail!("this platform has no sandbox backend yet (Linux is supported; Windows and macOS are planned)")
    }
}

fn import_host_program(
    store: &Store,
    backend: &dyn SandboxBackend,
    sb: &Sandbox,
    argv: &mut [OsString],
    user: &str,
) -> Result<()> {
    let first = Path::new(&argv[0]);
    let is_host_relative = first.starts_with("./") || first.starts_with("../");
    if !is_host_relative || !first.is_file() {
        return Ok(());
    }
    let _ = store;
    let file = first.file_name().ok_or_else(|| anyhow!("bad program path"))?;
    let home = if user == "root" {
        PathBuf::from("/root")
    } else {
        PathBuf::from("/home").join(user)
    };
    let dest = home.join(file);
    backend.put_file(sb, first, &dest)?;
    eprintln!(
        "sandbox: copied {} to {} inside {}",
        first.display(),
        dest.display(),
        sb.name
    );
    argv[0] = dest.into_os_string();
    Ok(())
}

fn print_status(sb: &Sandbox, backend: &dyn SandboxBackend) -> Result<()> {
    let st = backend.status(sb)?;
    println!("name:      {}", sb.name);
    println!("state:     {}", st.state);
    println!("directory: {}", sb.dir.display());
    if let Some(p) = st.init_pid {
        println!("init pid:  {p}");
    }
    for (k, v) in st.details {
        println!("{:<10} {v}", format!("{k}:"));
    }
    let snaps = sb.snapshots()?;
    if !snaps.is_empty() {
        println!("snapshots: {}", snaps.join(", "));
    }
    Ok(())
}

fn real_main() -> Result<i32> {
    let cli = Cli::parse();
    let store = match cli.home {
        Some(h) => Store::new(h),
        None => Store::from_env()?,
    };
    let backend = backend(&store)?;
    match cli.cmd {
        Cmd::Create { name, opts } => {
            let cfg = build_config(&name, &opts)?;
            let sb = backend.create(&store, &cfg)?;
            println!("created sandbox {} ({})", sb.name, sb.dir.display());
        }
        Cmd::Start { name } => {
            let sb = store.open(&name)?;
            backend.start(&sb)?;
            println!("started sandbox {name}");
        }
        Cmd::Stop { name } => {
            let sb = store.open(&name)?;
            backend.stop(&sb)?;
            println!("stopped sandbox {name}");
        }
        Cmd::Run {
            name,
            exec,
            mut command,
        } => {
            let sb = store.open(&name)?;
            import_host_program(&store, backend.as_ref(), &sb, &mut command, &exec.user)?;
            let mut cmd = SandboxCommand::new(command);
            cmd.cwd = exec.cwd;
            cmd.env = parse_env(&exec.env)?;
            cmd.user = Some(exec.user);
            return Ok(backend.run(&sb, &cmd)?);
        }
        Cmd::Shell { name, exec } => {
            let sb = store.open(&name)?;
            let mut cmd =
                SandboxCommand::new(["/bin/sh", "-c", "exec \"$(command -v bash || echo /bin/sh)\" -l"]);
            cmd.cwd = exec.cwd;
            cmd.env = parse_env(&exec.env)?;
            cmd.user = Some(exec.user);
            return Ok(backend.run(&sb, &cmd)?);
        }
        Cmd::List => {
            let names = store.list()?;
            if names.is_empty() {
                println!("no sandboxes (create one with `sandbox create <name>`)");
            } else {
                println!("{:<24} {:<9} NETWORK", "NAME", "STATE");
                for n in names {
                    match store.open(&n) {
                        Ok(sb) => {
                            let state = backend.status(&sb).map(|s| s.state).unwrap_or(RunState::Stopped);
                            println!("{:<24} {:<9} {}", sb.name, state, sb.config.network.describe());
                        }
                        Err(e) => println!("{n:<24} {:<9} {e}", "broken"),
                    }
                }
            }
        }
        Cmd::Status { name } => print_status(&store.open(&name)?, backend.as_ref())?,
        Cmd::Config { name, set } => {
            let mut sb = store.open(&name)?;
            if !set.is_empty() {
                let mut text = std::fs::read_to_string(sb.config_path())?;
                for kv in &set {
                    let (k, v) = kv
                        .split_once('=')
                        .ok_or_else(|| anyhow!("invalid --set `{kv}`: expected KEY=VALUE"))?;
                    text = sandbox_policy::set_value(&text, k, v)?;
                }
                std::fs::write(sb.config_path(), &text)?;
                sb = store.open(&name)?;
                if backend.status(&sb)?.state == RunState::Running {
                    eprintln!("sandbox: {name} is running; the new configuration applies after a restart");
                }
            }
            print!("{}", sb.config.to_toml()?);
        }
        Cmd::Logs { name } => {
            let sb = store.open(&name)?;
            print!("{}", backend.logs(&sb)?);
        }
        Cmd::Put {
            name,
            source,
            destination,
        } => {
            let sb = store.open(&name)?;
            backend.put_file(&sb, &source, &destination)?;
        }
        Cmd::Get {
            name,
            source,
            destination,
        } => {
            let sb = store.open(&name)?;
            backend.get_file(&sb, &source, &destination)?;
        }
        Cmd::Snapshot {
            name,
            snapshot,
            delete,
        } => {
            let sb = store.open(&name)?;
            match snapshot {
                None => {
                    for s in sb.snapshots()? {
                        println!("{s}");
                    }
                }
                Some(s) if delete => {
                    backend.delete_snapshot(&sb, &s)?;
                    println!("deleted snapshot {s} of {name}");
                }
                Some(s) => {
                    backend.snapshot(&sb, &s)?;
                    println!("saved snapshot {s} of {name}");
                }
            }
        }
        Cmd::Restore { name, snapshot } => {
            let sb = store.open(&name)?;
            backend.restore(&sb, &snapshot)?;
            println!("restored {name} from snapshot {snapshot}");
        }
        Cmd::Reset { name } => {
            let sb = store.open(&name)?;
            backend.reset(&sb)?;
            println!("reset sandbox {name}");
        }
        Cmd::Destroy { name } => {
            let sb = store.open(&name)?;
            backend.destroy(&sb)?;
            println!("destroyed sandbox {name}");
        }
    }
    Ok(0)
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("sandbox: {e}");
            ExitCode::from(1)
        }
    }
}
