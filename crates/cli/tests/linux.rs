#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Output};

struct Env {
    home: tempfile::TempDir,
    name: String,
}

impl Env {
    fn new(tag: &str) -> Option<Self> {
        if unsafe { libc::geteuid() } != 0 || std::env::var_os("SANDBOX_INTEGRATION").is_none() {
            eprintln!("skipping: needs root and SANDBOX_INTEGRATION=1");
            return None;
        }
        let home = tempfile::tempdir().unwrap();
        let name = format!("it-{tag}-{}", std::process::id());
        Some(Self { home, name })
    }

    fn cmd(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sandbox"))
            .arg("--home")
            .arg(self.home.path())
            .args(args)
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.cmd(args);
        assert!(
            out.status.success(),
            "`sandbox {}` failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn run(&self, script: &str) -> Output {
        self.cmd(&["run", &self.name, "--", "sh", "-c", script])
    }

    fn sh(&self, script: &str) -> String {
        let out = self.run(script);
        assert!(
            out.status.success(),
            "script failed: {script}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn fails(&self, script: &str) {
        let out = self.run(script);
        assert!(
            !out.status.success(),
            "expected failure: {script}\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.cmd(&["destroy", &self.name]);
    }
}

#[test]
fn lifecycle_and_persistence() {
    let Some(e) = Env::new("life") else { return };
    e.ok(&["create", &e.name, "--network", "none"]);
    assert_eq!(e.sh("hostname"), e.name);
    assert_eq!(e.sh("id -u"), "0");
    assert!(e.sh("echo $$").parse::<u32>().unwrap() < 20);
    e.sh("echo persisted > /root/state && mkdir -p /opt/app && echo x > /usr/local/bin/tool");
    e.ok(&["stop", &e.name]);
    assert!(e.ok(&["status", &e.name]).contains("stopped"));
    assert_eq!(e.sh("cat /root/state; cat /usr/local/bin/tool"), "persisted\nx");
    e.ok(&["stop", &e.name]);
    e.ok(&["snapshot", &e.name, "clean"]);
    e.sh("rm /root/state");
    e.ok(&["stop", &e.name]);
    e.ok(&["restore", &e.name, "clean"]);
    assert_eq!(e.sh("cat /root/state"), "persisted");
    e.ok(&["stop", &e.name]);
    e.ok(&["reset", &e.name]);
    e.fails("cat /root/state");
    let dir = PathBuf::from(
        e.ok(&["status", &e.name])
            .lines()
            .find_map(|l| l.strip_prefix("directory: "))
            .unwrap()
            .trim(),
    );
    e.ok(&["destroy", &e.name]);
    assert!(!dir.exists());
}

#[test]
fn stop_kills_process_tree() {
    let Some(e) = Env::new("tree") else { return };
    e.ok(&["create", &e.name, "--network", "none"]);
    e.sh("nohup sh -c 'sleep 600' >/dev/null 2>&1 &");
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(e.sh("ps -eo comm | grep -c '^sleep$'"), "1");
    e.ok(&["stop", &e.name]);
    let ps = Command::new("ps").args(["-eo", "args"]).output().unwrap();
    assert!(!String::from_utf8_lossy(&ps.stdout).contains("sleep 600"));
}

#[test]
fn host_is_invisible() {
    let Some(e) = Env::new("host") else { return };
    let home = e.home.path().to_str().unwrap().to_string();
    e.ok(&["create", &e.name, "--network", "none"]);
    e.fails("ls /home/* 2>/dev/null | grep -q .");
    e.fails(&format!("test -e {home}"));
    e.fails("grep -q '^root:[^:*!]' /etc/shadow");
    e.fails("test -e /etc/ssh/ssh_host_rsa_key");
    e.fails("ps -eo comm | grep -q cargo");
    e.fails("test -e /proc/kcore");
    assert_eq!(e.sh("ls /var/log"), "apt");
}

#[test]
fn escape_primitives_are_blocked() {
    let Some(e) = Env::new("esc") else { return };
    e.ok(&["create", &e.name, "--network", "none"]);
    e.fails("mount -t tmpfs none /mnt");
    e.fails("umount /proc");
    e.fails("unshare -U true");
    e.fails("unshare -m true");
    e.fails("unshare -pf true");
    e.fails("echo 1 > /proc/sys/kernel/sysrq");
    e.fails("mknod /tmp/dev c 1 3");
    e.fails("python3 -c 'import os; os.setuid(65536)'");
    e.fails("nsenter -t 1 -m true");
    assert_eq!(
        e.sh("grep CapBnd /proc/self/status | cut -f2"),
        "00000000a00405fb"
    );
    assert_eq!(e.sh("grep Seccomp: /proc/self/status | cut -f2"), "2");
}

#[test]
fn resource_limits_apply() {
    let Some(e) = Env::new("res") else { return };
    e.ok(&[
        "create",
        &e.name,
        "--network",
        "none",
        "--processes",
        "64",
        "--memory",
        "64M",
    ]);
    let out = e.sh("python3 -c '
import os
n = 0
try:
    while n < 200:
        if os.fork() == 0:
            os.execlp(\"sleep\", \"sleep\", \"5\")
        n += 1
except OSError:
    pass
print(n)
'");
    let forks: u32 = out.trim().parse().unwrap();
    assert!(forks < 64, "fork bomb was not capped: {forks}");
    let oom = e.run("python3 -c 'b = bytearray(200 * 1024 * 1024); print(len(b))'");
    assert!(!oom.status.success());
}

#[test]
fn file_transfer_and_host_import() {
    let Some(e) = Env::new("xfer") else { return };
    e.ok(&["create", &e.name, "--network", "none"]);
    let src = e.home.path().join("in.txt");
    std::fs::write(&src, "from host\n").unwrap();
    e.ok(&["put", &e.name, src.to_str().unwrap(), "/root/Downloads/in.txt"]);
    assert_eq!(e.sh("cat /root/Downloads/in.txt"), "from host");
    e.sh("echo from sandbox > /root/out.txt; ln -sf /etc/hostname /root/link");
    let dst = e.home.path().join("out.txt");
    e.ok(&["get", &e.name, "/root/out.txt", dst.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(&dst).unwrap(), "from sandbox\n");
    e.ok(&["stop", &e.name]);
    e.ok(&["get", &e.name, "/root/link", dst.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(&dst).unwrap().trim(), e.name);
    let app = e.home.path().join("app.sh");
    std::fs::write(&app, "#!/bin/sh\necho app-in-$(hostname)\n").unwrap();
    std::fs::set_permissions(&app, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sandbox"))
        .current_dir(e.home.path())
        .args([
            "--home",
            e.home.path().to_str().unwrap(),
            "run",
            &e.name,
            "--",
            "./app.sh",
        ])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        format!("app-in-{}", e.name),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn network_modes() {
    let Some(e) = Env::new("net") else { return };
    e.ok(&["create", &e.name, "--network", "none"]);
    assert_eq!(e.sh("cut -d: -f1 /proc/net/dev | tail -n +3 | tr -d ' '"), "lo");
    e.fails("getent hosts example.com");
    e.ok(&["destroy", &e.name]);
    if std::env::var_os("SANDBOX_INTEGRATION_INTERNET").is_none() {
        return;
    }
    e.ok(&["create", &e.name, "--network", "internet"]);
    assert!(e
        .sh("cut -d: -f1 /proc/net/dev | tail -n +3 | tr -d ' '")
        .contains("tap0"));
    e.sh("getent hosts deb.debian.org");
    e.fails("curl -sS -m 3 http://10.0.2.2/");
    e.fails("curl -sS -m 3 http://192.168.0.1/");
}

#[test]
fn users_and_sudo() {
    let Some(e) = Env::new("user") else { return };
    e.ok(&["create", &e.name, "--network", "none"]);
    let out = e.cmd(&[
        "run",
        &e.name,
        "--user",
        "sandbox",
        "--",
        "sh",
        "-c",
        "id -un; echo $HOME; sudo -n id -u",
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "sandbox\n/home/sandbox\n0"
    );
    assert_eq!(
        e.sh("awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd"),
        "sandbox"
    );
}
