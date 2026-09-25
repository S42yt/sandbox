use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

use sandbox_core::{Error, IoContext, Result};
use sandbox_policy::NetworkPolicy;

use crate::sys::{self, Fork};

pub const SLIRP_DNS: &str = "10.0.2.3";
const SLIRP_GW6: &str = "fd00::2";
const TAP: &str = "tap0";

pub struct Network {
    slirp: Option<libc::pid_t>,
}

impl Network {
    pub fn none() -> Self {
        Self { slirp: None }
    }

    pub fn start(policy: &NetworkPolicy, init_pid: libc::pid_t, log: &Path) -> Result<Self> {
        if !policy.isolated {
            return Ok(Self::none());
        }
        bring_up_loopback(init_pid)?;
        if !policy.internet {
            return Ok(Self::none());
        }
        if !(policy.lan && policy.host) {
            apply_firewall(init_pid, policy)?;
        }
        let slirp = spawn_slirp(init_pid, policy, log)?;
        Ok(Self { slirp: Some(slirp) })
    }

    pub fn pid(&self) -> Option<libc::pid_t> {
        self.slirp
    }

    pub fn stop(&mut self) {
        if let Some(pid) = self.slirp.take() {
            sys::kill(pid, libc::SIGTERM);
            if !sys::wait_pid_gone(pid, Duration::from_secs(2)) {
                sys::kill(pid, libc::SIGKILL);
            }
            let _ = sys::try_wait(pid);
        }
    }
}

fn in_netns<F: FnOnce() -> Result<()>>(init_pid: libc::pid_t, what: &str, f: F) -> Result<()> {
    let ns = File::open(format!("/proc/{init_pid}/ns/net"))
        .with_ctx(|| "opening sandbox network namespace".to_string())?;
    sys::run_child(what, move || {
        sys::setns(ns.as_raw_fd(), libc::CLONE_NEWNET)?;
        f()
    })
}

fn bring_up_loopback(init_pid: libc::pid_t) -> Result<()> {
    in_netns(init_pid, "loopback", || {
        let sock = sys::check_i(
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) },
            || "socket".into(),
        )?;
        let sock = unsafe { OwnedFd::from_raw_fd(sock) };
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        for (i, b) in b"lo".iter().enumerate() {
            req.ifr_name[i] = *b as libc::c_char;
        }
        sys::check_i(
            unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS, &mut req) },
            || "SIOCGIFFLAGS lo".into(),
        )?;
        unsafe {
            req.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        }
        sys::check_i(
            unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS, &req) },
            || "SIOCSIFFLAGS lo".into(),
        )?;
        Ok(())
    })
}

pub struct HostAddrs {
    pub v4: BTreeSet<String>,
    pub v6: BTreeSet<String>,
}

pub fn host_addresses() -> HostAddrs {
    let mut out = HostAddrs {
        v4: BTreeSet::new(),
        v6: BTreeSet::new(),
    };
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            match unsafe { (*ifa.ifa_addr).sa_family } as i32 {
                libc::AF_INET => {
                    let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    if !ip.is_loopback() {
                        out.v4.insert(ip.to_string());
                    }
                }
                libc::AF_INET6 => {
                    let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                    let ip = std::net::Ipv6Addr::from(sin.sin6_addr.s6_addr);
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        out.v6.insert(ip.to_string());
                    }
                }
                _ => {}
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifap) };
    out
}

pub fn ruleset(policy: &NetworkPolicy, host: &HostAddrs) -> String {
    let mut r = String::from(
        "table inet sandbox {\n  chain output {\n    type filter hook output priority 0; policy accept;\n    oifname \"lo\" accept\n",
    );
    r.push_str(&format!(
        "    ip daddr {SLIRP_DNS} udp dport 53 accept\n    ip daddr {SLIRP_DNS} tcp dport 53 accept\n"
    ));
    let v4 = "reject with icmp type admin-prohibited";
    let v6 = "reject with icmpv6 type admin-prohibited";
    if !policy.lan {
        r.push_str(&format!("    ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, 224.0.0.0/4, 240.0.0.0/4 }} {v4}\n"));
        r.push_str(&format!(
            "    ip6 daddr {{ fc00::/7, fe80::/10, ff00::/8 }} {v6}\n"
        ));
    } else if !policy.host {
        r.push_str(&format!(
            "    ip daddr 10.0.2.2 {v4}\n    ip6 daddr {SLIRP_GW6} {v6}\n"
        ));
        if !host.v4.is_empty() {
            let list: Vec<&str> = host.v4.iter().map(String::as_str).collect();
            r.push_str(&format!("    ip daddr {{ {} }} {v4}\n", list.join(", ")));
        }
        if !host.v6.is_empty() {
            let list: Vec<&str> = host.v6.iter().map(String::as_str).collect();
            r.push_str(&format!("    ip6 daddr {{ {} }} {v6}\n", list.join(", ")));
        }
    }
    r.push_str("  }\n}\n");
    r
}

fn apply_firewall(init_pid: libc::pid_t, policy: &NetworkPolicy) -> Result<()> {
    let nft = sys::which("nft").ok_or_else(|| {
        Error::Runtime(
            "network policy restricts LAN or host access, which needs the `nft` tool (package nftables) on the host; install it or set network.lan = true and network.host = true".into(),
        )
    })?;
    let rules = ruleset(policy, &host_addresses());
    let p = sys::pipe()?;
    let ns = File::open(format!("/proc/{init_pid}/ns/net"))
        .with_ctx(|| "opening sandbox network namespace".to_string())?;
    let nft = sys::cstr(&nft)?;
    let pid = match sys::fork()? {
        Fork::Child => {
            drop(p.write);
            let r = sys::setns(ns.as_raw_fd(), libc::CLONE_NEWNET)
                .and_then(|()| sys::dup2(p.read.as_raw_fd(), 0));
            if r.is_ok() {
                let args = [nft.as_ptr(), c"-f".as_ptr(), c"-".as_ptr(), std::ptr::null()];
                unsafe { libc::execv(nft.as_ptr(), args.as_ptr()) };
            }
            sys::exit(127)
        }
        Fork::Parent(pid) => pid,
    };
    drop(p.read);
    let written = sys::write_all(&p.write, rules.as_bytes());
    drop(p.write);
    let code = sys::waitpid(pid)?;
    written?;
    if code != 0 {
        return Err(Error::Runtime(format!(
            "nft failed to apply the network policy (exit {code}); see the supervisor log"
        )));
    }
    Ok(())
}

fn spawn_slirp(init_pid: libc::pid_t, policy: &NetworkPolicy, log: &Path) -> Result<libc::pid_t> {
    let bin = sys::which("slirp4netns").ok_or_else(|| {
        Error::Runtime("internet access needs `slirp4netns` on the host (package slirp4netns); install it or set network.internet = false".into())
    })?;
    let ready = sys::pipe()?;
    let ready_fd = ready.write.as_raw_fd();
    let mut args: Vec<CString> = vec![
        sys::cstr(&bin)?,
        c"--configure".into(),
        c"--mtu=65520".into(),
        c"--enable-ipv6".into(),
        c"--disable-dns".into(),
        c"--enable-seccomp".into(),
        CString::new(format!("--ready-fd={ready_fd}")).unwrap(),
        c"--netns-type=path".into(),
    ];
    if !policy.host {
        args.push(c"--disable-host-loopback".into());
    }
    args.push(CString::new(format!("/proc/{init_pid}/ns/net")).unwrap());
    args.push(CString::new(TAP).unwrap());
    let argv: Vec<*const libc::c_char> = args
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let log = log.to_path_buf();
    let pid = match sys::fork()? {
        Fork::Child => {
            drop(ready.read);
            unsafe {
                libc::fcntl(ready_fd, libc::F_SETFD, 0);
            }
            let _ = sys::redirect_stdio(Path::new("/dev/null"), &log);
            sys::unblock_all_signals();
            let _ = sys::set_pdeathsig(libc::SIGKILL);
            unsafe { libc::execv(argv[0], argv.as_ptr()) };
            sys::exit(127)
        }
        Fork::Parent(pid) => pid,
    };
    drop(ready.write);
    let start = Instant::now();
    let mut ok = false;
    while start.elapsed() < Duration::from_secs(10) {
        if let Some(code) = sys::try_wait(pid)? {
            return Err(Error::Runtime(format!(
                "slirp4netns exited with status {code}; see the supervisor log"
            )));
        }
        if sys::poll_readable(&ready.read, 100) {
            ok = sys::read_byte(&ready.read)?.is_some();
            break;
        }
    }
    if !ok {
        sys::kill(pid, libc::SIGKILL);
        let _ = sys::waitpid(pid);
        return Err(Error::Runtime("slirp4netns did not become ready".into()));
    }
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(lan: bool, host: bool) -> NetworkPolicy {
        NetworkPolicy {
            isolated: true,
            internet: true,
            lan,
            host,
        }
    }

    fn addrs() -> HostAddrs {
        HostAddrs {
            v4: ["192.168.1.5".to_string()].into_iter().collect(),
            v6: ["2001:db8::5".to_string()].into_iter().collect(),
        }
    }

    #[test]
    fn internet_only_blocks_private_ranges() {
        let r = ruleset(&policy(false, false), &addrs());
        assert!(r.contains("192.168.0.0/16"));
        assert!(r.contains("fc00::/7"));
        assert!(!r.contains("192.168.1.5"));
    }

    #[test]
    fn lan_without_host_blocks_host_addresses() {
        let r = ruleset(&policy(true, false), &addrs());
        assert!(!r.contains("192.168.0.0/16"));
        assert!(r.contains("10.0.2.2"));
        assert!(r.contains("192.168.1.5"));
        assert!(r.contains("2001:db8::5"));
    }

    #[test]
    fn dns_is_always_allowed() {
        let r = ruleset(&policy(false, false), &addrs());
        assert!(r.contains("10.0.2.3 udp dport 53 accept"));
    }
}
