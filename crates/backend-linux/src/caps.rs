use sandbox_core::Result;
use sandbox_policy::CapabilitySet;

use crate::sys::{check, prctl};

const CAP_CHOWN: u32 = 0;
const CAP_DAC_OVERRIDE: u32 = 1;
const CAP_FOWNER: u32 = 3;
const CAP_FSETID: u32 = 4;
const CAP_KILL: u32 = 5;
const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;
const CAP_SETPCAP: u32 = 8;
const CAP_NET_BIND_SERVICE: u32 = 10;
const CAP_SYS_CHROOT: u32 = 18;
const CAP_AUDIT_WRITE: u32 = 29;
const CAP_SETFCAP: u32 = 31;

const DEFAULT_KEEP: &[u32] = &[
    CAP_CHOWN,
    CAP_DAC_OVERRIDE,
    CAP_FOWNER,
    CAP_FSETID,
    CAP_KILL,
    CAP_SETGID,
    CAP_SETUID,
    CAP_SETPCAP,
    CAP_NET_BIND_SERVICE,
    CAP_SYS_CHROOT,
    CAP_AUDIT_WRITE,
    CAP_SETFCAP,
];

#[repr(C)]
struct Header {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const VERSION_3: u32 = 0x2008_0522;

fn last_cap() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(40)
}

pub fn keep_set(set: CapabilitySet) -> &'static [u32] {
    match set {
        CapabilitySet::None => &[],
        CapabilitySet::Default => DEFAULT_KEEP,
    }
}

pub fn confine(set: CapabilitySet) -> Result<()> {
    let keep = keep_set(set);
    prctl(
        libc::PR_CAP_AMBIENT,
        libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
        0,
        0,
        0,
    )?;
    for cap in 0..=last_cap() {
        if !keep.contains(&cap) {
            prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0)?;
        }
    }
    let mut data = [Data::default(); 2];
    for cap in keep {
        let (idx, bit) = ((cap / 32) as usize, 1u32 << (cap % 32));
        data[idx].effective |= bit;
        data[idx].permitted |= bit;
    }
    let hdr = Header {
        version: VERSION_3,
        pid: 0,
    };
    check(
        unsafe { libc::syscall(libc::SYS_capset, &hdr as *const Header, data.as_ptr()) },
        || "dropping capabilities".into(),
    )?;
    Ok(())
}
