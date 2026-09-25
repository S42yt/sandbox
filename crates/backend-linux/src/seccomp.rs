use sandbox_core::{Error, Result};

use crate::sys::{check, errno};

const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const RET_ALLOW: u32 = 0x7fff_0000;

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;

const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const OFF_ARG0_LO: u32 = 16;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn denied(nested: bool) -> Vec<libc::c_long> {
    let mut v: Vec<libc::c_long> = vec![
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_mount_setattr,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_clock_adjtime,
        libc::SYS_adjtimex,
        libc::SYS_acct,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_quotactl,
        libc::SYS_lookup_dcookie,
        libc::SYS_mbind,
        libc::SYS_move_pages,
        libc::SYS_set_mempolicy,
        libc::SYS_migrate_pages,
        libc::SYS_kcmp,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_syslog,
        libc::SYS_nfsservctl,
        libc::SYS_vhangup,
        libc::SYS_setdomainname,
        libc::SYS_sethostname,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([
        libc::SYS_iopl,
        libc::SYS_ioperm,
        libc::SYS_uselib,
        libc::SYS_modify_ldt,
    ]);
    if !nested {
        v.extend([libc::SYS_unshare, libc::SYS_setns]);
    }
    v
}

const NS_FLAGS: u32 = (libc::CLONE_NEWUSER
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWCGROUP
    | 0x80) as u32;

pub fn program(nested: bool) -> Vec<libc::sock_filter> {
    let mut p = vec![
        insn(LD_W_ABS, 0, 0, OFF_ARCH),
        insn(JEQ_K, 1, 0, AUDIT_ARCH),
        insn(RET_K, 0, 0, RET_KILL_PROCESS),
        insn(LD_W_ABS, 0, 0, OFF_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        p.push(insn(JSET_K, 0, 1, 0x4000_0000));
        p.push(insn(RET_K, 0, 0, RET_KILL_PROCESS));
    }
    for nr in denied(nested) {
        p.push(insn(JEQ_K, 0, 1, nr as u32));
        p.push(insn(RET_K, 0, 0, RET_ERRNO | libc::EPERM as u32));
    }
    if !nested {
        p.push(insn(JEQ_K, 0, 1, libc::SYS_clone3 as u32));
        p.push(insn(RET_K, 0, 0, RET_ERRNO | libc::ENOSYS as u32));
        p.push(insn(JEQ_K, 0, 4, libc::SYS_clone as u32));
        p.push(insn(LD_W_ABS, 0, 0, OFF_ARG0_LO));
        p.push(insn(JSET_K, 0, 1, NS_FLAGS));
        p.push(insn(RET_K, 0, 0, RET_ERRNO | libc::EPERM as u32));
        p.push(insn(LD_W_ABS, 0, 0, OFF_NR));
    }
    p.push(insn(RET_K, 0, 0, RET_ALLOW));
    p
}

pub fn install(nested: bool) -> Result<()> {
    let mut prog = program(nested);
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_mut_ptr(),
    };
    let r = unsafe { libc::syscall(libc::SYS_seccomp, 1u32, 0u32, &fprog as *const libc::sock_fprog) };
    if r < 0 {
        let e = errno();
        if e.raw_os_error() == Some(libc::ENOSYS) {
            return Err(Error::Runtime(
                "seccomp filters are not supported by this kernel".into(),
            ));
        }
        check(r, || "installing seccomp filter".into())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_is_well_formed() {
        for nested in [true, false] {
            let p = program(nested);
            assert!(p.len() < 4096);
            assert_eq!(p.last().unwrap().k, RET_ALLOW);
            for (i, ins) in p.iter().enumerate() {
                if ins.code == JEQ_K || ins.code == JSET_K {
                    let far = usize::from(ins.jt.max(ins.jf));
                    assert!(i + 1 + far < p.len(), "jump out of range at {i}");
                }
            }
        }
    }

    #[test]
    fn nested_mode_allows_unshare() {
        let strict = program(false);
        let nested = program(true);
        let has = |p: &[libc::sock_filter]| {
            p.iter()
                .any(|i| i.code == JEQ_K && i.k == libc::SYS_unshare as u32)
        };
        assert!(has(&strict));
        assert!(!has(&nested));
    }
}
