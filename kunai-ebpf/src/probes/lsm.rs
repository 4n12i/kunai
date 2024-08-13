use core::ffi::{c_void, c_long, c_char};

use aya_ebpf::{bindings::path, bpf_printk, cty::c_int, maps::PerCpuArray, programs::LsmContext};

use crate::vmlinux::file;

use super::*;

// use vmlinux::file;


#[repr(C)]
struct Path {
    path: [u8; MAX_PATH_LEN]
}

#[map]
static mut PATH_BUF: PerCpuArray<Path> = PerCpuArray::with_max_entries(1, 0);

enum LsmStatus {
    Continue(i32),
    Block,
}

impl From<LsmStatus> for i32 {
    #[inline(always)]
    fn from(value: LsmStatus) -> Self {
        match value {
            LsmStatus::Block => -1,
            LsmStatus::Continue(ret) => ret,
        }
    }
}

#[lsm(hook = "file_open")]
pub fn lsm_file_open(ctx: LsmContext) -> i32 {
    match unsafe { try_lsm_security_file_open(&ctx) } {
        Ok(s) => s.into(),
        Err(s) => {
            error!(&ctx, s);
            // we don't block on error to prevent DOS
            0
        }
    }
}

#[inline(always)]
pub fn my_bpf_d_path(path: *mut path, buf: &mut [u8]) -> Result<usize, c_long> {
    let ret = unsafe { aya_ebpf::helpers::bpf_d_path(path, buf.as_mut_ptr() as *mut c_char, buf.len() as u32) };
    if ret < 0 {
        return Err(ret);
    }

    Ok(ret as usize)
}

#[inline(always)]
unsafe fn try_lsm_security_file_open(ctx: &LsmContext) -> Result<LsmStatus, ProbeError> {
    let buf = unsafe {
        let buf_ptr = PATH_BUF.get_ptr_mut(0).ok_or(0).unwrap();
        &mut *buf_ptr
    };

    let p = {
        let f: *const file = ctx.arg(0);
        bpf_printk!(b"file_open: file: %s", f);
        let p = unsafe { &(*f).f_path as *const _ as *mut path };
        let len = my_bpf_d_path(p, &mut buf.path).map_err(|_| 0).unwrap();
        if len >= 64 { // path_len = 64
            return Ok(LsmStatus::Block);
        }
        core::str::from_utf8_unchecked(&buf.path[..len])
    };

    if p.starts_with("/.dockerenv") {
        return Ok(LsmStatus::Block)
    }

    Ok(LsmStatus::Continue(0))
}

#[lsm(hook = "task_kill")]
pub fn lsm_task_kill(ctx: LsmContext) -> i32 {
    match unsafe { try_lsm_security_task_kill(&ctx) } {
        Ok(s) => s.into(),
        Err(s) => {
            error!(&ctx, s);
            // we don't block on error to prevent DOS
            0
        }
    }
}

#[inline(always)]
unsafe fn try_lsm_security_task_kill(ctx: &LsmContext) -> Result<LsmStatus, ProbeError> {
    let target = co_re::task_struct::from_ptr(ctx.arg::<*const c_void>(0) as *const _);
    let sig: c_int = ctx.arg(2);
    // previous hook return code
    let ret: c_int = ctx.arg(4);

    // signal can be 0 but no signal is actually sent to the target
    // it is used only to check if the task can be killed
    if sig == 0 {
        return Ok(LsmStatus::Continue(ret));
    }

    let target_tgid = core_read_kernel!(target, tgid)?;

    // if the target is not kunai we let it go
    if target_tgid as u32 != get_cfg!()?.loader.tgid {
        return Ok(LsmStatus::Continue(ret));
    }

    // we block any attempt to send a signal to kunai
    Ok(LsmStatus::Block)
}

#[lsm(hook = "ptrace_access_check")]
pub fn lsm_ptrace_access_check(ctx: LsmContext) -> i32 {
    match unsafe { try_ptrace_access_check(&ctx) } {
        Ok(s) => s.into(),
        Err(s) => {
            error!(&ctx, s);
            // we don't block on error to prevent DOS
            0
        }
    }
}

#[inline(always)]
unsafe fn try_ptrace_access_check(ctx: &LsmContext) -> Result<LsmStatus, ProbeError> {
    let target = co_re::task_struct::from_ptr(ctx.arg::<*const c_void>(0) as *const _);
    // previous hook return code
    let ret: c_int = ctx.arg(2);

    let target_tgid = core_read_kernel!(target, tgid)?;

    // if the target is not kunai we let it go
    if target_tgid as u32 != get_cfg!()?.loader.tgid {
        return Ok(LsmStatus::Continue(ret));
    }

    // we block any attempt to ptrace kunai
    Ok(LsmStatus::Block)
}
