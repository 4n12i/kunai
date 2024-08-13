use core::ffi::c_void;

use aya_ebpf::{bpf_printk, cty::c_int, maps::PerCpuArray, programs::LsmContext};

use super::*;

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
unsafe fn try_lsm_security_file_open(ctx: &LsmContext) -> Result<LsmStatus, ProbeError> {
    let file = co_re::file::from_ptr(ctx.arg::<*const c_void>(0) as *const _);
    let path = core_read_kernel!(file, f_path)?;

    alloc::init()?;
    let buf = alloc::alloc_zero::<Path>()?;
    buf.core_resolve(&path, 128)?;

    // bpf_printk!(b"len: %d, depth: %d", buf.len(), buf.depth());

    let mut p = Path::default();
    let s = "/.dockerenv";
    let len = p.copy_from_str(s, Mode::Append).unwrap();
    if len == buf.len() {
        // bpf_printk!(b"path len=%d", len);

        for i in 0..100 { // core::mem::size_of::<Path>() {
            if i == buf.len() {
                break;
            }
     
            let b = buf.get_byte(i)?;
            bpf_printk!(b"%c", b);
        }
    }

    for i in 0..100 { // core::mem::size_of::<Path>() {
       if i == buf.len() {
           break;
       }

       let _b = buf.get_byte(i)?;
       // bpf_printk!(b"%c", b);
   }

    if buf.starts_with("/.dockerenv") {
        bpf_printk!(b"file_open /.dockerenv");
        // return Ok(LsmStatus::Block)
    };

    // let path = p.as_ptr();

    // let buf = unsafe {
    //     let buf_ptr = PATH_BUF.get_ptr_mut(0).ok_or(0).unwrap();
    //     &mut *buf_ptr
    // };

    // let f: *const file = ctx.arg(0);
    // let p = &(*f).f_path;
    // // let aya_path = unsafe { p as *mut aya_path };

    // let bpf_ptr = unsafe {
    //     PATH_BUF.get_ptr_mut(0).ok_or(0).unwrap()
    // };
    // let b: &mut Path = unsafe { &mut *bpf_ptr };
    
    // let len = unsafe { 
    //     bpf_d_path(
    //         p as *mut _, 
    //         buf.path.as_mut_ptr() as *mut c_char, 
    //         buf.path.len() as u32
    //     ) 
    // } as usize;

    // let s = core::str::from_utf8_unchecked(&buf.path[..len]);
    // if s.starts_with("tmp") {
    //     bpf_printk!(b"detect");
    //     return Ok(LsmStatus::Block)
    // }

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
