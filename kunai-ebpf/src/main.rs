#![deny(unused_imports)]
#![no_std]
#![no_main]

// bringing probes into main
mod probes;

mod actions;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
