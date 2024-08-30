use kunai_common::bpf_events::Signal;

pub unsafe fn send_sigkill() -> i64 {
    aya_ebpf::helpers::bpf_send_signal(Signal::SIGKILL as u32)
}
