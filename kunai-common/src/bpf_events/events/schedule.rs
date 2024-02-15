use crate::bpf_events::{Event, Nodename};

use crate::buffer::Buffer;
use crate::cgroup::Cgroup;
use crate::path::Path;

pub type ScheduleEvent = Event<ScheduleData>;

pub struct ScheduleData {
    pub exe: Path,
    pub argv: Buffer<512>,
    pub nodename: Nodename,
    pub cgroup: Cgroup,
}
