#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user, bpf_probe_read_user_str,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use core::{mem::size_of, panic::PanicInfo, slice};

const EVENT_EXEC: u32 = 1;
const EVENT_CONNECT: u32 = 2;
const EVENT_FILE_OPEN: u32 = 3;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfEvent {
    timestamp_ns: u64,
    pid: u32,
    uid: u32,
    kind: u32,
    family: u32,
    port: u16,
    reserved: u16,
    ipv4: u32,
    ipv6: [u8; 16],
    comm: [u8; 16],
    path: [u8; 256],
    padding: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SysEnterContext {
    common: [u8; 8],
    syscall_number: i64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    family: u16,
    port: u16,
    address: u32,
    zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    address: [u8; 16],
    scope_id: u32,
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 24, 0);

fn new_event(kind: u32) -> BpfEvent {
    let pid_tgid = bpf_get_current_pid_tgid();
    BpfEvent {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid: (pid_tgid >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        kind,
        family: 0,
        port: 0,
        reserved: 0,
        ipv4: 0,
        ipv6: [0; 16],
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
        path: [0; 256],
        padding: [0; 8],
    }
}

fn submit_event(event: &BpfEvent) {
    if let Some(mut entry) = EVENTS.reserve_bytes(size_of::<BpfEvent>(), 0) {
        let bytes = unsafe {
            slice::from_raw_parts(
                (event as *const BpfEvent).cast::<u8>(),
                size_of::<BpfEvent>(),
            )
        };
        entry.copy_from_slice(bytes);
        entry.submit(0);
    }
}

#[tracepoint(name = "sys_enter_execve", category = "syscalls")]
pub fn trace_execve(ctx: TracePointContext) -> u32 {
    let Ok(context) = (unsafe { ctx.read_at::<SysEnterContext>(0) }) else {
        return 0;
    };
    let mut event = new_event(EVENT_EXEC);
    if unsafe { bpf_probe_read_user_str(context.args[0] as *const u8, &mut event.path) }.is_err() {
        return 0;
    }
    submit_event(&event);
    0
}

#[tracepoint(name = "sys_enter_connect", category = "syscalls")]
pub fn trace_connect(ctx: TracePointContext) -> u32 {
    let Ok(context) = (unsafe { ctx.read_at::<SysEnterContext>(0) }) else {
        return 0;
    };
    let address_ptr = context.args[1] as *const u8;
    let Ok(family) = (unsafe { bpf_probe_read_user::<u16>(address_ptr.cast()) }) else {
        return 0;
    };
    let mut event = new_event(EVENT_CONNECT);
    event.family = family as u32;

    match family {
        AF_INET => {
            let Ok(address) = (unsafe { bpf_probe_read_user::<SockAddrIn>(address_ptr.cast()) })
            else {
                return 0;
            };
            event.port = address.port;
            event.ipv4 = address.address;
        }
        AF_INET6 => {
            let Ok(address) = (unsafe { bpf_probe_read_user::<SockAddrIn6>(address_ptr.cast()) })
            else {
                return 0;
            };
            event.port = address.port;
            event.ipv6 = address.address;
        }
        _ => return 0,
    }

    submit_event(&event);
    0
}

#[tracepoint(name = "sys_enter_openat", category = "syscalls")]
pub fn trace_openat(ctx: TracePointContext) -> u32 {
    let Ok(context) = (unsafe { ctx.read_at::<SysEnterContext>(0) }) else {
        return 0;
    };
    let mut event = new_event(EVENT_FILE_OPEN);
    if unsafe { bpf_probe_read_user_str(context.args[1] as *const u8, &mut event.path) }.is_err() {
        return 0;
    }
    submit_event(&event);
    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
