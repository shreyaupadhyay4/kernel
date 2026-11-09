#!/usr/bin/env python3
import argparse
import json
import socket
import struct
import time
from pathlib import Path
from typing import Any

from agent.telemetry_schema import normalize_event


BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>

#define EVENT_EXEC 1
#define EVENT_CONNECT 2
#define EVENT_FILE_OPEN 3

struct event_t {
    u64 ts;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 type;
    u32 family;
    u16 port;
    u32 ipv4;
    u8 ipv6[16];
    char comm[TASK_COMM_LEN];
    char path[256];
};

BPF_PERF_OUTPUT(events);

static inline void fill_common(struct event_t *event) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;

    event->ts = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent != NULL) {
        bpf_probe_read_kernel(&event->ppid, sizeof(event->ppid), &parent->tgid);
    }
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t event = {};
    event.type = EVENT_EXEC;
    fill_common(&event);
    if (bpf_probe_read_user_str(&event.path, sizeof(event.path), args->filename) <= 0) {
        return 0;
    }
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct event_t event = {};
    u16 family = 0;
    event.type = EVENT_CONNECT;
    fill_common(&event);

    if (args->uservaddr == NULL ||
        bpf_probe_read_user(&family, sizeof(family), args->uservaddr) < 0) {
        return 0;
    }
    event.family = family;

    if (family == AF_INET) {
        struct sockaddr_in addr = {};
        if (bpf_probe_read_user(&addr, sizeof(addr), args->uservaddr) < 0) {
            return 0;
        }
        event.port = addr.sin_port;
        event.ipv4 = addr.sin_addr.s_addr;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 addr = {};
        if (bpf_probe_read_user(&addr, sizeof(addr), args->uservaddr) < 0) {
            return 0;
        }
        event.port = addr.sin6_port;
        __builtin_memcpy(event.ipv6, addr.sin6_addr.in6_u.u6_addr8, 16);
    } else {
        return 0;
    }

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t event = {};
    event.type = EVENT_FILE_OPEN;
    fill_common(&event);
    if (bpf_probe_read_user_str(&event.path, sizeof(event.path), args->filename) <= 0) {
        return 0;
    }
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

EVENT_TYPES = {
    1: "exec",
    2: "connect",
    3: "file_open",
}


def decode_socket_address(family: int, address: bytes, network_port: int) -> tuple[str, int]:
    if family == socket.AF_INET:
        ip = socket.inet_ntop(socket.AF_INET, address[:4])
    elif family == socket.AF_INET6:
        ip = socket.inet_ntop(socket.AF_INET6, address[:16])
    else:
        raise ValueError(f"Unsupported socket address family: {family}")
    return ip, socket.ntohs(network_port)


def event_to_mapping(raw: Any) -> dict[str, Any]:
    event_type = EVENT_TYPES.get(int(raw.type))
    if event_type is None:
        raise ValueError(f"Unsupported BPF event type: {raw.type}")

    payload: dict[str, Any] = {
        "ts": int(raw.ts),
        "pid": int(raw.pid),
        "ppid": int(raw.ppid),
        "uid": int(raw.uid),
        "comm": raw.comm.decode("utf-8", "replace").split("\0", 1)[0],
        "event_type": event_type,
    }
    if event_type == "exec":
        payload["file"] = raw.path.decode("utf-8", "replace").split("\0", 1)[0]
    elif event_type == "file_open":
        payload["path"] = raw.path.decode("utf-8", "replace").split("\0", 1)[0]
    else:
        address = bytes(raw.ipv6)
        if int(raw.family) == socket.AF_INET:
            address = struct.pack("=I", int(raw.ipv4))
        payload["dest_ip"], payload["dest_port"] = decode_socket_address(
            int(raw.family), address, int(raw.port)
        )
    return normalize_event(payload)


def collect(output_path: str, duration_seconds: float) -> int:
    try:
        from bcc import BPF
    except ImportError as exc:
        raise RuntimeError(
            "BCC Python bindings are required. Install your distribution's BCC "
            "Python package and run with privileges needed to attach eBPF probes."
        ) from exc

    output = Path(output_path)
    try:
        handle = output.open("a", encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Cannot open telemetry output {output}: {exc}") from exc

    captured = 0
    try:
        bpf = BPF(text=BPF_PROGRAM)

        def on_event(_cpu, data, _size):
            nonlocal captured
            raw = bpf["events"].event(data)
            payload = event_to_mapping(raw)
            handle.write(json.dumps(payload) + "\n")
            handle.flush()
            captured += 1
            print(f"[eBPF] Captured {payload['event_type']} for PID {payload['pid']}")

        bpf["events"].open_perf_buffer(on_event)
        print(
            f"Collecting exec, connect, and openat syscall-entry events for "
            f"{duration_seconds:g}s into {output}. Records are attempted operations; "
            "this collector does not stop processes."
        )
        deadline = time.monotonic() + duration_seconds
        while time.monotonic() < deadline:
            try:
                bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
    finally:
        handle.close()

    print(f"Captured {captured} telemetry event(s)")
    return captured


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Capture live Linux execve, connect, and openat syscall-entry "
            "events into AegisKernel JSONL telemetry."
        )
    )
    parser.add_argument("output", help="JSONL file to append captured events to")
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="collection duration in seconds (default: 30)",
    )
    args = parser.parse_args()
    if args.duration <= 0:
        parser.error("--duration must be greater than zero")
    collect(args.output, args.duration)


if __name__ == "__main__":
    main()
