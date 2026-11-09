use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    time::Duration,
};

use aegis_phase1::telemetry::{
    EventType, TelemetryEvent, telemetry_ingest_client::TelemetryIngestClient,
};
use anyhow::{Context, anyhow, bail};
use aya::{Ebpf, maps::RingBuf, programs::TracePoint};
use bytemuck::{Pod, Zeroable, pod_read_unaligned};
use clap::Parser;
use tokio::time::sleep;

#[derive(Parser)]
struct Args {
    #[arg(long, env = "AEGIS_BPF_OBJECT")]
    bpf_object: PathBuf,
    #[arg(
        long,
        env = "AEGIS_GRPC_ENDPOINT",
        default_value = "http://127.0.0.1:50051"
    )]
    grpc_endpoint: String,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut bpf = Ebpf::load_file(&args.bpf_object)
        .with_context(|| format!("load eBPF object {}", args.bpf_object.display()))?;

    for (program_name, category, event_name) in [
        ("trace_execve", "syscalls", "sys_enter_execve"),
        ("trace_connect", "syscalls", "sys_enter_connect"),
        ("trace_openat", "syscalls", "sys_enter_openat"),
    ] {
        let program: &mut TracePoint = bpf
            .program_mut(program_name)
            .ok_or_else(|| anyhow!("eBPF object is missing {program_name}"))?
            .try_into()
            .with_context(|| format!("{program_name} is not a tracepoint program"))?;
        program
            .load()
            .with_context(|| format!("load tracepoint {program_name}"))?;
        program
            .attach(category, event_name)
            .with_context(|| format!("attach {category}:{event_name}"))?;
    }

    let mut ring_buf = RingBuf::try_from(
        bpf.take_map("EVENTS")
            .ok_or_else(|| anyhow!("eBPF object is missing EVENTS ring buffer"))?,
    )
    .context("open EVENTS ring buffer")?;
    let mut client = TelemetryIngestClient::connect(args.grpc_endpoint.clone())
        .await
        .with_context(|| {
            format!(
                "connect to gRPC ingestion service at {}",
                args.grpc_endpoint
            )
        })?;

    println!("AegisKernel Rust agent attached; forwarding telemetry to gRPC.");
    loop {
        let mut forwarded = false;
        while let Some(item) = ring_buf.next() {
            let raw = pod_read_unaligned::<BpfEvent>(&item);
            drop(item);
            let event = decode_event(raw)?;
            let mut delay = Duration::from_millis(100);
            loop {
                match client.publish_event(event.clone()).await {
                    Ok(ack) => {
                        if ack.into_inner().accepted {
                            break;
                        }
                        bail!("gRPC ingestion service rejected an event");
                    }
                    Err(error) => {
                        eprintln!("gRPC publish failed; retrying: {error}");
                        sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(5));
                    }
                }
            }
            forwarded = true;
        }
        if !forwarded {
            sleep(Duration::from_millis(10)).await;
        }
    }
}

fn decode_event(raw: BpfEvent) -> anyhow::Result<TelemetryEvent> {
    let comm = c_string(&raw.comm)?;
    if comm.is_empty() {
        bail!("captured event has an empty command name");
    }
    let parent_pid = read_parent_pid(raw.pid).unwrap_or_default();

    let mut event = TelemetryEvent {
        timestamp_ns: raw.timestamp_ns,
        pid: raw.pid,
        ppid: parent_pid,
        uid: raw.uid,
        comm,
        event_type: raw.kind as i32,
        attempted: true,
        ..Default::default()
    };
    match EventType::try_from(raw.kind as i32).context("unknown eBPF event kind")? {
        EventType::ProcessExec => event.executable = c_string(&raw.path)?,
        EventType::NetworkConnect => {
            event.destination_ip = match raw.family {
                2 => IpAddr::V4(Ipv4Addr::from(raw.ipv4.to_ne_bytes())).to_string(),
                10 => IpAddr::V6(Ipv6Addr::from(raw.ipv6)).to_string(),
                family => bail!("unsupported address family {family}"),
            };
            event.destination_port = u16::from_be(raw.port) as u32;
        }
        EventType::FileOpen => event.path = c_string(&raw.path)?,
        EventType::Unspecified => bail!("unspecified eBPF event kind"),
    }
    Ok(event)
}

fn c_string(value: &[u8]) -> anyhow::Result<String> {
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len());
    String::from_utf8(value[..end].to_vec()).context("event string is not valid UTF-8")
}

fn read_parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(") ")?.1;
    after_comm.split_whitespace().nth(1)?.parse().ok()
}
