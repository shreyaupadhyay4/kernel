# AegisKernel

AegisKernel is a local defensive security prototype for collecting and
analyzing process activity. It builds a process relationship graph, looks for
selected suspicious patterns, and presents its findings in a browser dashboard.

The Python pipeline is the easiest way to run the project. Rust and eBPF
components are included as an experimental implementation path.

## Features

- Normalize process execution, network connection, and file access events.
- Build an in-memory graph of processes and related files or network endpoints.
- Detect downloader and shell processes launched under a common parent within
  a short time window.
- Produce structured reports and an explainable, rule-based behavior score.
- Display sample or JSONL telemetry in a read-only dashboard.
- Provide a separate, explicitly approved SIGSTOP command with a process
  identity check.

## Project structure

- `agent/` — telemetry schema, detection rules, and sample events.
- `collector/` — optional Linux telemetry collector.
- `detector/` — process graph construction and behavior scoring.
- `swarm/` — structured reports and decision workflow.
- `response/` — approval-gated process response.
- `dashboard/` — local, read-only threat graph dashboard.
- `phase1/` — experimental Rust, eBPF, gRPC, and Kafka components.
- `deception/` — local evidence/session scaffold.
- `tests/` — Python regression tests.

## Requirements

- Python 3.11 or newer for the Python pipeline.
- Rust and Cargo for the Rust ingestion tests.
- Linux, BCC tools, suitable kernel support, and elevated privileges only if
  using the optional live telemetry collector.

## Installation

From the project directory, create a Python virtual environment and install
the dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage

Run the sample analysis:

```bash
python aegis_pipeline.py agent/attack_test.jsonl
```

Run the download-to-shell detector separately:

```bash
python agent/detect.py agent/attack_test.jsonl
```

Start the dashboard with simulated sample events:

```bash
python dashboard/graph_dashboard.py --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in a browser. To load
events from a JSONL file, provide its path with `--events`:

```bash
python dashboard/graph_dashboard.py --host 127.0.0.1 --port 8000 \
  --events agent/attack_test.jsonl
```

## Tests

Run the Python tests:

```bash
python -m pytest -q
```

Check and test the Rust ingestion crate:

```bash
cargo fmt --manifest-path phase1/Cargo.toml --all -- --check
cargo test --manifest-path phase1/Cargo.toml -p aegis-phase1
```

## Optional live telemetry

On a supported Linux system, install the distribution's BCC tools and Python
bindings. eBPF collection may require root privileges, kernel headers, and
kernel BPF support. Use a short collection window on systems you are authorized
to monitor:

```bash
sudo .venv/bin/python -m collector.ebpf_agent live-events.jsonl --duration 30
.venv/bin/python aegis_pipeline.py live-events.jsonl
```

The collector observes `execve`, `connect`, and `openat` system calls. Events
are recorded at system-call entry and indicate attempted operations; they do
not prove that an operation succeeded. Event files may contain sensitive
process names, paths, and network information. Review and sanitize them before
sharing.

## Safety and limitations

The behavior score is a manually weighted heuristic, not a trained model or a
probability of compromise. A `MONITOR` result only means the current rules did
not recommend containment; it does not prove a system is safe. Telemetry may be
incomplete, and the graph is an in-memory snapshot.

The analysis pipeline does not change process state. Process pausing is
available only through a separate command that requires explicit approval and
checks the process identity. SIGSTOP can interrupt services, so use it only
when authorized.

The gRPC ingestion server listens on `127.0.0.1:50051` by default and rejects
non-loopback bind addresses. Authenticated remote gRPC transport is not
implemented. The Rust/eBPF, Kafka, and graph-database paths have not been
verified end to end.

See [SECURITY-REVIEW.md](./SECURITY-REVIEW.md) for the ingestion security
finding and its mitigation.

## License

This project is licensed under the [MIT License](./LICENSE).
