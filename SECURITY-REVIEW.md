# Security Review

## Scope and status

This review examined the telemetry ingestion service and its relationship to
downstream event analysis. One medium-severity finding was identified and
mitigated by restricting the gRPC service to loopback addresses.

## Findings

### MEDIUM — Unauthenticated gRPC telemetry ingestion (mitigated)

- **Location:** `phase1/ingest/src/bin/ingest_server.rs`
- **Confidence:** 9/10
- **Original evidence:** The service defaulted to listening on `0.0.0.0:50051`
  and served gRPC without TLS or client authentication. The `PublishEvent`
  handler validates event fields but does not authenticate the sender before
  publishing to Kafka.
- **Impact:** A network-reachable client can submit fabricated telemetry.
  Downstream graph analysis may then be polluted or generate false alerts.
  Unencrypted traffic may also be observed or modified in transit.
- **Mitigation:** The server now defaults to `127.0.0.1:50051` and refuses all
  non-loopback bind addresses. Remote ingestion remains disabled until
  authenticated, encrypted transport (for example, mutual TLS) and client
  authorization are implemented.
