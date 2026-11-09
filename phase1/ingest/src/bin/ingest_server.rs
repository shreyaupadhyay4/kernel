use std::{env, net::SocketAddr};

use aegis_phase1::{
    ingest::KafkaIngest, telemetry::telemetry_ingest_server::TelemetryIngestServer,
};
use anyhow::Context;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listen: SocketAddr = env::var("AEGIS_GRPC_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:50051".to_owned())
        .parse()
        .context("parse AEGIS_GRPC_LISTEN")?;
    validate_listen_address(listen)?;
    let brokers =
        env::var("KAFKA_BOOTSTRAP_SERVERS").unwrap_or_else(|_| "localhost:9092".to_owned());
    let topic = env::var("KAFKA_TOPIC").unwrap_or_else(|_| "aegis-telemetry".to_owned());
    let service = KafkaIngest::new(&brokers, topic).await?;

    println!("gRPC telemetry ingestion listening at {listen}");
    Server::builder()
        .add_service(TelemetryIngestServer::new(service))
        .serve(listen)
        .await
        .context("serve gRPC telemetry ingestion")
}

fn validate_listen_address(listen: SocketAddr) -> anyhow::Result<()> {
    anyhow::ensure!(
        listen.ip().is_loopback(),
        "refusing to expose unauthenticated gRPC ingestion on {listen}; use a loopback address. Remote ingestion requires TLS and client authentication, which are not configured"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_listen_address;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn allows_ipv4_loopback() {
        assert!(validate_listen_address(SocketAddr::from((Ipv4Addr::LOCALHOST, 50051))).is_ok());
    }

    #[test]
    fn allows_ipv6_loopback() {
        assert!(validate_listen_address(SocketAddr::from((Ipv6Addr::LOCALHOST, 50051))).is_ok());
    }

    #[test]
    fn rejects_non_loopback_bind_addresses() {
        for address in ["0.0.0.0:50051", "192.0.2.10:50051", "[::]:50051"] {
            let listen = address.parse().expect("valid socket address");
            let error = validate_listen_address(listen).expect_err("non-loopback must be rejected");
            assert!(error.to_string().contains("TLS and client authentication"));
        }
    }
}
