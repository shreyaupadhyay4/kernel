pub mod telemetry {
    tonic::include_proto!("aegis.telemetry.v1");
}

pub mod ingest {
    use std::collections::BTreeMap;

    use anyhow::Context;
    use chrono::Utc;
    use rskafka::{
        client::{
            ClientBuilder,
            partition::{Compression, UnknownTopicHandling},
        },
        record::Record,
    };
    use tonic::{Request, Response, Status};

    use crate::telemetry::{
        EventType, IngestAck, TelemetryEvent, telemetry_ingest_server::TelemetryIngest,
    };

    pub struct KafkaIngest {
        partition: rskafka::client::partition::PartitionClient,
    }

    impl KafkaIngest {
        pub async fn new(bootstrap_servers: &str, topic: String) -> anyhow::Result<Self> {
            let client = ClientBuilder::new(vec![bootstrap_servers.to_owned()])
                .build()
                .await
                .context("connect to Kafka bootstrap broker")?;
            let partition = client
                .partition_client(topic, 0, UnknownTopicHandling::Retry)
                .await
                .context("connect to telemetry topic partition 0")?;
            Ok(Self { partition })
        }
    }

    #[tonic::async_trait]
    impl TelemetryIngest for KafkaIngest {
        async fn publish_event(
            &self,
            request: Request<TelemetryEvent>,
        ) -> Result<Response<IngestAck>, Status> {
            let event = request.into_inner();
            validate_event(&event)?;
            let payload = prost::Message::encode_to_vec(&event);
            self.partition
                .produce(
                    vec![Record {
                        key: Some(event.pid.to_string().into_bytes()),
                        value: Some(payload),
                        headers: BTreeMap::new(),
                        timestamp: Utc::now(),
                    }],
                    Compression::NoCompression,
                )
                .await
                .map_err(|error| Status::unavailable(format!("Kafka publish failed: {error}")))?;

            Ok(Response::new(IngestAck { accepted: true }))
        }
    }

    fn validate_event(event: &TelemetryEvent) -> Result<(), Status> {
        if event.timestamp_ns == 0 || event.pid == 0 || event.comm.trim().is_empty() {
            return Err(Status::invalid_argument(
                "timestamp_ns, pid, and comm are required",
            ));
        }
        match EventType::try_from(event.event_type) {
            Ok(EventType::ProcessExec) if !event.executable.trim().is_empty() => Ok(()),
            Ok(EventType::NetworkConnect)
                if event.destination_ip.parse::<std::net::IpAddr>().is_ok()
                    && event.destination_port <= 65535 =>
            {
                Ok(())
            }
            Ok(EventType::FileOpen) if !event.path.trim().is_empty() => Ok(()),
            Ok(EventType::Unspecified) => Err(Status::invalid_argument("event_type is required")),
            Ok(_) => Err(Status::invalid_argument(
                "required event-specific fields are missing or invalid",
            )),
            Err(_) => Err(Status::invalid_argument("unknown event_type")),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::validate_event;
        use crate::telemetry::{EventType, TelemetryEvent};

        fn event(event_type: EventType) -> TelemetryEvent {
            TelemetryEvent {
                timestamp_ns: 1,
                pid: 42,
                comm: "test".to_owned(),
                event_type: event_type as i32,
                ..Default::default()
            }
        }

        #[test]
        fn accepts_valid_network_event() {
            let mut event = event(EventType::NetworkConnect);
            event.destination_ip = "192.0.2.1".to_owned();
            event.destination_port = 443;

            assert!(validate_event(&event).is_ok());
        }

        #[test]
        fn rejects_invalid_network_address() {
            let mut event = event(EventType::NetworkConnect);
            event.destination_ip = "not-an-ip".to_owned();
            event.destination_port = 443;

            assert!(validate_event(&event).is_err());
        }

        #[test]
        fn rejects_missing_event_type() {
            let event = event(EventType::Unspecified);

            assert!(validate_event(&event).is_err());
        }
    }
}
