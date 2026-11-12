//! JSON logs on stderr, and OTLP traces when the process is given a collector.
//!
//! `OTEL_EXPORTER_OTLP_HEADERS` is read by the exporter. It is not written here.

use anyhow::{Context, Result};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub struct Guard {
    provider: Option<SdkTracerProvider>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

pub fn init() -> Result<Guard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("infer=info"));
    let json = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(std::io::stderr)
        .with_current_span(false)
        .with_span_list(false);
    let export_traces = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .is_some_and(|value| !value.trim().is_empty());
    if !export_traces {
        tracing_subscriber::registry()
            .with(filter)
            .with(json)
            .try_init()
            .context("installing the log subscriber")?;
        return Ok(Guard { provider: None });
    }

    // The exporter reads OTEL_EXPORTER_OTLP_ENDPOINT itself. The value is not logged.
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .build()
        .context("building the OTLP span exporter")?;
    let service = std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "infer".to_owned());
    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(service)
        .build();
    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();
    let tracer = provider.tracer("infer");
    tracing_subscriber::registry()
        .with(filter)
        .with(json)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .try_init()
        .context("installing the log and trace subscribers")?;
    tracing::info!("OTLP trace export enabled");
    Ok(Guard {
        provider: Some(provider),
    })
}
