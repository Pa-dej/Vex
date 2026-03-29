use rand::random;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::LogFormat;

pub fn init_tracing(default_level: &str, log_format: LogFormat) {
    let env_filter = std::env::var("RUST_LOG").unwrap_or_else(|_| default_level.to_string());
    let filter = EnvFilter::try_new(env_filter).unwrap_or_else(|_| EnvFilter::new(default_level));

    match log_format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .json()
                        .with_target(true)
                        .flatten_event(true)
                        .with_current_span(true)
                        .with_span_list(true),
                )
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().compact().with_target(false))
                .init();
        }
    }
}

pub fn generate_trace_id() -> String {
    format!("{:016x}", random::<u64>())
}
