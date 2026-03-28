use anyhow::Result;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};

#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    active_connections: IntGauge,
    backend_inflight: IntGaugeVec,
    backend_connect_errors_total: IntCounterVec,
    backend_latency_seconds: HistogramVec,
    backend_health_state: IntGaugeVec,
    connections_rejected_total: IntCounterVec,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        let active_connections = IntGauge::with_opts(Opts::new(
            "vex_active_connections",
            "Current active client connections",
        ))?;
        registry.register(Box::new(active_connections.clone()))?;

        let backend_inflight = IntGaugeVec::new(
            Opts::new(
                "vex_backend_inflight",
                "Current inflight sessions per backend",
            ),
            &["backend"],
        )?;
        registry.register(Box::new(backend_inflight.clone()))?;

        let backend_connect_errors_total = IntCounterVec::new(
            Opts::new(
                "vex_backend_connect_errors_total",
                "Backend connect errors partitioned by reason",
            ),
            &["backend", "reason"],
        )?;
        registry.register(Box::new(backend_connect_errors_total.clone()))?;

        let backend_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "vex_backend_latency_seconds",
                "Backend latency histogram by backend and probe phase",
            ),
            &["backend", "phase"],
        )?;
        registry.register(Box::new(backend_latency_seconds.clone()))?;

        let backend_health_state = IntGaugeVec::new(
            Opts::new(
                "vex_backend_health_state",
                "Backend health state encoded as healthy=2,degraded=1,unhealthy=0",
            ),
            &["backend"],
        )?;
        registry.register(Box::new(backend_health_state.clone()))?;

        let connections_rejected_total = IntCounterVec::new(
            Opts::new(
                "vex_connections_rejected_total",
                "Rejected client connections partitioned by reason",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(connections_rejected_total.clone()))?;

        Ok(Self {
            registry,
            active_connections,
            backend_inflight,
            backend_connect_errors_total,
            backend_latency_seconds,
            backend_health_state,
            connections_rejected_total,
        })
    }

    pub fn inc_active_connections(&self) {
        self.active_connections.inc();
    }

    pub fn dec_active_connections(&self) {
        self.active_connections.dec();
    }

    pub fn set_backend_inflight(&self, backend: &str, value: i64) {
        self.backend_inflight
            .with_label_values(&[backend])
            .set(value);
    }

    pub fn inc_backend_error(&self, backend: &str, reason: &str) {
        self.backend_connect_errors_total
            .with_label_values(&[backend, reason])
            .inc();
    }

    pub fn observe_backend_latency(&self, backend: &str, phase: &str, seconds: f64) {
        self.backend_latency_seconds
            .with_label_values(&[backend, phase])
            .observe(seconds);
    }

    pub fn set_backend_health_state(&self, backend: &str, encoded_state: i64) {
        self.backend_health_state
            .with_label_values(&[backend])
            .set(encoded_state);
    }

    pub fn inc_reject(&self, reason: &str) {
        self.connections_rejected_total
            .with_label_values(&[reason])
            .inc();
    }

    pub fn gather_text(&self) -> Result<String> {
        let mut output = Vec::new();
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        encoder.encode(&families, &mut output)?;
        Ok(String::from_utf8(output)?)
    }
}
