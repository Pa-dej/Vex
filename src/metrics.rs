use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};

#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Registry>,
    active_connections: IntGauge,
    backend_inflight: IntGaugeVec,
    backend_connect_errors_total: IntCounterVec,
    backend_latency_seconds: HistogramVec,
    backend_health_state: IntGaugeVec,
    connections_rejected_total: IntCounterVec,
    connections_total: IntCounterVec,
    connection_duration_seconds: Histogram,
    login_duration_seconds: HistogramVec,
    login_failures_total: IntCounterVec,
    backend_bytes_sent_total: IntCounterVec,
    backend_bytes_recv_total: IntCounterVec,
    backend_reconnects_total: IntCounterVec,
    ratelimit_hits_total: IntCounterVec,
    reputation_score_histogram: Histogram,
    reputation_blocks_total: IntCounterVec,
    reputation_delays_total: IntCounterVec,
    protocol_versions_total: IntCounterVec,
    attack_mode_active: IntGauge,
    attack_detections_total: IntCounter,
    unique_ips_per_minute: IntGauge,
    connections_per_second: IntGauge,
    process_memory_bytes: IntGauge,
    tokio_tasks_active: IntGauge,
    cluster_nodes_active: IntGauge,
    cluster_global_players: IntGauge,
    cluster_redis_ops_total: IntCounterVec,
    cluster_redis_errors_total: IntCounterVec,
    cluster_events_published: IntCounter,
    cluster_events_received: IntCounter,
    cluster_sync_duration_seconds: Histogram,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let registry = Arc::new(Registry::new());

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

        let connections_total = IntCounterVec::new(
            Opts::new(
                "vex_connections_total",
                "Total client connections partitioned by result",
            ),
            &["result"],
        )?;
        registry.register(Box::new(connections_total.clone()))?;
        for result in ["success", "reject", "error"] {
            let _ = connections_total.with_label_values(&[result]);
        }

        let connection_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "vex_connection_duration_seconds",
                "Client connection duration in seconds",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        )?;
        registry.register(Box::new(connection_duration_seconds.clone()))?;

        let login_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "vex_login_duration_seconds",
                "Login pipeline latency by auth mode",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["auth_mode"],
        )?;
        registry.register(Box::new(login_duration_seconds.clone()))?;
        for auth_mode in ["online", "offline"] {
            let _ = login_duration_seconds.with_label_values(&[auth_mode]);
        }

        let login_failures_total = IntCounterVec::new(
            Opts::new(
                "vex_login_failures_total",
                "Login failures partitioned by reason",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(login_failures_total.clone()))?;
        for reason in [
            "auth_failed",
            "circuit_open",
            "timeout",
            "backend_unavailable",
        ] {
            let _ = login_failures_total.with_label_values(&[reason]);
        }

        let backend_bytes_sent_total = IntCounterVec::new(
            Opts::new(
                "vex_backend_bytes_sent_total",
                "Total bytes sent from proxy to backend",
            ),
            &["backend"],
        )?;
        registry.register(Box::new(backend_bytes_sent_total.clone()))?;

        let backend_bytes_recv_total = IntCounterVec::new(
            Opts::new(
                "vex_backend_bytes_recv_total",
                "Total bytes received from backend by proxy",
            ),
            &["backend"],
        )?;
        registry.register(Box::new(backend_bytes_recv_total.clone()))?;

        let backend_reconnects_total = IntCounterVec::new(
            Opts::new(
                "vex_backend_reconnects_total",
                "Number of times backend recovered from unhealthy to healthy",
            ),
            &["backend"],
        )?;
        registry.register(Box::new(backend_reconnects_total.clone()))?;

        let ratelimit_hits_total = IntCounterVec::new(
            Opts::new(
                "vex_ratelimit_hits_total",
                "Rate limiter rejections partitioned by scope",
            ),
            &["scope"],
        )?;
        registry.register(Box::new(ratelimit_hits_total.clone()))?;
        for scope in ["ip", "subnet", "global"] {
            let _ = ratelimit_hits_total.with_label_values(&[scope]);
        }

        let reputation_score_histogram = Histogram::with_opts(
            HistogramOpts::new(
                "vex_reputation_score_histogram",
                "Reputation score distribution for anti-bot pipeline",
            )
            .buckets(vec![0.0, 10.0, 25.0, 50.0, 75.0, 90.0, 100.0]),
        )?;
        registry.register(Box::new(reputation_score_histogram.clone()))?;

        let reputation_blocks_total = IntCounterVec::new(
            Opts::new(
                "vex_reputation_blocks_total",
                "Reputation-based blocks partitioned by block duration tier",
            ),
            &["duration"],
        )?;
        registry.register(Box::new(reputation_blocks_total.clone()))?;
        for duration in ["30s", "2min", "10min"] {
            let _ = reputation_blocks_total.with_label_values(&[duration]);
        }

        let reputation_delays_total = IntCounterVec::new(
            Opts::new(
                "vex_reputation_delays_total",
                "Reputation-based delayed connections partitioned by delay tier",
            ),
            &["tier"],
        )?;
        registry.register(Box::new(reputation_delays_total.clone()))?;
        for tier in ["200ms", "500ms"] {
            let _ = reputation_delays_total.with_label_values(&[tier]);
        }

        let protocol_versions_total = IntCounterVec::new(
            Opts::new(
                "vex_protocol_versions_total",
                "Observed protocol versions by Minecraft version label",
            ),
            &["version"],
        )?;
        registry.register(Box::new(protocol_versions_total.clone()))?;

        let attack_mode_active = IntGauge::with_opts(Opts::new(
            "vex_attack_mode_active",
            "Attack mode state encoded as 1=active,0=inactive",
        ))?;
        registry.register(Box::new(attack_mode_active.clone()))?;

        let attack_detections_total = IntCounter::with_opts(Opts::new(
            "vex_attack_detections_total",
            "Total attack mode detections",
        ))?;
        registry.register(Box::new(attack_detections_total.clone()))?;

        let unique_ips_per_minute = IntGauge::with_opts(Opts::new(
            "vex_unique_ips_per_minute",
            "Observed unique source IP addresses in the current 60s window",
        ))?;
        registry.register(Box::new(unique_ips_per_minute.clone()))?;

        let connections_per_second = IntGauge::with_opts(Opts::new(
            "vex_connections_per_second",
            "Observed connections in the current second",
        ))?;
        registry.register(Box::new(connections_per_second.clone()))?;

        let process_memory_bytes = IntGauge::with_opts(Opts::new(
            "vex_process_memory_bytes",
            "Current Vex process RSS memory in bytes",
        ))?;
        registry.register(Box::new(process_memory_bytes.clone()))?;

        let tokio_tasks_active = IntGauge::with_opts(Opts::new(
            "vex_tokio_tasks_active",
            "Current active Tokio tasks in runtime metrics",
        ))?;
        registry.register(Box::new(tokio_tasks_active.clone()))?;

        let cluster_nodes_active = IntGauge::with_opts(Opts::new(
            "vex_cluster_nodes_active",
            "Active cluster nodes seen in last heartbeat window",
        ))?;
        registry.register(Box::new(cluster_nodes_active.clone()))?;

        let cluster_global_players = IntGauge::with_opts(Opts::new(
            "vex_cluster_global_players",
            "Total players across all cluster nodes",
        ))?;
        registry.register(Box::new(cluster_global_players.clone()))?;

        let cluster_redis_ops_total = IntCounterVec::new(
            Opts::new(
                "vex_cluster_redis_ops_total",
                "Cluster Redis operations partitioned by operation type",
            ),
            &["op"],
        )?;
        registry.register(Box::new(cluster_redis_ops_total.clone()))?;
        let _ = cluster_redis_ops_total.with_label_values(&["noop"]);

        let cluster_redis_errors_total = IntCounterVec::new(
            Opts::new(
                "vex_cluster_redis_errors_total",
                "Cluster Redis errors partitioned by operation type",
            ),
            &["op"],
        )?;
        registry.register(Box::new(cluster_redis_errors_total.clone()))?;
        let _ = cluster_redis_errors_total.with_label_values(&["noop"]);

        let cluster_events_published = IntCounter::with_opts(Opts::new(
            "vex_cluster_events_published",
            "Cluster events published to Redis pub/sub",
        ))?;
        registry.register(Box::new(cluster_events_published.clone()))?;

        let cluster_events_received = IntCounter::with_opts(Opts::new(
            "vex_cluster_events_received",
            "Cluster events received from Redis pub/sub",
        ))?;
        registry.register(Box::new(cluster_events_received.clone()))?;

        let cluster_sync_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "vex_cluster_sync_duration_seconds",
                "Duration of cluster full sync/heartbeat cycle",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0]),
        )?;
        registry.register(Box::new(cluster_sync_duration_seconds.clone()))?;

        Ok(Self {
            registry,
            active_connections,
            backend_inflight,
            backend_connect_errors_total,
            backend_latency_seconds,
            backend_health_state,
            connections_rejected_total,
            connections_total,
            connection_duration_seconds,
            login_duration_seconds,
            login_failures_total,
            backend_bytes_sent_total,
            backend_bytes_recv_total,
            backend_reconnects_total,
            ratelimit_hits_total,
            reputation_score_histogram,
            reputation_blocks_total,
            reputation_delays_total,
            protocol_versions_total,
            attack_mode_active,
            attack_detections_total,
            unique_ips_per_minute,
            connections_per_second,
            process_memory_bytes,
            tokio_tasks_active,
            cluster_nodes_active,
            cluster_global_players,
            cluster_redis_ops_total,
            cluster_redis_errors_total,
            cluster_events_published,
            cluster_events_received,
            cluster_sync_duration_seconds,
        })
    }

    pub fn spawn_runtime_sampler(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let metrics = self.clone();
        tokio::spawn(async move {
            loop {
                metrics.sample_runtime_metrics();
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
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

    pub fn inc_connection_result(&self, result: &str) {
        self.connections_total.with_label_values(&[result]).inc();
    }

    pub fn observe_connection_duration(&self, seconds: f64) {
        self.connection_duration_seconds.observe(seconds);
    }

    pub fn observe_login_duration(&self, auth_mode: &str, seconds: f64) {
        self.login_duration_seconds
            .with_label_values(&[auth_mode])
            .observe(seconds);
    }

    pub fn inc_login_failure(&self, reason: &str) {
        self.login_failures_total.with_label_values(&[reason]).inc();
    }

    pub fn inc_backend_bytes_sent(&self, backend: &str, bytes: u64) {
        self.backend_bytes_sent_total
            .with_label_values(&[backend])
            .inc_by(bytes);
    }

    pub fn inc_backend_bytes_recv(&self, backend: &str, bytes: u64) {
        self.backend_bytes_recv_total
            .with_label_values(&[backend])
            .inc_by(bytes);
    }

    pub fn inc_backend_reconnect(&self, backend: &str) {
        self.backend_reconnects_total
            .with_label_values(&[backend])
            .inc();
    }

    pub fn inc_ratelimit_hit(&self, scope: &str) {
        self.ratelimit_hits_total.with_label_values(&[scope]).inc();
    }

    pub fn observe_reputation_score(&self, score: f64) {
        self.reputation_score_histogram.observe(score);
    }

    pub fn inc_reputation_block(&self, duration: &str) {
        self.reputation_blocks_total
            .with_label_values(&[duration])
            .inc();
    }

    pub fn inc_reputation_delay(&self, tier: &str) {
        self.reputation_delays_total
            .with_label_values(&[tier])
            .inc();
    }

    pub fn init_backend_labels(&self, backend: &str) {
        let _ = self
            .backend_latency_seconds
            .with_label_values(&[backend, "status"]);
        let _ = self
            .backend_latency_seconds
            .with_label_values(&[backend, "tcp_fallback"]);
        for reason in ["connect_error", "connect_timeout", "probe_unreachable"] {
            let _ = self
                .backend_connect_errors_total
                .with_label_values(&[backend, reason]);
        }
        let _ = self.backend_bytes_sent_total.with_label_values(&[backend]);
        let _ = self.backend_bytes_recv_total.with_label_values(&[backend]);
        let _ = self.backend_reconnects_total.with_label_values(&[backend]);
    }

    pub fn init_protocol_version_label(&self, version: &str) {
        let _ = self.protocol_versions_total.with_label_values(&[version]);
    }

    pub fn inc_protocol_version(&self, version: &str) {
        self.protocol_versions_total
            .with_label_values(&[version])
            .inc();
    }

    pub fn set_process_memory_bytes(&self, bytes: u64) {
        self.process_memory_bytes.set(bytes as i64);
    }

    pub fn set_attack_mode_active(&self, active: bool) {
        self.attack_mode_active.set(i64::from(active as i32));
    }

    pub fn inc_attack_detection(&self) {
        self.attack_detections_total.inc();
    }

    pub fn set_unique_ips_per_minute(&self, unique_ips: usize) {
        self.unique_ips_per_minute.set(unique_ips as i64);
    }

    pub fn set_connections_per_second(&self, cps: u32) {
        self.connections_per_second.set(cps as i64);
    }

    pub fn set_tokio_tasks_active(&self, tasks: u64) {
        self.tokio_tasks_active.set(tasks as i64);
    }

    pub fn set_cluster_nodes_active(&self, nodes: i64) {
        self.cluster_nodes_active.set(nodes);
    }

    pub fn set_cluster_global_players(&self, players: i64) {
        self.cluster_global_players.set(players);
    }

    pub fn inc_cluster_redis_op(&self, op: &str) {
        self.cluster_redis_ops_total.with_label_values(&[op]).inc();
    }

    pub fn inc_cluster_redis_error(&self, op: &str) {
        self.cluster_redis_errors_total
            .with_label_values(&[op])
            .inc();
    }

    pub fn inc_cluster_events_published(&self) {
        self.cluster_events_published.inc();
    }

    pub fn inc_cluster_events_received(&self) {
        self.cluster_events_received.inc();
    }

    pub fn observe_cluster_sync_duration(&self, seconds: f64) {
        self.cluster_sync_duration_seconds.observe(seconds);
    }

    pub fn gather_text(&self) -> Result<String> {
        let mut output = Vec::new();
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        encoder.encode(&families, &mut output)?;
        Ok(String::from_utf8(output)?)
    }

    pub fn registry(&self) -> Arc<Registry> {
        self.registry.clone()
    }

    fn sample_runtime_metrics(&self) {
        if let Some(rss) = current_process_rss_bytes() {
            self.set_process_memory_bytes(rss);
        }

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let runtime_metrics = handle.metrics();
            self.set_tokio_tasks_active(runtime_metrics.num_alive_tasks() as u64);
        }
    }
}

#[cfg(target_os = "linux")]
fn current_process_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let vmrss = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kb = vmrss.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some(kb.saturating_mul(1024))
}

#[cfg(target_os = "windows")]
fn current_process_rss_bytes() -> Option<u64> {
    use std::ffi::c_void;
    use std::mem::size_of;

    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
    }

    #[link(name = "psapi")]
    unsafe extern "system" {
        fn GetProcessMemoryInfo(
            process: *mut c_void,
            counters: *mut ProcessMemoryCounters,
            cb: u32,
        ) -> i32;
    }

    let mut counters = ProcessMemoryCounters {
        cb: size_of::<ProcessMemoryCounters>() as u32,
        page_fault_count: 0,
        peak_working_set_size: 0,
        working_set_size: 0,
        quota_peak_paged_pool_usage: 0,
        quota_paged_pool_usage: 0,
        quota_peak_non_paged_pool_usage: 0,
        quota_non_paged_pool_usage: 0,
        pagefile_usage: 0,
        peak_pagefile_usage: 0,
    };

    let process = unsafe { GetCurrentProcess() };
    let ok = unsafe { GetProcessMemoryInfo(process, &mut counters, counters.cb) };
    if ok == 0 {
        return None;
    }
    Some(counters.working_set_size as u64)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn current_process_rss_bytes() -> Option<u64> {
    use sysinfo::{Pid, ProcessesToUpdate, System};

    let pid = Pid::from_u32(std::process::id());
    let mut system = System::new();
    let _ = system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    let process = system.process(pid)?;
    Some(process.memory())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_observability_metrics() -> Result<()> {
        let metrics = Metrics::new()?;
        metrics.init_backend_labels("backend-a");
        metrics.init_protocol_version_label("1.21.4");

        let output = metrics.gather_text()?;
        let expected = [
            "vex_connections_total",
            "vex_connection_duration_seconds",
            "vex_login_duration_seconds",
            "vex_login_failures_total",
            "vex_backend_bytes_sent_total",
            "vex_backend_bytes_recv_total",
            "vex_backend_reconnects_total",
            "vex_ratelimit_hits_total",
            "vex_reputation_score_histogram",
            "vex_reputation_blocks_total",
            "vex_reputation_delays_total",
            "vex_protocol_versions_total",
            "vex_attack_mode_active",
            "vex_attack_detections_total",
            "vex_unique_ips_per_minute",
            "vex_connections_per_second",
            "vex_process_memory_bytes",
            "vex_tokio_tasks_active",
            "vex_cluster_nodes_active",
            "vex_cluster_global_players",
            "vex_cluster_redis_ops_total",
            "vex_cluster_redis_errors_total",
            "vex_cluster_events_published",
            "vex_cluster_events_received",
            "vex_cluster_sync_duration_seconds",
        ];
        for metric_name in expected {
            assert!(
                output.contains(metric_name),
                "metrics output is missing '{metric_name}'"
            );
        }
        Ok(())
    }
}
