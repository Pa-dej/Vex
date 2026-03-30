//! Core plugin API surface.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use dashmap::{DashMap, DashSet};
#[cfg(feature = "metrics")]
use prometheus::{CounterVec, GaugeVec, HistogramOpts, HistogramVec, Opts, Registry};
use thiserror::Error;
use tokio::time::timeout;
use tracing::{error, warn};
use uuid::Uuid;

use crate::config::PluginConfig;
use crate::event::Event;
use crate::player::ProxiedPlayer;
use crate::scheduler::Scheduler;
use crate::server::BackendRef;

type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type ErasedHandler = Arc<dyn Fn(Arc<dyn Any + Send + Sync>) -> BoxFuture + Send + Sync>;
type CommandHandler = Arc<dyn Fn(CommandSender, Vec<String>) + Send + Sync>;
type PermissionChecker = Arc<dyn Fn(&ProxiedPlayer, &str) -> bool + Send + Sync>;

/// Main API handle provided to plugins in [`crate::VexPlugin::on_load`].
#[derive(Clone)]
pub struct PluginApi {
    /// Event registration and dispatch.
    pub events: Arc<EventBus>,
    /// Read/write access to proxy actions.
    pub proxy: Arc<ProxyHandle>,
    /// Command registry for plugin commands.
    pub commands: Arc<CommandRegistry>,
    /// Plugin scheduler.
    pub scheduler: Arc<Scheduler>,
    /// Plugin configuration.
    pub config: Arc<PluginConfig>,
    /// Plugin-scoped logger.
    pub logger: PluginLogger,
    /// Plugin metrics handle.
    pub metrics: Arc<MetricsHandle>,
}

impl PluginApi {
    /// Creates plugin API bundle.
    pub fn new(
        events: Arc<EventBus>,
        proxy: Arc<ProxyHandle>,
        commands: Arc<CommandRegistry>,
        scheduler: Arc<Scheduler>,
        config: Arc<PluginConfig>,
        logger: PluginLogger,
        metrics: Arc<MetricsHandle>,
    ) -> Self {
        Self {
            events,
            proxy,
            commands,
            scheduler,
            config,
            logger,
            metrics,
        }
    }
}

/// Asynchronous event bus used by plugins.
#[derive(Clone)]
pub struct EventBus {
    inner: Arc<EventBusInner>,
    plugin_name: Arc<str>,
}

struct EventBusInner {
    timeout_ms: AtomicU64,
    handlers: DashMap<TypeId, Vec<HandlerEntry>>,
    faulted_plugins: DashSet<String>,
}

#[derive(Clone)]
struct HandlerEntry {
    plugin_name: Arc<str>,
    priority: i32,
    handler: ErasedHandler,
}

impl EventBus {
    /// Creates an event bus with default handler timeout.
    pub fn new(timeout: Duration) -> Self {
        Self {
            inner: Arc::new(EventBusInner {
                timeout_ms: AtomicU64::new(timeout.as_millis() as u64),
                handlers: DashMap::new(),
                faulted_plugins: DashSet::new(),
            }),
            plugin_name: Arc::from("host"),
        }
    }

    /// Returns a plugin-scoped view of this event bus.
    pub fn with_plugin(&self, plugin_name: impl Into<Arc<str>>) -> Self {
        Self {
            inner: self.inner.clone(),
            plugin_name: plugin_name.into(),
        }
    }

    /// Registers an async event handler with priority `0`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use std::time::Duration;
    /// # use vex_proxy_sdk::api::EventBus;
    /// # use vex_proxy_sdk::event::OnLoginSuccess;
    /// let bus = EventBus::new(Duration::from_millis(500));
    /// bus.on::<OnLoginSuccess, _, _>(|event| async move {
    ///     let _name = event.player.username.clone();
    /// });
    /// ```
    pub fn on<E, F, Fut>(&self, handler: F)
    where
        E: Event + 'static,
        F: Fn(Arc<E>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.on_priority(0, handler);
    }

    /// Registers an async event handler with explicit priority.
    ///
    /// Lower values run first. Handlers with the same priority run concurrently.
    pub fn on_priority<E, F, Fut>(&self, priority: i32, handler: F)
    where
        E: Event + 'static,
        F: Fn(Arc<E>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let erased: ErasedHandler = Arc::new(move |event_any| {
            let handler = handler.clone();
            match event_any.downcast::<E>() {
                Ok(event) => Box::pin(async move {
                    (handler)(event).await;
                }),
                Err(_) => Box::pin(async move {}),
            }
        });

        let mut list = self.inner.handlers.entry(TypeId::of::<E>()).or_default();
        list.push(HandlerEntry {
            plugin_name: self.plugin_name.clone(),
            priority,
            handler: erased,
        });
        list.sort_by_key(|entry| entry.priority);
    }

    /// Dispatches event with configured default timeout.
    pub async fn dispatch<E>(&self, event: Arc<E>) -> Arc<E>
    where
        E: Event + 'static,
    {
        let timeout_ms = self.inner.timeout_ms.load(Ordering::Relaxed);
        let timeout_duration = Duration::from_millis(timeout_ms.max(1));
        self.dispatch_internal(event, timeout_duration).await
    }

    /// Dispatches event with explicit timeout.
    pub async fn dispatch_with_timeout<E>(
        &self,
        event: Arc<E>,
        timeout_duration: Duration,
    ) -> Arc<E>
    where
        E: Event + 'static,
    {
        self.dispatch_internal(event, timeout_duration).await
    }

    async fn dispatch_internal<E>(&self, event: Arc<E>, timeout_duration: Duration) -> Arc<E>
    where
        E: Event + 'static,
    {
        let handlers = self
            .inner
            .handlers
            .get(&TypeId::of::<E>())
            .map(|entries| entries.clone())
            .unwrap_or_default();

        if handlers.is_empty() {
            return event;
        }

        let timeout_ms = timeout_duration.as_millis() as u64;
        let mut grouped: HashMap<i32, Vec<HandlerEntry>> = HashMap::new();
        for entry in handlers {
            grouped.entry(entry.priority).or_default().push(entry);
        }

        let mut priorities = grouped.keys().copied().collect::<Vec<_>>();
        priorities.sort_unstable();

        for priority in priorities {
            let entries = grouped.remove(&priority).unwrap_or_default();
            let mut in_flight = Vec::with_capacity(entries.len());

            for entry in entries {
                if self
                    .inner
                    .faulted_plugins
                    .contains(entry.plugin_name.as_ref())
                {
                    continue;
                }

                let plugin_name = entry.plugin_name.clone();
                let handler = entry.handler.clone();
                let event_any: Arc<dyn Any + Send + Sync> = event.clone();
                let handle = tokio::spawn(async move {
                    (handler)(event_any).await;
                });
                in_flight.push((plugin_name, handle));
            }

            for (plugin_name, mut handle) in in_flight {
                match timeout(timeout_duration, &mut handle).await {
                    Ok(Ok(())) => {}
                    Ok(Err(join_error)) => {
                        error!(
                            plugin = plugin_name.as_ref(),
                            error = %join_error,
                            "plugin event handler panicked"
                        );
                        self.mark_plugin_faulted(plugin_name.as_ref());
                    }
                    Err(_) => {
                        warn!(
                            plugin = plugin_name.as_ref(),
                            timeout_ms = timeout_ms,
                            "plugin event handler timed out"
                        );
                        handle.abort();
                    }
                }
            }

            if event.is_cancelled() {
                break;
            }
        }

        event
    }

    /// Removes all handlers and fault state for plugin.
    pub fn unregister_plugin(&self, plugin_name: &str) {
        for mut handlers in self.inner.handlers.iter_mut() {
            handlers.retain(|entry| entry.plugin_name.as_ref() != plugin_name);
        }
        self.inner.faulted_plugins.remove(plugin_name);
    }

    /// Marks plugin as faulted to skip future handlers.
    pub fn mark_plugin_faulted(&self, plugin_name: &str) {
        self.inner.faulted_plugins.insert(plugin_name.to_string());
    }

    /// Returns whether plugin is currently faulted.
    pub fn is_plugin_faulted(&self, plugin_name: &str) -> bool {
        self.inner.faulted_plugins.contains(plugin_name)
    }

    /// Updates default event timeout.
    pub fn set_timeout(&self, timeout: Duration) {
        self.inner
            .timeout_ms
            .store(timeout.as_millis() as u64, Ordering::Relaxed);
    }
}

/// Registry for commands exposed by plugins.
#[derive(Clone)]
pub struct CommandRegistry {
    inner: Arc<CommandRegistryInner>,
}

struct CommandRegistryInner {
    commands: DashMap<String, RegisteredCommand>,
    permission_checker: RwLock<Option<PermissionChecker>>,
}

#[derive(Clone)]
struct RegisteredCommand {
    plugin: Arc<str>,
    description: Arc<str>,
    handler: CommandHandler,
}

impl CommandRegistry {
    /// Creates empty command registry.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CommandRegistryInner {
                commands: DashMap::new(),
                permission_checker: RwLock::new(None),
            }),
        }
    }

    /// Registers a command handler.
    pub fn register<F>(&self, plugin: &str, name: &str, description: &str, handler: F)
    where
        F: Fn(CommandSender, Vec<String>) + Send + Sync + 'static,
    {
        let command_key = name.trim().to_ascii_lowercase();
        self.inner.commands.insert(
            command_key,
            RegisteredCommand {
                plugin: Arc::from(plugin),
                description: Arc::from(description),
                handler: Arc::new(handler),
            },
        );
    }

    /// Unregisters a command by owner and command name.
    pub fn unregister(&self, plugin: &str, name: &str) {
        let command_key = name.trim().to_ascii_lowercase();
        let should_remove = self
            .inner
            .commands
            .get(&command_key)
            .map(|entry| entry.plugin.as_ref() == plugin)
            .unwrap_or(false);
        if should_remove {
            self.inner.commands.remove(&command_key);
        }
    }

    /// Unregisters all commands belonging to plugin.
    pub fn unregister_plugin(&self, plugin: &str) {
        let keys = self
            .inner
            .commands
            .iter()
            .filter(|entry| entry.plugin.as_ref() == plugin)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in keys {
            self.inner.commands.remove(&key);
        }
    }

    /// Sets permission checker called for player command execution.
    pub fn set_permission_checker<F>(&self, checker: F)
    where
        F: Fn(&ProxiedPlayer, &str) -> bool + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.inner.permission_checker.write() {
            *guard = Some(Arc::new(checker));
        }
    }

    /// Clears custom permission checker.
    pub fn clear_permission_checker(&self) {
        if let Ok(mut guard) = self.inner.permission_checker.write() {
            *guard = None;
        }
    }

    /// Executes command from a sender.
    ///
    /// Returns `false` if command does not exist or permission is denied.
    pub fn execute(&self, name: &str, sender: CommandSender, args: Vec<String>) -> bool {
        let key = name.trim().to_ascii_lowercase();
        let Some(entry) = self.inner.commands.get(&key) else {
            return false;
        };

        if let CommandSender::Player(player) = &sender {
            if let Ok(guard) = self.inner.permission_checker.read() {
                if let Some(checker) = guard.as_ref() {
                    let permission = format!("command.{key}");
                    if !checker(player, &permission) {
                        return false;
                    }
                }
            }
        }

        (entry.handler)(sender, args);
        true
    }

    /// Returns command description if present.
    pub fn description(&self, name: &str) -> Option<String> {
        let key = name.trim().to_ascii_lowercase();
        self.inner
            .commands
            .get(&key)
            .map(|entry| entry.description.to_string())
    }

    /// Returns command owner (plugin name) if present.
    pub fn owner(&self, name: &str) -> Option<String> {
        let key = name.trim().to_ascii_lowercase();
        self.inner
            .commands
            .get(&key)
            .map(|entry| entry.plugin.to_string())
    }
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Command invocation sender.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CommandSender {
    /// Proxy console/admin API context.
    Console,
    /// Player-issued command.
    Player(ProxiedPlayer),
}

/// Proxy operations exposed to plugins.
pub trait ProxyOps: Send + Sync + 'static {
    /// Returns all online players.
    fn get_players(&self) -> Vec<ProxiedPlayer>;
    /// Looks up player by username.
    fn get_player(&self, username: &str) -> Option<ProxiedPlayer>;
    /// Looks up player by UUID.
    fn get_player_by_uuid(&self, uuid: Uuid) -> Option<ProxiedPlayer>;
    /// Returns available backends.
    fn get_backends(&self) -> Vec<BackendRef>;
    /// Broadcasts text message to all players.
    fn broadcast(&self, message: &str);
    /// Broadcasts text message to selected players.
    fn broadcast_to(&self, message: &str, filter: &(dyn Fn(&ProxiedPlayer) -> bool + Send + Sync));
    /// Returns total online players.
    fn online_count(&self) -> usize;
    /// Returns online player count for backend.
    fn online_count_for(&self, backend: &BackendRef) -> usize;
    /// Forwards plugin payload to selected players.
    fn forward_plugin_message(
        &self,
        channel: &str,
        data: Bytes,
        filter: &(dyn Fn(&ProxiedPlayer) -> bool + Send + Sync),
    );
}

/// Object-safe wrapper around [`ProxyOps`].
#[derive(Clone)]
pub struct ProxyHandle {
    ops: Arc<dyn ProxyOps>,
}

impl ProxyHandle {
    /// Creates a handle from proxy operations implementation.
    pub fn new(ops: Arc<dyn ProxyOps>) -> Self {
        Self { ops }
    }

    /// Returns all online players.
    pub fn get_players(&self) -> Vec<ProxiedPlayer> {
        self.ops.get_players()
    }

    /// Looks up player by username.
    pub fn get_player(&self, username: &str) -> Option<ProxiedPlayer> {
        self.ops.get_player(username)
    }

    /// Looks up player by UUID.
    pub fn get_player_by_uuid(&self, uuid: Uuid) -> Option<ProxiedPlayer> {
        self.ops.get_player_by_uuid(uuid)
    }

    /// Returns available backends.
    pub fn get_backends(&self) -> Vec<BackendRef> {
        self.ops.get_backends()
    }

    /// Broadcasts text message to all players.
    pub fn broadcast(&self, message: &str) {
        self.ops.broadcast(message);
    }

    /// Broadcasts text message to selected players.
    pub fn broadcast_to<F>(&self, message: &str, filter: F)
    where
        F: Fn(&ProxiedPlayer) -> bool + Send + Sync,
    {
        self.ops.broadcast_to(message, &filter);
    }

    /// Returns total online players.
    pub fn online_count(&self) -> usize {
        self.ops.online_count()
    }

    /// Returns online player count for backend.
    pub fn online_count_for(&self, backend: &BackendRef) -> usize {
        self.ops.online_count_for(backend)
    }

    /// Forwards plugin payload to selected players.
    pub fn forward_plugin_message<F>(&self, channel: &str, data: Bytes, filter: F)
    where
        F: Fn(&ProxiedPlayer) -> bool + Send + Sync,
    {
        self.ops.forward_plugin_message(channel, data, &filter);
    }
}

/// Metrics API errors.
#[derive(Debug, Error)]
pub enum MetricsError {
    /// Metric name is invalid after normalization.
    #[error("invalid metric name '{0}'")]
    InvalidMetricName(String),
    /// Metric already exists.
    #[error("metric already registered '{0}'")]
    AlreadyRegistered(String),
    /// Prometheus metrics support is disabled.
    #[cfg(not(feature = "metrics"))]
    #[error("metrics feature is disabled for vex-sdk")]
    Unavailable,
    /// Error returned by Prometheus registry.
    #[cfg(feature = "metrics")]
    #[error(transparent)]
    Prometheus(#[from] prometheus::Error),
}

#[cfg(feature = "metrics")]
#[derive(Clone)]
enum PluginCollector {
    Counter(CounterVec),
    Gauge(GaugeVec),
    Histogram(HistogramVec),
}

#[cfg(feature = "metrics")]
impl PluginCollector {
    fn unregister(self, registry: &Registry) {
        let _ = match self {
            Self::Counter(metric) => registry.unregister(Box::new(metric)),
            Self::Gauge(metric) => registry.unregister(Box::new(metric)),
            Self::Histogram(metric) => registry.unregister(Box::new(metric)),
        };
    }
}

/// Plugin-scoped metrics registration handle.
#[cfg(feature = "metrics")]
#[derive(Clone)]
pub struct MetricsHandle {
    registry: Arc<Registry>,
    plugin_name: Arc<str>,
    collectors: Arc<DashMap<String, PluginCollector>>,
}

/// Plugin-scoped metrics registration handle.
#[cfg(not(feature = "metrics"))]
#[derive(Clone)]
pub struct MetricsHandle {
    plugin_name: Arc<str>,
}

#[cfg(feature = "metrics")]
impl MetricsHandle {
    /// Creates metrics handle with plugin prefix.
    pub fn new(registry: Arc<Registry>, plugin_name: impl Into<Arc<str>>) -> Self {
        Self {
            registry,
            plugin_name: plugin_name.into(),
            collectors: Arc::new(DashMap::new()),
        }
    }

    /// Registers a counter vec metric for plugin.
    pub fn register_counter(
        &self,
        name: &str,
        help: &str,
        labels: &[&str],
    ) -> Result<PluginCounter, MetricsError> {
        let metric_name = self.prefixed_name(name)?;
        if self.collectors.contains_key(&metric_name) {
            return Err(MetricsError::AlreadyRegistered(metric_name));
        }

        let counter = CounterVec::new(Opts::new(metric_name.clone(), help), labels)?;
        self.registry.register(Box::new(counter.clone()))?;
        self.collectors
            .insert(metric_name, PluginCollector::Counter(counter.clone()));
        Ok(PluginCounter(counter))
    }

    /// Registers a gauge vec metric for plugin.
    pub fn register_gauge(
        &self,
        name: &str,
        help: &str,
        labels: &[&str],
    ) -> Result<PluginGauge, MetricsError> {
        let metric_name = self.prefixed_name(name)?;
        if self.collectors.contains_key(&metric_name) {
            return Err(MetricsError::AlreadyRegistered(metric_name));
        }

        let gauge = GaugeVec::new(Opts::new(metric_name.clone(), help), labels)?;
        self.registry.register(Box::new(gauge.clone()))?;
        self.collectors
            .insert(metric_name, PluginCollector::Gauge(gauge.clone()));
        Ok(PluginGauge(gauge))
    }

    /// Registers a histogram vec metric for plugin.
    pub fn register_histogram(
        &self,
        name: &str,
        help: &str,
        labels: &[&str],
        buckets: Vec<f64>,
    ) -> Result<PluginHistogram, MetricsError> {
        let metric_name = self.prefixed_name(name)?;
        if self.collectors.contains_key(&metric_name) {
            return Err(MetricsError::AlreadyRegistered(metric_name));
        }

        let histogram_opts = HistogramOpts::new(metric_name.clone(), help).buckets(buckets);
        let histogram = HistogramVec::new(histogram_opts, labels)?;
        self.registry.register(Box::new(histogram.clone()))?;
        self.collectors
            .insert(metric_name, PluginCollector::Histogram(histogram.clone()));
        Ok(PluginHistogram(histogram))
    }

    /// Deregisters all metrics created by this plugin handle.
    pub fn deregister_all(&self) {
        let keys = self
            .collectors
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in keys {
            if let Some((_, collector)) = self.collectors.remove(&key) {
                collector.unregister(self.registry.as_ref());
            }
        }
    }

    fn prefixed_name(&self, metric_name: &str) -> Result<String, MetricsError> {
        let normalized_plugin = normalize_metric_part(self.plugin_name.as_ref());
        let normalized_metric = normalize_metric_part(metric_name);
        if normalized_plugin.is_empty() || normalized_metric.is_empty() {
            return Err(MetricsError::InvalidMetricName(metric_name.to_string()));
        }
        Ok(format!(
            "vex_plugin_{}_{}",
            normalized_plugin, normalized_metric
        ))
    }
}

#[cfg(not(feature = "metrics"))]
impl MetricsHandle {
    /// Creates metrics handle placeholder when `metrics` feature is disabled.
    pub fn new(plugin_name: impl Into<Arc<str>>) -> Self {
        Self {
            plugin_name: plugin_name.into(),
        }
    }

    /// Always returns [`MetricsError::Unavailable`].
    pub fn register_counter(
        &self,
        _name: &str,
        _help: &str,
        _labels: &[&str],
    ) -> Result<PluginCounter, MetricsError> {
        let _ = &self.plugin_name;
        Err(MetricsError::Unavailable)
    }

    /// Always returns [`MetricsError::Unavailable`].
    pub fn register_gauge(
        &self,
        _name: &str,
        _help: &str,
        _labels: &[&str],
    ) -> Result<PluginGauge, MetricsError> {
        let _ = &self.plugin_name;
        Err(MetricsError::Unavailable)
    }

    /// Always returns [`MetricsError::Unavailable`].
    pub fn register_histogram(
        &self,
        _name: &str,
        _help: &str,
        _labels: &[&str],
        _buckets: Vec<f64>,
    ) -> Result<PluginHistogram, MetricsError> {
        let _ = &self.plugin_name;
        Err(MetricsError::Unavailable)
    }

    /// No-op when `metrics` feature is disabled.
    pub fn deregister_all(&self) {}
}

#[cfg(feature = "metrics")]
fn normalize_metric_part(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

/// Counter vector wrapper for plugin metrics.
#[cfg(feature = "metrics")]
#[derive(Clone)]
pub struct PluginCounter(pub CounterVec);

/// Counter vector wrapper for plugin metrics.
#[cfg(not(feature = "metrics"))]
#[derive(Clone)]
pub struct PluginCounter;

impl PluginCounter {
    /// Increments counter for provided labels.
    pub fn inc(&self, labels: &[&str]) {
        #[cfg(feature = "metrics")]
        self.0.with_label_values(labels).inc();
        #[cfg(not(feature = "metrics"))]
        {
            let _ = labels;
        }
    }

    /// Increments counter by value for provided labels.
    pub fn inc_by(&self, labels: &[&str], v: f64) {
        #[cfg(feature = "metrics")]
        self.0.with_label_values(labels).inc_by(v);
        #[cfg(not(feature = "metrics"))]
        {
            let _ = (labels, v);
        }
    }
}

/// Gauge vector wrapper for plugin metrics.
#[cfg(feature = "metrics")]
#[derive(Clone)]
pub struct PluginGauge(pub GaugeVec);

/// Gauge vector wrapper for plugin metrics.
#[cfg(not(feature = "metrics"))]
#[derive(Clone)]
pub struct PluginGauge;

impl PluginGauge {
    /// Sets gauge value.
    pub fn set(&self, labels: &[&str], v: f64) {
        #[cfg(feature = "metrics")]
        self.0.with_label_values(labels).set(v);
        #[cfg(not(feature = "metrics"))]
        {
            let _ = (labels, v);
        }
    }

    /// Increments gauge by one.
    pub fn inc(&self, labels: &[&str]) {
        #[cfg(feature = "metrics")]
        self.0.with_label_values(labels).inc();
        #[cfg(not(feature = "metrics"))]
        {
            let _ = labels;
        }
    }

    /// Decrements gauge by one.
    pub fn dec(&self, labels: &[&str]) {
        #[cfg(feature = "metrics")]
        self.0.with_label_values(labels).dec();
        #[cfg(not(feature = "metrics"))]
        {
            let _ = labels;
        }
    }
}

/// Histogram vector wrapper for plugin metrics.
#[cfg(feature = "metrics")]
#[derive(Clone)]
pub struct PluginHistogram(pub HistogramVec);

/// Histogram vector wrapper for plugin metrics.
#[cfg(not(feature = "metrics"))]
#[derive(Clone)]
pub struct PluginHistogram;

impl PluginHistogram {
    /// Observes value for provided labels.
    pub fn observe(&self, labels: &[&str], v: f64) {
        #[cfg(feature = "metrics")]
        self.0.with_label_values(labels).observe(v);
        #[cfg(not(feature = "metrics"))]
        {
            let _ = (labels, v);
        }
    }
}

/// Plugin-scoped logger helper.
#[derive(Clone)]
pub struct PluginLogger {
    plugin_name: Arc<str>,
}

impl PluginLogger {
    /// Creates plugin logger wrapper.
    pub fn new(plugin_name: impl Into<Arc<str>>) -> Self {
        Self {
            plugin_name: plugin_name.into(),
        }
    }

    /// Logs info-level plugin message.
    pub fn info(&self, message: &str) {
        tracing::info!(plugin = self.plugin_name.as_ref(), "{message}");
    }

    /// Logs warn-level plugin message.
    pub fn warn(&self, message: &str) {
        tracing::warn!(plugin = self.plugin_name.as_ref(), "{message}");
    }

    /// Logs error-level plugin message.
    pub fn error(&self, message: &str) {
        tracing::error!(plugin = self.plugin_name.as_ref(), "{message}");
    }

    /// Logs debug-level plugin message.
    pub fn debug(&self, message: &str) {
        tracing::debug!(plugin = self.plugin_name.as_ref(), "{message}");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::{CommandRegistry, CommandSender};

    #[test]
    fn register_execute_unregister_command() {
        let registry = CommandRegistry::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen_args = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let calls_for_handler = calls.clone();
        let args_for_handler = seen_args.clone();
        registry.register("test-plugin", "hello", "says hi", move |_sender, args| {
            calls_for_handler.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut guard) = args_for_handler.lock() {
                *guard = args;
            }
        });

        let ok = registry.execute(
            "hello",
            CommandSender::Console,
            vec!["one".to_string(), "two".to_string()],
        );
        assert!(ok);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let guard = seen_args.lock().expect("lock args");
        assert_eq!(guard.as_slice(), &["one".to_string(), "two".to_string()]);

        registry.unregister("test-plugin", "hello");
        assert!(!registry.execute("hello", CommandSender::Console, vec![]));
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn register_increment_and_deregister_plugin_metrics() {
        use prometheus::Encoder;
        use prometheus::Registry;

        use super::MetricsHandle;

        let registry = Arc::new(Registry::new());
        let handle = MetricsHandle::new(registry.clone(), "hello_plugin");
        let counter = handle
            .register_counter(
                "players_greeted_total",
                "Total players greeted by plugin",
                &["source"],
            )
            .expect("register counter");
        counter.inc(&["login"]);

        let mut encoded = Vec::new();
        let encoder = prometheus::TextEncoder::new();
        encoder
            .encode(&registry.gather(), &mut encoded)
            .expect("encode metrics");
        let body = String::from_utf8(encoded).expect("metrics are utf8");
        assert!(body.contains("vex_plugin_hello_plugin_players_greeted_total"));

        handle.deregister_all();

        let mut encoded_after = Vec::new();
        encoder
            .encode(&registry.gather(), &mut encoded_after)
            .expect("encode metrics after deregister");
        let body_after = String::from_utf8(encoded_after).expect("metrics are utf8");
        assert!(!body_after.contains("vex_plugin_hello_plugin_players_greeted_total"));
    }
}
