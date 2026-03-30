#![allow(improper_ctypes_definitions)] // Plugin ABI intentionally uses Box<dyn VexPlugin> across extern boundary.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use libloading::{Library, Symbol};
use notify::{RecursiveMode, Watcher};
use prometheus::Registry;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{error, info, warn};
use vex_sdk::VexPlugin;
use vex_sdk::api::{
    CommandRegistry, EventBus, MetricsHandle, PluginApi, PluginLogger, ProxyHandle,
};
use vex_sdk::event::OnReload;

type CreatePluginFn = unsafe extern "C" fn() -> Box<dyn VexPlugin>;

#[derive(Debug, Default)]
struct ReloadPlan {
    unload: Vec<PathBuf>,
    load: Vec<PluginFile>,
    reload: Vec<PluginFile>,
}

#[derive(Debug, Clone)]
struct PluginFile {
    path: PathBuf,
    modified: SystemTime,
}

pub struct PluginHost {
    plugin_dir: PathBuf,
    events: Arc<EventBus>,
    proxy: Arc<ProxyHandle>,
    commands: Arc<CommandRegistry>,
    metrics_registry: Arc<Registry>,
    plugins: HashMap<PathBuf, LoadedPlugin>,
}

struct LoadedPlugin {
    path: PathBuf,
    modified: SystemTime,
    name: String,
    instance: Box<dyn VexPlugin>,
    metrics: Arc<MetricsHandle>,
    _lib: Library,
}

impl PluginHost {
    pub fn new(
        plugin_dir: impl Into<PathBuf>,
        events: Arc<EventBus>,
        proxy: Arc<ProxyHandle>,
        commands: Arc<CommandRegistry>,
        metrics_registry: Arc<Registry>,
    ) -> Self {
        Self {
            plugin_dir: plugin_dir.into(),
            events,
            proxy,
            commands,
            metrics_registry,
            plugins: HashMap::new(),
        }
    }

    pub fn load_all(&mut self) -> Result<usize> {
        let _ = self.reload_changed_internal()?;
        Ok(self.plugins.len())
    }

    pub async fn reload(&mut self) -> Result<usize> {
        let _changed = self.reload_changed_internal()?;
        Ok(self.plugins.len())
    }

    pub fn unload_all(&mut self) {
        let paths = self.plugins.keys().cloned().collect::<Vec<_>>();
        for path in paths {
            self.unload_plugin(&path);
        }
    }

    fn reload_changed_internal(&mut self) -> Result<bool> {
        fs::create_dir_all(&self.plugin_dir).with_context(|| {
            format!(
                "failed to create plugin directory {}",
                self.plugin_dir.display()
            )
        })?;

        let discovered = self.scan_plugin_files()?;
        let existing = self
            .plugins
            .iter()
            .map(|(path, plugin)| (path.clone(), plugin.modified))
            .collect::<HashMap<_, _>>();

        let plan = build_reload_plan(&existing, &discovered);
        let mut changed = false;

        for path in plan.unload {
            self.unload_plugin(&path);
            changed = true;
        }

        for plugin in plan.reload {
            self.unload_plugin(&plugin.path);
            std::thread::sleep(Duration::from_millis(10));
            self.load_one(&plugin.path, plugin.modified)?;
            changed = true;
        }

        for plugin in plan.load {
            self.load_one(&plugin.path, plugin.modified)?;
            changed = true;
        }

        Ok(changed)
    }

    fn scan_plugin_files(&self) -> Result<HashMap<PathBuf, SystemTime>> {
        let mut discovered = HashMap::new();
        for entry in fs::read_dir(&self.plugin_dir)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warn!(
                        plugin_dir = %self.plugin_dir.display(),
                        error = %err,
                        "failed to read plugin directory entry"
                    );
                    continue;
                }
            };
            let path = entry.path();
            if !is_dynamic_library(&path) {
                continue;
            }
            let modified = entry
                .metadata()
                .ok()
                .and_then(|meta| meta.modified().ok())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            discovered.insert(path, modified);
        }
        Ok(discovered)
    }

    fn load_one(&mut self, plugin_path: &Path, modified: SystemTime) -> Result<()> {
        let lib = unsafe {
            // SAFETY: Loading a dynamic library is inherently unsafe; the path is discovered from
            // the configured plugin directory and we keep the library handle alive for at least as
            // long as the plugin instance.
            Library::new(plugin_path)
        }
        .with_context(|| format!("failed opening plugin dylib {}", plugin_path.display()))?;

        let constructor: Symbol<CreatePluginFn> = unsafe {
            // SAFETY: Symbol type and name are part of the plugin ABI contract.
            lib.get(b"vex_plugin_create")
        }
        .with_context(|| {
            format!(
                "symbol vex_plugin_create not found in {}",
                plugin_path.display()
            )
        })?;

        let instance = unsafe {
            // SAFETY: constructor ABI is validated by symbol lookup; plugin controls implementation.
            constructor()
        };
        let name = instance.name().to_string();
        let metrics = Arc::new(MetricsHandle::new(
            self.metrics_registry.clone(),
            name.clone(),
        ));
        let api = Arc::new(PluginApi::new(
            Arc::new(self.events.with_plugin(name.clone())),
            self.proxy.clone(),
            self.commands.clone(),
            PluginLogger::new(name.clone()),
            metrics.clone(),
        ));

        let mut faulted = false;
        match catch_unwind(AssertUnwindSafe(|| instance.on_load(api))) {
            Ok(Ok(())) => {
                info!(plugin = %name, path = %plugin_path.display(), "plugin loaded");
            }
            Ok(Err(err)) => {
                warn!(plugin = %name, error = %err, "plugin on_load returned error");
                faulted = true;
            }
            Err(_) => {
                error!(plugin = %name, "plugin on_load panicked");
                faulted = true;
            }
        }

        if faulted {
            self.events.mark_plugin_faulted(&name);
        }

        self.plugins.insert(
            plugin_path.to_path_buf(),
            LoadedPlugin {
                path: plugin_path.to_path_buf(),
                modified,
                name,
                instance,
                metrics,
                _lib: lib,
            },
        );
        Ok(())
    }

    fn unload_plugin(&mut self, plugin_path: &Path) {
        let Some(plugin) = self.plugins.remove(plugin_path) else {
            return;
        };

        let unload_result = catch_unwind(AssertUnwindSafe(|| {
            plugin.instance.on_unload();
        }));
        if unload_result.is_err() {
            error!(plugin = %plugin.name, "plugin on_unload panicked");
        }

        plugin.metrics.deregister_all();
        self.events.unregister_plugin(&plugin.name);
        self.commands.unregister_plugin(&plugin.name);
        info!(plugin = %plugin.name, path = %plugin.path.display(), "plugin unloaded");
    }
}

impl Drop for PluginHost {
    fn drop(&mut self) {
        self.unload_all();
    }
}

pub fn spawn_plugin_watcher(
    plugin_dir: PathBuf,
    plugin_host: Arc<tokio::sync::Mutex<PluginHost>>,
    active_plugins: Arc<std::sync::atomic::AtomicUsize>,
    debounce: Duration,
) -> notify::Result<tokio::task::JoinHandle<()>> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<notify::Result<notify::Event>>();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = tx.send(event);
    })?;
    watcher.watch(plugin_dir.as_path(), RecursiveMode::NonRecursive)?;

    let handle = tokio::spawn(async move {
        let _watcher = watcher;
        while let Some(event) = rx.recv().await {
            if let Err(err) = event {
                warn!(error = %err, "plugin watcher error");
                continue;
            }

            if drain_debounced_events(&mut rx, debounce).await {
                let mut host = plugin_host.lock().await;
                match host.reload().await {
                    Ok(count) => {
                        let events = host.events.clone();
                        active_plugins.store(count, std::sync::atomic::Ordering::Relaxed);
                        drop(host);
                        let _ = events.dispatch(Arc::new(OnReload {})).await;
                        info!(count, "plugin watcher applied reload");
                    }
                    Err(err) => {
                        warn!(error = %format!("{err:#}"), "plugin watcher reload failed");
                    }
                }
            }
        }
    });

    Ok(handle)
}

async fn drain_debounced_events(
    rx: &mut UnboundedReceiver<notify::Result<notify::Event>>,
    debounce: Duration,
) -> bool {
    tokio::time::sleep(debounce).await;
    while rx.try_recv().is_ok() {}
    true
}

fn build_reload_plan(
    existing: &HashMap<PathBuf, SystemTime>,
    discovered: &HashMap<PathBuf, SystemTime>,
) -> ReloadPlan {
    let mut plan = ReloadPlan::default();

    let mut existing_paths = existing.keys().cloned().collect::<Vec<_>>();
    existing_paths.sort();
    for path in existing_paths {
        if !discovered.contains_key(&path) {
            plan.unload.push(path);
        }
    }

    let mut discovered_files = discovered
        .iter()
        .map(|(path, modified)| PluginFile {
            path: path.clone(),
            modified: *modified,
        })
        .collect::<Vec<_>>();
    discovered_files.sort_by(|a, b| a.path.cmp(&b.path));

    for file in discovered_files {
        match existing.get(&file.path) {
            None => plan.load.push(file),
            Some(previous_mtime) if *previous_mtime != file.modified => plan.reload.push(file),
            Some(_) => {}
        }
    }

    plan
}

fn is_dynamic_library(path: &Path) -> bool {
    match path.extension().and_then(OsStr::to_str) {
        #[cfg(target_os = "windows")]
        Some(ext) => ext.eq_ignore_ascii_case("dll"),
        #[cfg(target_os = "linux")]
        Some(ext) => ext.eq_ignore_ascii_case("so"),
        #[cfg(target_os = "macos")]
        Some(ext) => ext.eq_ignore_ascii_case("dylib"),
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        Some(_) => false,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use prometheus::Registry;
    use uuid::Uuid;
    use vex_sdk::api::{CommandRegistry, ProxyHandle, ProxyOps};
    use vex_sdk::player::ProxiedPlayer;
    use vex_sdk::server::BackendRef;

    use super::{PluginHost, build_reload_plan};

    struct EmptyProxyOps;
    impl ProxyOps for EmptyProxyOps {
        fn get_players(&self) -> Vec<ProxiedPlayer> {
            Vec::new()
        }

        fn get_player(&self, _username: &str) -> Option<ProxiedPlayer> {
            None
        }

        fn get_player_by_uuid(&self, _uuid: Uuid) -> Option<ProxiedPlayer> {
            None
        }

        fn get_backends(&self) -> Vec<BackendRef> {
            Vec::new()
        }

        fn broadcast(&self, _message: &str) {}

        fn broadcast_to(
            &self,
            _message: &str,
            _filter: &(dyn Fn(&ProxiedPlayer) -> bool + Send + Sync),
        ) {
        }

        fn online_count(&self) -> usize {
            0
        }

        fn online_count_for(&self, _backend: &BackendRef) -> usize {
            0
        }

        fn forward_plugin_message(
            &self,
            _channel: &str,
            _data: bytes::Bytes,
            _filter: &(dyn Fn(&ProxiedPlayer) -> bool + Send + Sync),
        ) {
        }
    }

    #[tokio::test]
    async fn reload_works_with_empty_plugin_directory() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let event_bus = Arc::new(vex_sdk::api::EventBus::new(Duration::from_millis(500)));
        let proxy = Arc::new(ProxyHandle::new(Arc::new(EmptyProxyOps)));
        let commands = Arc::new(CommandRegistry::new());
        let metrics_registry = Arc::new(Registry::new());
        let mut host = PluginHost::new(tmp.path(), event_bus, proxy, commands, metrics_registry);
        let loaded = host.reload().await?;
        assert_eq!(loaded, 0);
        Ok(())
    }

    #[test]
    fn reload_plan_only_marks_changed_plugin_for_reload() {
        let now = SystemTime::now();
        let newer = now + Duration::from_secs(60);
        let path_a = PathBuf::from("plugins/a.dll");
        let path_b = PathBuf::from("plugins/b.dll");

        let existing = HashMap::from([(path_a.clone(), now), (path_b.clone(), now)]);
        let discovered = HashMap::from([(path_a.clone(), newer), (path_b.clone(), now)]);

        let plan = build_reload_plan(&existing, &discovered);
        assert!(plan.unload.is_empty());
        assert!(plan.load.is_empty());
        assert_eq!(plan.reload.len(), 1);
        assert_eq!(plan.reload[0].path, path_a);
    }
}
