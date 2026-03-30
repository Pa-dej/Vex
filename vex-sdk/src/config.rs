//! Per-plugin configuration API backed by YAML.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_yaml::{Mapping, Value};

/// Errors returned by plugin config operations.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// YAML parse/serialization error.
    #[error(transparent)]
    Parse(#[from] serde_yaml::Error),
    /// Invalid dot-notation key.
    #[error("invalid key '{0}'")]
    InvalidKey(String),
}

/// Per-plugin config handle.
pub struct PluginConfig {
    plugin_name: Arc<str>,
    data_dir: PathBuf,
    config_path: PathBuf,
    data: Arc<RwLock<Value>>,
}

impl PluginConfig {
    /// Creates plugin config rooted at `plugins_dir/{plugin_name}/config.yml`.
    pub fn new(
        plugin_name: impl Into<Arc<str>>,
        plugins_dir: impl AsRef<Path>,
    ) -> Result<Self, ConfigError> {
        let plugin_name: Arc<str> = plugin_name.into();
        let data_dir = plugins_dir.as_ref().join(plugin_name.as_ref());
        let config_path = data_dir.join("config.yml");
        std::fs::create_dir_all(&data_dir)?;

        let initial = if config_path.exists() {
            let raw = std::fs::read_to_string(&config_path)?;
            serde_yaml::from_str::<Value>(&raw)?
        } else {
            Value::Mapping(Mapping::new())
        };

        Ok(Self {
            plugin_name,
            data_dir,
            config_path,
            data: Arc::new(RwLock::new(initial)),
        })
    }

    /// Returns plugin name.
    pub fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    /// Get typed value by dot-notation key: `"database.host"`.
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let segments = split_key(key).ok()?;
        let guard = self.data.read().unwrap_or_else(|e| e.into_inner());
        let node = get_node(&guard, &segments)?;
        serde_yaml::from_value(node.clone()).ok()
    }

    /// Get with default if key is missing or not deserializable.
    pub fn get_or<T: DeserializeOwned>(&self, key: &str, default: T) -> T {
        self.get(key).unwrap_or(default)
    }

    /// Set value and mark dirty (does not write to disk yet).
    pub fn set<T: Serialize>(&self, key: &str, value: T) -> Result<(), ConfigError> {
        let segments = split_key(key)?;
        let mut guard = self.data.write().unwrap_or_else(|e| e.into_inner());
        let serialized = serde_yaml::to_value(value)?;
        set_node(&mut guard, &segments, serialized)?;
        Ok(())
    }

    /// Write current config to disk (`plugins/{name}/config.yml`).
    pub fn save(&self) -> Result<(), ConfigError> {
        std::fs::create_dir_all(&self.data_dir)?;
        let guard = self.data.read().unwrap_or_else(|e| e.into_inner());
        let yaml = serde_yaml::to_string(&*guard)?;
        std::fs::write(&self.config_path, yaml)?;
        Ok(())
    }

    /// Reload from disk.
    pub fn reload(&self) -> Result<(), ConfigError> {
        if !self.config_path.exists() {
            let mut guard = self.data.write().unwrap_or_else(|e| e.into_inner());
            *guard = Value::Mapping(Mapping::new());
            return Ok(());
        }
        let raw = std::fs::read_to_string(&self.config_path)?;
        let parsed = serde_yaml::from_str::<Value>(&raw)?;
        let mut guard = self.data.write().unwrap_or_else(|e| e.into_inner());
        *guard = parsed;
        Ok(())
    }

    /// Get path to plugin data directory (`plugins/{name}/`).
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Check if config file exists.
    pub fn exists(&self) -> bool {
        self.config_path.exists()
    }

    /// Save default config from string if file does not exist.
    pub fn save_default(&self, default_yaml: &str) -> Result<(), ConfigError> {
        if self.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::write(&self.config_path, default_yaml)?;
        self.reload()?;
        Ok(())
    }
}

fn split_key(key: &str) -> Result<Vec<&str>, ConfigError> {
    if key.trim().is_empty() {
        return Err(ConfigError::InvalidKey(key.to_string()));
    }
    let mut parts = Vec::new();
    for segment in key.split('.') {
        if segment.trim().is_empty() {
            return Err(ConfigError::InvalidKey(key.to_string()));
        }
        parts.push(segment);
    }
    Ok(parts)
}

fn get_node<'a>(root: &'a Value, segments: &[&str]) -> Option<&'a Value> {
    let mut current = root;
    for segment in segments {
        let mapping = current.as_mapping()?;
        current = mapping.get(Value::String((*segment).to_string()))?;
    }
    Some(current)
}

fn set_node(root: &mut Value, segments: &[&str], value: Value) -> Result<(), ConfigError> {
    if segments.is_empty() {
        return Err(ConfigError::InvalidKey(String::new()));
    }

    if !root.is_mapping() {
        *root = Value::Mapping(Mapping::new());
    }

    let mut current = root;
    for segment in &segments[..segments.len() - 1] {
        let Some(mapping) = current.as_mapping_mut() else {
            return Err(ConfigError::InvalidKey(segments.join(".")));
        };
        let key = Value::String((*segment).to_string());
        let entry = mapping
            .entry(key)
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        if !entry.is_mapping() {
            *entry = Value::Mapping(Mapping::new());
        }
        current = entry;
    }

    let Some(mapping) = current.as_mapping_mut() else {
        return Err(ConfigError::InvalidKey(segments.join(".")));
    };
    mapping.insert(
        Value::String(segments[segments.len() - 1].to_string()),
        value,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::PluginConfig;

    #[test]
    fn save_default_creates_file_if_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = PluginConfig::new("alpha", tmp.path()).expect("config");
        assert!(!config.exists());
        config
            .save_default("greeting: hello\n")
            .expect("save default");
        assert!(config.exists());
    }

    #[test]
    fn save_default_skips_existing_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = PluginConfig::new("alpha", tmp.path()).expect("config");
        config
            .save_default("greeting: first\n")
            .expect("save default");
        config
            .save_default("greeting: second\n")
            .expect("second save default");
        let raw = fs::read_to_string(tmp.path().join("alpha").join("config.yml")).expect("read");
        assert!(raw.contains("first"));
    }

    #[test]
    fn get_returns_typed_value() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = PluginConfig::new("alpha", tmp.path()).expect("config");
        config
            .save_default("greeting: \"Welcome\"\nmax_warnings: 3\n")
            .expect("save default");
        let greeting: Option<String> = config.get("greeting");
        let warnings: Option<u32> = config.get("max_warnings");
        assert_eq!(greeting.as_deref(), Some("Welcome"));
        assert_eq!(warnings, Some(3));
    }

    #[test]
    fn get_or_returns_default_when_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = PluginConfig::new("alpha", tmp.path()).expect("config");
        let greeting: String = config.get_or("missing.greeting", "fallback".to_string());
        assert_eq!(greeting, "fallback");
    }

    #[test]
    fn set_save_reload_roundtrip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = PluginConfig::new("alpha", tmp.path()).expect("config");
        config.set("database.host", "127.0.0.1").expect("set host");
        config.set("database.port", 5432).expect("set port");
        config.save().expect("save");

        let config_reloaded = PluginConfig::new("alpha", tmp.path()).expect("reloaded config");
        let host: Option<String> = config_reloaded.get("database.host");
        let port: Option<u16> = config_reloaded.get("database.port");
        assert_eq!(host.as_deref(), Some("127.0.0.1"));
        assert_eq!(port, Some(5432));
    }

    #[test]
    fn dot_notation_resolves_nested_yaml() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = PluginConfig::new("alpha", tmp.path()).expect("config");
        config
            .save_default("database:\n  host: localhost\n")
            .expect("save default");
        let host: Option<String> = config.get("database.host");
        assert_eq!(host.as_deref(), Some("localhost"));
    }

    #[test]
    fn data_dir_returns_plugin_specific_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = PluginConfig::new("alpha", tmp.path()).expect("config");
        let expected = tmp.path().join("alpha");
        assert_eq!(config.data_dir(), expected.as_path());
    }
}
