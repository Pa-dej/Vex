//! Plugin metadata (`plugin.toml`) model.

use serde::{Deserialize, Serialize};

fn default_sdk_version() -> u32 {
    1
}

/// Parsed plugin metadata from `plugin.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginMeta {
    /// Plugin name.
    pub name: String,
    /// Plugin version.
    pub version: String,
    /// Plugin author.
    #[serde(default)]
    pub author: Option<String>,
    /// Plugin description.
    #[serde(default)]
    pub description: Option<String>,
    /// Declared Vex SDK major ABI version.
    #[serde(default = "default_sdk_version")]
    pub vex_sdk_version: u32,
    /// Soft dependencies.
    #[serde(default)]
    pub depends: Vec<String>,
}

impl PluginMeta {
    /// Parse metadata from TOML string.
    pub fn from_toml_str(input: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(input)
    }
}

#[cfg(test)]
mod tests {
    use super::PluginMeta;

    #[test]
    fn parse_valid_plugin_toml() {
        let raw = r#"
name = "my_plugin"
version = "1.0.0"
author = "Your Name"
description = "Does something cool"
vex_sdk_version = 1
depends = ["other_plugin"]
"#;
        let meta = PluginMeta::from_toml_str(raw).expect("parse");
        assert_eq!(meta.name, "my_plugin");
        assert_eq!(meta.version, "1.0.0");
        assert_eq!(meta.author.as_deref(), Some("Your Name"));
        assert_eq!(meta.description.as_deref(), Some("Does something cool"));
        assert_eq!(meta.vex_sdk_version, 1);
        assert_eq!(meta.depends, vec!["other_plugin".to_string()]);
    }

    #[test]
    fn missing_optional_fields_use_defaults() {
        let raw = r#"
name = "my_plugin"
version = "1.0.0"
"#;
        let meta = PluginMeta::from_toml_str(raw).expect("parse");
        assert_eq!(meta.name, "my_plugin");
        assert_eq!(meta.version, "1.0.0");
        assert!(meta.author.is_none());
        assert!(meta.description.is_none());
        assert_eq!(meta.vex_sdk_version, 1);
        assert!(meta.depends.is_empty());
    }

    #[test]
    fn invalid_toml_returns_error() {
        let raw = r#"
name = "my_plugin
version = "1.0.0"
"#;
        assert!(PluginMeta::from_toml_str(raw).is_err());
    }
}
