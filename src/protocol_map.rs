use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct ProtocolMap {
    supported_ids: BTreeSet<i32>,
    version_to_id: BTreeMap<String, i32>,
}

impl ProtocolMap {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read protocol map {}", path.display()))?;
        let parsed: ProtocolMapFile = toml::from_str(&raw)
            .with_context(|| format!("failed to parse protocol map {}", path.display()))?;

        if parsed.supported_ids.is_empty() {
            bail!("protocol map has no supported_ids");
        }
        let supported_ids = parsed.supported_ids.into_iter().collect();
        Ok(Self {
            supported_ids,
            version_to_id: parsed.versions,
        })
    }

    pub fn is_supported(&self, protocol_id: i32) -> bool {
        self.supported_ids.contains(&protocol_id)
    }

    pub fn supported_compact_range(&self) -> String {
        let first = self.supported_ids.first().copied().unwrap_or_default();
        let last = self.supported_ids.last().copied().unwrap_or_default();
        format!("{first}-{last}")
    }

    pub fn max_supported_id(&self) -> i32 {
        self.supported_ids.last().copied().unwrap_or_default()
    }

    pub fn versions(&self) -> &BTreeMap<String, i32> {
        &self.version_to_id
    }
}

#[derive(Debug, Deserialize)]
struct ProtocolMapFile {
    supported_ids: Vec<i32>,
    versions: BTreeMap<String, i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_is_reported() {
        let map = ProtocolMap {
            supported_ids: [763, 764, 765].into_iter().collect(),
            version_to_id: BTreeMap::new(),
        };
        assert_eq!(map.supported_compact_range(), "763-765");
    }
}
