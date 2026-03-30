use std::any::Any;
use std::sync::Arc;

use dashmap::DashMap;

#[derive(Clone, Default)]
pub struct PlayerMeta {
    inner: Arc<DashMap<String, Arc<dyn Any + Send + Sync>>>,
}

impl PlayerMeta {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set<T>(&self, key: &str, value: T)
    where
        T: Clone + Send + Sync + 'static,
    {
        self.inner.insert(key.to_string(), Arc::new(value));
    }

    pub fn get<T>(&self, key: &str) -> Option<T>
    where
        T: Clone + Send + Sync + 'static,
    {
        let entry = self.inner.get(key)?;
        entry.downcast_ref::<T>().cloned()
    }

    pub fn remove(&self, key: &str) {
        self.inner.remove(key);
    }

    pub fn has(&self, key: &str) -> bool {
        self.inner.contains_key(key)
    }
}

impl std::fmt::Debug for PlayerMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlayerMeta")
            .field("entries", &self.inner.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::PlayerMeta;

    #[test]
    fn set_get_remove_type_safe_values() {
        let meta = PlayerMeta::new();
        meta.set("score", 42_u32);
        meta.set("name", String::from("alex"));

        assert_eq!(meta.get::<u32>("score"), Some(42));
        assert_eq!(meta.get::<String>("name"), Some(String::from("alex")));
        assert_eq!(meta.get::<u64>("score"), None);

        meta.remove("score");
        assert!(!meta.has("score"));
    }
}
