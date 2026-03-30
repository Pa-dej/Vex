use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub name: Arc<str>,
    pub address: Arc<str>,
    pub healthy: bool,
}

impl BackendInfo {
    pub fn new(name: impl Into<Arc<str>>, address: impl Into<Arc<str>>, healthy: bool) -> Self {
        Self {
            name: name.into(),
            address: address.into(),
            healthy,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackendRef {
    inner: Arc<BackendInfo>,
}

impl BackendRef {
    pub fn new(info: BackendInfo) -> Self {
        Self {
            inner: Arc::new(info),
        }
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn address(&self) -> &str {
        &self.inner.address
    }

    pub fn is_healthy(&self) -> bool {
        self.inner.healthy
    }

    pub fn as_info(&self) -> &BackendInfo {
        &self.inner
    }
}
