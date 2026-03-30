use std::sync::Arc;

use bytes::Bytes;

#[derive(Clone, Debug)]
pub struct PluginMessage {
    pub channel: Arc<str>,
    pub data: Bytes,
}

impl PluginMessage {
    pub fn new(channel: impl Into<Arc<str>>, data: Bytes) -> Self {
        Self {
            channel: channel.into(),
            data,
        }
    }
}
