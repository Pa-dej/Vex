//! Plugin messaging types.

use std::sync::Arc;

use bytes::Bytes;

/// Plugin channel payload with zero-copy body semantics.
#[derive(Clone, Debug)]
pub struct PluginMessage {
    /// Channel name.
    pub channel: Arc<str>,
    /// Message payload.
    pub data: Bytes,
}

impl PluginMessage {
    /// Creates a new plugin message.
    pub fn new(channel: impl Into<Arc<str>>, data: Bytes) -> Self {
        Self {
            channel: channel.into(),
            data,
        }
    }
}
