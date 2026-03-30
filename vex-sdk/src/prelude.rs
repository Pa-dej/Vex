//! Convenient imports for plugin crates.

pub use std::error::Error;
pub use std::sync::Arc;

pub use bytes::Bytes;
pub use uuid::Uuid;

pub use crate::api::{
    CommandRegistry, CommandSender, EventBus, MetricsHandle, PluginApi, PluginCounter, PluginGauge,
    PluginHistogram, ProxyHandle,
};
pub use crate::config::{ConfigError, PluginConfig};
pub use crate::event::*;
pub use crate::message::PluginMessage;
pub use crate::meta::{PlayerMeta, PlayerMetaOps};
pub use crate::player::{ProxiedPlayer, TransferResult};
pub use crate::plugin_meta::PluginMeta;
pub use crate::scheduler::{BoxFuture, Scheduler, TaskHandle};
pub use crate::server::{
    AnyPlayerInfo, BackendInfo, BackendRef, HealthState, NodeInfo, RemotePlayerInfo,
};
pub use crate::VexPlugin;
