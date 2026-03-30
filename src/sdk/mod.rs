pub mod api;
pub mod event;
pub mod message;
pub mod meta;
pub mod player;
pub mod server;

use std::error::Error;
use std::sync::Arc;

pub use api::{
    CommandRegistry, CommandSender, EventBus, MetricsError, MetricsHandle, PluginApi,
    PluginCounter, PluginGauge, PluginHistogram, PluginLogger, ProxyHandle, ProxyOps,
};
pub use event::*;
pub use message::PluginMessage;
pub use meta::PlayerMeta;
pub use player::{PlayerHooks, PlayerRef, ProxiedPlayer, TransferResult};
pub use server::{BackendInfo, BackendRef};

pub trait VexPlugin: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn on_load(&self, api: Arc<PluginApi>) -> Result<(), Box<dyn Error + Send + Sync>>;
    fn on_unload(&self);
}
