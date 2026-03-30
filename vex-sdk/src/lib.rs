//! Plugin SDK for the Vex Minecraft proxy.
//!
//! This crate provides the stable API surface that Vex plugins compile against.
//! Plugins are dynamic libraries (`cdylib`) that export `vex_plugin_create`.
//!
//! # Hello World Plugin
//!
//! ```no_run
//! use std::error::Error;
//! use std::sync::Arc;
//! use vex_proxy_sdk::prelude::*;
//!
//! struct HelloPlugin;
//!
//! impl VexPlugin for HelloPlugin {
//!     fn name(&self) -> &'static str { "hello_plugin" }
//!     fn version(&self) -> &'static str { "0.1.0" }
//!
//!     fn on_load(&self, api: Arc<PluginApi>) -> Result<(), Box<dyn Error + Send + Sync>> {
//!         api.logger.info("Hello from plugin!");
//!         let events = api.events.clone();
//!         let api_for_handler = api.clone();
//!         events.on::<OnLoginSuccess, _, _>(move |event| {
//!             let api = api_for_handler.clone();
//!             async move {
//!                 api.proxy.broadcast(&format!("{} joined!", event.player.username));
//!             }
//!         });
//!         Ok(())
//!     }
//!
//!     fn on_unload(&self) {}
//! }
//!
//! #[no_mangle]
//! pub extern "C" fn vex_plugin_create() -> Box<dyn VexPlugin> {
//!     Box::new(HelloPlugin)
//! }
//!
//! #[no_mangle]
//! pub static VEX_SDK_VERSION: u32 = vex_proxy_sdk::VEX_SDK_VERSION;
//! ```

pub mod api;
pub mod event;
pub mod message;
pub mod meta;
pub mod player;
pub mod prelude;
pub mod server;

use std::error::Error;
use std::sync::Arc;

pub use api::{
    CommandRegistry, CommandSender, EventBus, MetricsError, MetricsHandle, PluginApi,
    PluginCounter, PluginGauge, PluginHistogram, PluginLogger, ProxyHandle, ProxyOps,
};
pub use event::*;
pub use message::PluginMessage;
pub use meta::{PlayerMeta, PlayerMetaOps};
pub use player::{PlayerHooks, PlayerRef, ProxiedPlayer, TransferResult};
pub use server::{BackendInfo, BackendRef, HealthState};

/// ABI version used by the Vex proxy/plugin loader compatibility check.
#[no_mangle]
pub static VEX_SDK_VERSION: u32 = 1;

/// Entry point trait every Vex plugin implements.
///
/// The proxy calls:
/// - [`VexPlugin::on_load`] when the plugin is loaded.
/// - [`VexPlugin::on_unload`] before the plugin is unloaded/reloaded.
pub trait VexPlugin: Send + Sync + 'static {
    /// Plugin identifier.
    fn name(&self) -> &'static str;

    /// Plugin version string.
    fn version(&self) -> &'static str;

    /// Called after plugin instantiation.
    fn on_load(&self, api: Arc<PluginApi>) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Called before plugin unload.
    fn on_unload(&self);
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn prelude_reexports_compile() {
        let _bytes = Bytes::from_static(b"ok");
        let _uuid = Uuid::new_v4();
        let _ = std::mem::size_of::<Option<Arc<PluginApi>>>();
        let _ = std::mem::size_of::<TransferResult>();
    }
}
