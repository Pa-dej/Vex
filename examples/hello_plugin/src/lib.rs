#![allow(improper_ctypes_definitions)] // Plugin ABI intentionally uses Box<dyn VexPlugin> at extern boundary.

use std::error::Error;
use std::sync::Arc;

use vex_proxy_sdk::VexPlugin;
use vex_proxy_sdk::api::{CommandSender, PluginApi};
use vex_proxy_sdk::event::{
    OnAttackModeChange, OnBackendConnect, OnBackendDisconnect, OnBackendHealthChange,
    OnBackendReady, OnBackendSwitch, OnDisconnect, OnHandshake, OnPluginMessage, OnPreLogin,
    OnReload, OnStatusPing, OnTcpConnect,
};

struct HelloPlugin;

fn plugin_println(message: &str) {
    println!("[hello_plugin] {message}");
}

impl VexPlugin for HelloPlugin {
    fn name(&self) -> &'static str {
        "hello_plugin"
    }

    fn version(&self) -> &'static str {
        "3.0.0-beta"
    }

    fn on_load(&self, api: Arc<PluginApi>) -> Result<(), Box<dyn Error + Send + Sync>> {
        plugin_println("on_load called");
        api.logger.info(&format!("Hello from {}!", self.name()));

        let command_api = api.clone();
        api.commands.register(
            self.name(),
            "hello",
            "Logs hello command usage",
            move |sender, _args| match sender {
                CommandSender::Console => {
                    plugin_println("command /hello from console");
                    command_api.logger.info("Hello, Console!");
                }
                CommandSender::Player(_player) => {
                    plugin_println("command /hello from player (ignored)");
                    command_api
                        .logger
                        .info("Player greeting is temporarily disabled");
                }
            },
        );

        api.events
            .on::<OnStatusPing, _, _>(move |event| async move {
                if let Ok(mut response) = event.response.lock() {
                    response.description = format!(
                        "{} | {} online",
                        response.description, response.online_players
                    );
                }
            });

        let logger_api = api.clone();
        api.events.on::<OnAttackModeChange, _, _>(move |event| {
            let logger_api = logger_api.clone();
            async move {
                if event.active {
                    logger_api.logger.warn(&format!(
                        "Attack mode enabled cps={:.2} fail_ratio={:.3}",
                        event.cps, event.fail_ratio
                    ));
                } else {
                    logger_api.logger.info("Attack mode disabled");
                }
            }
        });

        api.events.on::<OnTcpConnect, _, _>(|_event| async move {});
        api.events.on::<OnHandshake, _, _>(|_event| async move {});
        api.events.on::<OnPreLogin, _, _>(|_event| async move {});
        api.events
            .on::<OnBackendConnect, _, _>(|_event| async move {});
        api.events
            .on::<OnBackendReady, _, _>(|_event| async move {});
        api.events
            .on::<OnBackendDisconnect, _, _>(|_event| async move {});
        api.events
            .on::<OnBackendSwitch, _, _>(|_event| async move {});
        api.events
            .on::<OnPluginMessage, _, _>(|_event| async move {});
        api.events
            .on::<OnBackendHealthChange, _, _>(|_event| async move {});
        api.events.on::<OnReload, _, _>(|_event| async move {});
        api.events.on::<OnDisconnect, _, _>(|_event| async move {});

        Ok(())
    }

    fn on_unload(&self) {}
}

#[unsafe(no_mangle)]
pub extern "C" fn vex_plugin_create() -> Box<dyn VexPlugin> {
    Box::new(HelloPlugin)
}

#[unsafe(no_mangle)]
pub static VEX_SDK_VERSION: u32 = vex_proxy_sdk::VEX_SDK_VERSION;
