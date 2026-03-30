#![allow(improper_ctypes_definitions)] // Plugin ABI intentionally uses Box<dyn VexPlugin> at extern boundary.

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use vex_proxy_sdk::VexPlugin;
use vex_proxy_sdk::api::{CommandSender, PluginApi};
use vex_proxy_sdk::event::{OnAttackModeChange, OnBackendKick, OnLoginSuccess};
use vex_proxy_sdk::player::TransferResult;

struct HelloPlugin;

impl VexPlugin for HelloPlugin {
    fn name(&self) -> &'static str {
        "hello_plugin"
    }

    fn version(&self) -> &'static str {
        "3.1.0"
    }

    fn on_load(&self, api: Arc<PluginApi>) -> Result<(), Box<dyn Error + Send + Sync>> {
        api.logger.info("Hello from hello_plugin!");

        api.config.save_default(
            r#"
greeting: "Welcome to Vex!"
tab_header: "§bVex Proxy"
tab_footer: "§7Have fun!"
"#,
        )?;

        let greeting: String = api.config.get_or("greeting", "Welcome to Vex!".to_string());
        let tab_header: String = api.config.get_or("tab_header", "§bVex Proxy".to_string());
        let tab_footer: String = api.config.get_or("tab_footer", "§7Have fun!".to_string());

        let greeted_counter =
            api.metrics
                .register_counter("greetings_total", "Total greeted players", &[])?;

        let periodic_proxy = api.proxy.clone();
        api.scheduler
            .run_timer(Duration::ZERO, Duration::from_secs(30), move || {
                let periodic_proxy = periodic_proxy.clone();
                Box::pin(async move {
                    periodic_proxy.broadcast(&format!(
                        "§aVex online: {} players",
                        periodic_proxy.online_count()
                    ));
                })
            });

        let greeting_scheduler = api.scheduler.clone();
        let greeting_for_login = greeting.clone();
        let tab_header_for_login = tab_header.clone();
        let tab_footer_for_login = tab_footer.clone();
        api.events.on::<OnLoginSuccess, _, _>(move |event| {
            let greeting_scheduler = greeting_scheduler.clone();
            let greeting_for_login = greeting_for_login.clone();
            let tab_header_for_login = tab_header_for_login.clone();
            let tab_footer_for_login = tab_footer_for_login.clone();
            let greeted_counter = greeted_counter.clone();
            async move {
                let player = event.player.clone();
                greeted_counter.inc(&[]);
                player.set_tab_list(&tab_header_for_login, &tab_footer_for_login);
                greeting_scheduler.run_later(Duration::from_secs(2), async move {
                    player.send_message(&format!("§a{}, {}!", greeting_for_login, player.username));
                    player.send_actionbar("§7Connected through Vex");
                });
            }
        });

        let kick_proxy = api.proxy.clone();
        api.events.on::<OnBackendKick, _, _>(move |event| {
            let kick_proxy = kick_proxy.clone();
            async move {
                let fallback = kick_proxy
                    .get_backends()
                    .into_iter()
                    .find(|backend| backend.name() != event.backend.name() && backend.is_healthy());
                let Some(fallback) = fallback else {
                    return;
                };
                let player = event.player.clone();
                let transfer_result =
                    tokio::task::spawn_blocking(move || player.transfer(fallback))
                        .await
                        .unwrap_or(TransferResult::Timeout);
                if matches!(transfer_result, TransferResult::Success) {
                    event.cancel("redirected by hello_plugin");
                }
            }
        });

        let attack_logger = api.logger.clone();
        api.events.on::<OnAttackModeChange, _, _>(move |event| {
            let attack_logger = attack_logger.clone();
            async move {
                if event.active {
                    attack_logger.warn(&format!(
                        "Attack mode active: cps={:.2} fail_ratio={:.3}",
                        event.cps, event.fail_ratio
                    ));
                } else {
                    attack_logger.info("Attack mode disabled");
                }
            }
        });

        let command_logger = api.logger.clone();
        api.commands.register(
            self.name(),
            "hello",
            "Greets command sender",
            move |sender, _args| match sender {
                CommandSender::Console => command_logger.info("Hello, Console!"),
                CommandSender::Player(player) => {
                    player.send_message("§aHello from hello_plugin!");
                }
            },
        );

        Ok(())
    }

    fn on_unload(&self) {}
}

#[unsafe(no_mangle)]
pub extern "C" fn vex_plugin_create() -> Box<dyn VexPlugin> {
    Box::new(HelloPlugin)
}
