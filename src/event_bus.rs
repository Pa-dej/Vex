#[allow(unused_imports)]
pub use vex_proxy_sdk::api::EventBus;

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use vex_proxy_sdk::event::{Cancellation, Event};

    use super::EventBus;

    #[derive(Default)]
    struct TestEvent {
        calls: AtomicUsize,
    }

    impl Event for TestEvent {}

    struct CancellableEvent {
        cancellation: Cancellation,
        downstream_calls: AtomicUsize,
    }

    impl Event for CancellableEvent {
        fn is_cancelled(&self) -> bool {
            self.cancellation.is_cancelled()
        }
    }

    struct PanicEvent {
        calls: AtomicUsize,
    }

    impl Event for PanicEvent {}

    #[tokio::test]
    async fn registers_and_dispatches_handler() {
        let bus = EventBus::new(Duration::from_millis(500));
        bus.on::<TestEvent, _, _>(|event| async move {
            event.calls.fetch_add(1, Ordering::Relaxed);
        });

        let event = Arc::new(TestEvent::default());
        let _ = bus.dispatch(event.clone()).await;
        assert_eq!(event.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cancelled_event_skips_downstream_handlers() {
        let bus = EventBus::new(Duration::from_millis(500));
        bus.on_priority::<CancellableEvent, _, _>(0, |event| async move {
            event.cancellation.cancel();
        });
        bus.on_priority::<CancellableEvent, _, _>(10, |event| async move {
            event.downstream_calls.fetch_add(1, Ordering::Relaxed);
        });

        let event = Arc::new(CancellableEvent {
            cancellation: Cancellation::default(),
            downstream_calls: AtomicUsize::new(0),
        });
        let _ = bus.dispatch(event.clone()).await;
        assert_eq!(event.downstream_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn panicking_handler_faults_plugin_but_others_continue() {
        let bus = EventBus::new(Duration::from_millis(500));
        let panic_bus = bus.with_plugin("panic-plugin");
        panic_bus.on::<PanicEvent, _, _>(|_event| async move {
            panic!("simulated plugin panic");
        });

        let healthy_bus = bus.with_plugin("healthy-plugin");
        healthy_bus.on::<PanicEvent, _, _>(|event| async move {
            event.calls.fetch_add(1, Ordering::Relaxed);
        });

        let event = Arc::new(PanicEvent {
            calls: AtomicUsize::new(0),
        });
        let _ = bus.dispatch(event.clone()).await;

        assert_eq!(event.calls.load(Ordering::Relaxed), 1);
        assert!(bus.is_plugin_faulted("panic-plugin"));
    }
}
