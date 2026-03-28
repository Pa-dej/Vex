use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;

#[derive(Clone)]
pub struct ShutdownManager {
    inner: Arc<Inner>,
}

struct Inner {
    draining: AtomicBool,
    tx: watch::Sender<Option<String>>,
}

impl ShutdownManager {
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(None);
        Self {
            inner: Arc::new(Inner {
                draining: AtomicBool::new(false),
                tx,
            }),
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<Option<String>> {
        self.inner.tx.subscribe()
    }

    pub fn is_draining(&self) -> bool {
        self.inner.draining.load(Ordering::Relaxed)
    }

    pub fn trigger(&self, message: String) -> bool {
        let transitioned = self
            .inner
            .draining
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok();
        if transitioned {
            let _ = self.inner.tx.send(Some(message));
        }
        transitioned
    }
}
