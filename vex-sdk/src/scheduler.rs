//! Plugin task scheduler built on top of Tokio.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::task::{AbortHandle, JoinHandle};

/// Convenient boxed future type for scheduled callbacks.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Scheduler for a single plugin instance.
pub struct Scheduler {
    plugin_name: Arc<str>,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl Scheduler {
    /// Creates a scheduler for a plugin name.
    pub fn new(plugin_name: impl Into<Arc<str>>) -> Self {
        Self {
            plugin_name: plugin_name.into(),
            handles: Mutex::new(Vec::new()),
        }
    }

    /// Returns plugin name for this scheduler.
    pub fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    /// Run once after delay.
    pub fn run_later(
        &self,
        delay: Duration,
        task: impl Future<Output = ()> + Send + 'static,
    ) -> TaskHandle {
        let finished = Arc::new(AtomicBool::new(false));
        let finished_guard = finished.clone();
        let join = tokio::spawn(async move {
            let _finish = FinishOnDrop(finished_guard);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            task.await;
        });
        self.track(join, finished)
    }

    /// Run repeatedly every interval, starting after initial delay.
    pub fn run_timer(
        &self,
        delay: Duration,
        interval: Duration,
        task: impl Fn() -> BoxFuture<'static, ()> + Send + Sync + 'static,
    ) -> TaskHandle {
        let task = Arc::new(task);
        let finished = Arc::new(AtomicBool::new(false));
        let finished_guard = finished.clone();
        let join = tokio::spawn(async move {
            let _finish = FinishOnDrop(finished_guard);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            loop {
                (task)().await;
                if interval.is_zero() {
                    tokio::task::yield_now().await;
                } else {
                    tokio::time::sleep(interval).await;
                }
            }
        });
        self.track(join, finished)
    }

    /// Run on next proxy "tick" (next Tokio yield point).
    pub fn run_next_tick(&self, task: impl Future<Output = ()> + Send + 'static) -> TaskHandle {
        self.run_later(Duration::ZERO, task)
    }

    /// Cancel all tasks registered by this plugin.
    pub fn cancel_all(&self) {
        if let Ok(mut guard) = self.handles.lock() {
            for handle in guard.iter() {
                handle.abort();
            }
            guard.clear();
        }
    }

    fn track(&self, join: JoinHandle<()>, finished: Arc<AtomicBool>) -> TaskHandle {
        let abort_handle = Arc::new(join.abort_handle());
        if let Ok(mut guard) = self.handles.lock() {
            guard.retain(|handle| !handle.is_finished());
            guard.push(join);
        }
        TaskHandle {
            inner: abort_handle,
            finished,
        }
    }
}

/// Handle for a scheduled task.
#[derive(Clone)]
pub struct TaskHandle {
    inner: Arc<AbortHandle>,
    finished: Arc<AtomicBool>,
}

impl TaskHandle {
    /// Cancels the task.
    pub fn cancel(&self) {
        self.inner.abort();
    }

    /// Returns whether task is finished (completed or cancelled).
    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Relaxed)
    }
}

struct FinishOnDrop(Arc<AtomicBool>);

impl Drop for FinishOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::Scheduler;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn run_later_fires_after_delay() {
        let scheduler = Scheduler::new("test");
        let fired = Arc::new(AtomicBool::new(false));
        let fired_for_task = fired.clone();
        let handle = scheduler.run_later(Duration::from_secs(5), async move {
            fired_for_task.store(true, Ordering::Relaxed);
        });
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(4)).await;
        tokio::task::yield_now().await;
        assert!(!fired.load(Ordering::Relaxed));
        assert!(!handle.is_finished());

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(fired.load(Ordering::Relaxed));
        assert!(handle.is_finished());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn run_timer_fires_multiple_times() {
        let scheduler = Scheduler::new("test");
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_task = calls.clone();
        let handle =
            scheduler.run_timer(Duration::from_secs(1), Duration::from_secs(2), move || {
                let calls_for_task = calls_for_task.clone();
                Box::pin(async move {
                    calls_for_task.fetch_add(1, Ordering::Relaxed);
                })
            });
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::Relaxed), 2);

        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::Relaxed), 3);

        handle.cancel();
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn cancel_stops_future_executions() {
        let scheduler = Scheduler::new("test");
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_task = calls.clone();
        let handle =
            scheduler.run_timer(Duration::from_secs(0), Duration::from_secs(1), move || {
                let calls_for_task = calls_for_task.clone();
                Box::pin(async move {
                    calls_for_task.fetch_add(1, Ordering::Relaxed);
                })
            });
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        let before_cancel = calls.load(Ordering::Relaxed);
        assert!(before_cancel >= 2);

        handle.cancel();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::Relaxed), before_cancel);
        assert!(handle.is_finished());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn cancel_all_cancels_plugin_tasks() {
        let scheduler = Scheduler::new("test");
        let calls = Arc::new(AtomicUsize::new(0));

        let calls_a = calls.clone();
        let _a = scheduler.run_timer(Duration::from_secs(0), Duration::from_secs(1), move || {
            let calls_a = calls_a.clone();
            Box::pin(async move {
                calls_a.fetch_add(1, Ordering::Relaxed);
            })
        });
        let calls_b = calls.clone();
        let _b = scheduler.run_timer(Duration::from_secs(0), Duration::from_secs(1), move || {
            let calls_b = calls_b.clone();
            Box::pin(async move {
                calls_b.fetch_add(1, Ordering::Relaxed);
            })
        });

        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        let before = calls.load(Ordering::Relaxed);
        assert!(before > 0);

        scheduler.cancel_all();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::Relaxed), before);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn task_handle_is_finished_after_completion() {
        let scheduler = Scheduler::new("test");
        let handle = scheduler.run_next_tick(async {});
        assert!(!handle.is_finished());
        tokio::task::yield_now().await;
        assert!(handle.is_finished());
    }
}
