use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Result, bail};

#[derive(Clone)]
pub struct MemoryBudget {
    max_bytes: usize,
    used_bytes: Arc<AtomicUsize>,
    per_connection_cap: usize,
}

impl MemoryBudget {
    pub fn new(max_bytes: usize, per_connection_cap: usize) -> Self {
        Self {
            max_bytes,
            used_bytes: Arc::new(AtomicUsize::new(0)),
            per_connection_cap,
        }
    }

    pub fn acquire_connection(&self, initial_bytes: usize) -> Result<ConnectionMemory> {
        if initial_bytes > self.per_connection_cap {
            bail!(
                "initial buffer {} exceeds per-connection cap {}",
                initial_bytes,
                self.per_connection_cap
            );
        }
        self.claim(initial_bytes)?;
        Ok(ConnectionMemory {
            budget: self.clone(),
            held_bytes: initial_bytes,
            capacity_bytes: initial_bytes,
        })
    }

    fn claim(&self, bytes: usize) -> Result<()> {
        loop {
            let current = self.used_bytes.load(Ordering::Relaxed);
            let next = current.saturating_add(bytes);
            if next > self.max_bytes {
                bail!("memory watermark reached");
            }
            if self
                .used_bytes
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    fn release(&self, bytes: usize) {
        self.used_bytes.fetch_sub(bytes, Ordering::Relaxed);
    }
}

pub struct ConnectionMemory {
    budget: MemoryBudget,
    held_bytes: usize,
    capacity_bytes: usize,
}

impl ConnectionMemory {
    pub fn reserve_for(&mut self, wanted: usize) -> Result<()> {
        if wanted <= self.capacity_bytes {
            return Ok(());
        }
        if wanted > self.budget.per_connection_cap {
            bail!("per-connection cap exceeded");
        }

        let mut next_capacity = self.capacity_bytes.max(1);
        while next_capacity < wanted {
            next_capacity = next_capacity.saturating_mul(2);
            if next_capacity > self.budget.per_connection_cap {
                next_capacity = self.budget.per_connection_cap;
                break;
            }
        }

        if next_capacity <= self.capacity_bytes {
            return Ok(());
        }

        let delta = next_capacity - self.capacity_bytes;
        self.budget.claim(delta)?;
        self.held_bytes += delta;
        self.capacity_bytes = next_capacity;
        Ok(())
    }
}

impl Drop for ConnectionMemory {
    fn drop(&mut self) {
        self.budget.release(self.held_bytes);
    }
}
