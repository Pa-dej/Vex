use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
struct CircuitInner {
    state: CircuitState,
    consecutive_failures: u32,
    opened_at: Option<Instant>,
    half_open_probe_in_flight: bool,
}

impl Default for CircuitInner {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            opened_at: None,
            half_open_probe_in_flight: false,
        }
    }
}

pub struct AuthCircuitBreaker {
    failure_threshold: u32,
    open_duration: Duration,
    inner: Mutex<CircuitInner>,
}

impl Default for AuthCircuitBreaker {
    fn default() -> Self {
        Self::new(3, Duration::from_secs(30))
    }
}

impl AuthCircuitBreaker {
    pub fn new(failure_threshold: u32, open_duration: Duration) -> Self {
        Self {
            failure_threshold,
            open_duration,
            inner: Mutex::new(CircuitInner::default()),
        }
    }

    pub fn allow_request(&self) -> bool {
        self.allow_request_at(Instant::now())
    }

    pub fn record_success(&self) {
        self.record_success_at(Instant::now());
    }

    pub fn record_failure(&self) {
        self.record_failure_at(Instant::now());
    }

    pub fn state(&self) -> CircuitState {
        self.state_at(Instant::now())
    }

    fn allow_request_at(&self, now: Instant) -> bool {
        let mut inner = self.inner.lock().expect("auth circuit mutex poisoned");
        match inner.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let elapsed = inner.opened_at.map(|t| now.saturating_duration_since(t));
                if elapsed.unwrap_or_default() >= self.open_duration {
                    inner.state = CircuitState::HalfOpen;
                    inner.half_open_probe_in_flight = true;
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                if inner.half_open_probe_in_flight {
                    false
                } else {
                    inner.half_open_probe_in_flight = true;
                    true
                }
            }
        }
    }

    fn record_success_at(&self, _now: Instant) {
        let mut inner = self.inner.lock().expect("auth circuit mutex poisoned");
        inner.state = CircuitState::Closed;
        inner.consecutive_failures = 0;
        inner.opened_at = None;
        inner.half_open_probe_in_flight = false;
    }

    fn record_failure_at(&self, now: Instant) {
        let mut inner = self.inner.lock().expect("auth circuit mutex poisoned");
        match inner.state {
            CircuitState::Closed => {
                inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
                if inner.consecutive_failures >= self.failure_threshold {
                    inner.state = CircuitState::Open;
                    inner.opened_at = Some(now);
                    inner.half_open_probe_in_flight = false;
                }
            }
            CircuitState::HalfOpen => {
                inner.state = CircuitState::Open;
                inner.opened_at = Some(now);
                inner.consecutive_failures = self.failure_threshold;
                inner.half_open_probe_in_flight = false;
            }
            CircuitState::Open => {
                inner.opened_at = Some(now);
                inner.half_open_probe_in_flight = false;
            }
        }
    }

    fn state_at(&self, now: Instant) -> CircuitState {
        let mut inner = self.inner.lock().expect("auth circuit mutex poisoned");
        if inner.state == CircuitState::Open {
            let elapsed = inner.opened_at.map(|t| now.saturating_duration_since(t));
            if elapsed.unwrap_or_default() >= self.open_duration {
                inner.state = CircuitState::HalfOpen;
                inner.half_open_probe_in_flight = false;
            }
        }
        inner.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_transitions_closed_open_halfopen_closed() {
        let breaker = AuthCircuitBreaker::new(3, Duration::from_secs(30));
        let now = Instant::now();

        assert_eq!(breaker.state_at(now), CircuitState::Closed);
        breaker.record_failure_at(now);
        breaker.record_failure_at(now);
        assert_eq!(breaker.state_at(now), CircuitState::Closed);
        breaker.record_failure_at(now);
        assert_eq!(breaker.state_at(now), CircuitState::Open);

        assert!(!breaker.allow_request_at(now + Duration::from_secs(5)));
        assert!(breaker.allow_request_at(now + Duration::from_secs(31)));
        assert_eq!(
            breaker.state_at(now + Duration::from_secs(31)),
            CircuitState::HalfOpen
        );
        assert!(!breaker.allow_request_at(now + Duration::from_secs(31)));

        breaker.record_success_at(now + Duration::from_secs(31));
        assert_eq!(
            breaker.state_at(now + Duration::from_secs(31)),
            CircuitState::Closed
        );
    }

    #[test]
    fn halfopen_failure_reopens_circuit() {
        let breaker = AuthCircuitBreaker::new(3, Duration::from_secs(30));
        let now = Instant::now();
        breaker.record_failure_at(now);
        breaker.record_failure_at(now);
        breaker.record_failure_at(now);
        assert_eq!(breaker.state_at(now), CircuitState::Open);

        assert!(breaker.allow_request_at(now + Duration::from_secs(31)));
        breaker.record_failure_at(now + Duration::from_secs(31));
        assert_eq!(
            breaker.state_at(now + Duration::from_secs(31)),
            CircuitState::Open
        );
        assert!(!breaker.allow_request_at(now + Duration::from_secs(32)));
    }
}
