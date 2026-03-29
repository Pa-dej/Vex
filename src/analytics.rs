use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::AntiBotConfig;

const WINDOW_SECS: u64 = 60;
const ATTACK_MODE_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
pub struct AttackUpdate {
    pub connections_per_second: u32,
    pub unique_ips_per_minute: usize,
    pub login_fail_ratio: f64,
    pub attack_mode_active: bool,
    pub mode_changed: Option<bool>,
}

impl AttackUpdate {
    fn disabled() -> Self {
        Self {
            connections_per_second: 0,
            unique_ips_per_minute: 0,
            login_fail_ratio: 0.0,
            attack_mode_active: false,
            mode_changed: None,
        }
    }
}

#[derive(Debug)]
pub struct AttackAnalytics {
    config: AntiBotConfig,
    inner: Mutex<AnalyticsInner>,
}

impl AttackAnalytics {
    pub fn new(config: AntiBotConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(AnalyticsInner::new()),
        }
    }

    pub fn record_connection(&self, ip: IpAddr) -> AttackUpdate {
        self.record_connection_at(ip, Instant::now())
    }

    pub fn record_login_result(&self, success: bool) -> AttackUpdate {
        self.record_login_result_at(success, Instant::now())
    }

    fn record_connection_at(&self, ip: IpAddr, now: Instant) -> AttackUpdate {
        if !self.config.enabled {
            return AttackUpdate::disabled();
        }

        let mut inner = self.inner.lock().expect("attack analytics lock poisoned");
        let sec = inner.second_key(now);
        bump_counter(&mut inner.connections_per_second, sec);

        if now.saturating_duration_since(inner.unique_ips_window_start) >= Duration::from_secs(60) {
            inner.unique_ips.clear();
            inner.unique_ips_window_start = now;
        }
        inner.unique_ips.insert(ip);

        inner.evaluate(sec, now, &self.config)
    }

    fn record_login_result_at(&self, success: bool, now: Instant) -> AttackUpdate {
        if !self.config.enabled {
            return AttackUpdate::disabled();
        }

        let mut inner = self.inner.lock().expect("attack analytics lock poisoned");
        let sec = inner.second_key(now);
        bump_counter(&mut inner.login_attempts_per_second, sec);
        if !success {
            bump_counter(&mut inner.login_failures_per_second, sec);
        }

        inner.evaluate(sec, now, &self.config)
    }
}

#[derive(Debug)]
struct AnalyticsInner {
    base_instant: Instant,
    connections_per_second: VecDeque<(u64, u32)>,
    login_failures_per_second: VecDeque<(u64, u32)>,
    login_attempts_per_second: VecDeque<(u64, u32)>,
    unique_ips: HashSet<IpAddr>,
    unique_ips_window_start: Instant,
    attack_mode_active: bool,
    below_threshold_since: Option<Instant>,
}

impl AnalyticsInner {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            base_instant: now,
            connections_per_second: VecDeque::new(),
            login_failures_per_second: VecDeque::new(),
            login_attempts_per_second: VecDeque::new(),
            unique_ips: HashSet::new(),
            unique_ips_window_start: now,
            attack_mode_active: false,
            below_threshold_since: None,
        }
    }

    fn second_key(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.base_instant).as_secs()
    }

    fn evaluate(&mut self, sec: u64, now: Instant, cfg: &AntiBotConfig) -> AttackUpdate {
        prune_old(&mut self.connections_per_second, sec);
        prune_old(&mut self.login_failures_per_second, sec);
        prune_old(&mut self.login_attempts_per_second, sec);

        let cps = current_second_count(&self.connections_per_second, sec);
        let login_failures = sum_counts(&self.login_failures_per_second);
        let login_attempts = sum_counts(&self.login_attempts_per_second);
        let fail_ratio = if login_attempts == 0 {
            0.0
        } else {
            login_failures as f64 / login_attempts as f64
        };
        let unique_ips = self.unique_ips.len();

        let suspicious = cps >= cfg.attack_cps_threshold
            || fail_ratio > cfg.attack_login_fail_ratio
            || unique_ips >= cfg.attack_unique_ip_threshold;

        let mut mode_changed = None;
        if suspicious {
            self.below_threshold_since = None;
            if !self.attack_mode_active {
                self.attack_mode_active = true;
                mode_changed = Some(true);
            }
        } else if self.attack_mode_active {
            match self.below_threshold_since {
                None => {
                    self.below_threshold_since = Some(now);
                }
                Some(since) if now.saturating_duration_since(since) >= ATTACK_MODE_COOLDOWN => {
                    self.attack_mode_active = false;
                    self.below_threshold_since = None;
                    mode_changed = Some(false);
                }
                Some(_) => {}
            }
        }

        AttackUpdate {
            connections_per_second: cps,
            unique_ips_per_minute: unique_ips,
            login_fail_ratio: fail_ratio,
            attack_mode_active: self.attack_mode_active,
            mode_changed,
        }
    }
}

fn bump_counter(slots: &mut VecDeque<(u64, u32)>, second: u64) {
    match slots.back_mut() {
        Some((sec, count)) if *sec == second => {
            *count = count.saturating_add(1);
        }
        _ => slots.push_back((second, 1)),
    }
}

fn prune_old(slots: &mut VecDeque<(u64, u32)>, current_second: u64) {
    while let Some((sec, _)) = slots.front() {
        if current_second.saturating_sub(*sec) < WINDOW_SECS {
            break;
        }
        let _ = slots.pop_front();
    }
}

fn sum_counts(slots: &VecDeque<(u64, u32)>) -> u32 {
    slots
        .iter()
        .fold(0u32, |acc, (_, count)| acc.saturating_add(*count))
}

fn current_second_count(slots: &VecDeque<(u64, u32)>, current_second: u64) -> u32 {
    slots
        .back()
        .and_then(|(sec, count)| (*sec == current_second).then_some(*count))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn test_cfg() -> AntiBotConfig {
        AntiBotConfig {
            enabled: true,
            attack_cps_threshold: 3,
            attack_login_fail_ratio: 0.5,
            attack_unique_ip_threshold: 10,
        }
    }

    #[test]
    fn attack_mode_triggers_on_thresholds() {
        let analytics = AttackAnalytics::new(test_cfg());
        let base = Instant::now();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

        let first = analytics.record_connection_at(ip, base);
        assert!(!first.attack_mode_active);
        let second = analytics.record_connection_at(ip, base + Duration::from_millis(10));
        assert!(!second.attack_mode_active);
        let third = analytics.record_connection_at(ip, base + Duration::from_millis(20));
        assert!(third.attack_mode_active);
        assert_eq!(third.mode_changed, Some(true));
    }
}
