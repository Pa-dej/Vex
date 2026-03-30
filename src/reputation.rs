use std::net::IpAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::config::ReputationConfig;

const NEUTRAL_SCORE: i32 = 50;
const MIN_SCORE: i32 = 0;
const MAX_SCORE: i32 = 100;
const VIOLATION_WINDOW: Duration = Duration::from_secs(60);
const PENALTY_ESCALATION_WINDOW: Duration = Duration::from_secs(60 * 60);
const CONNECTION_BLOCK_MESSAGE: &str = "Connection refused due to suspicious activity";

type ClusterNotifier = Arc<dyn Fn(IpAddr, i32) + Send + Sync>;

#[derive(Debug, Clone)]
pub struct ReputationEntry {
    pub score: i32,
    pub last_seen: Instant,
    pub consecutive_violations: u32,
    pub penalty_until: Option<Instant>,
    last_violation: Option<Instant>,
    last_penalty_at: Option<Instant>,
    penalties_in_hour: u32,
}

impl ReputationEntry {
    fn new(now: Instant) -> Self {
        Self {
            score: NEUTRAL_SCORE,
            last_seen: now,
            consecutive_violations: 0,
            penalty_until: None,
            last_violation: None,
            last_penalty_at: None,
            penalties_in_hour: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationAction {
    Allow,
    Delay {
        duration: Duration,
        tier_label: &'static str,
        warn: bool,
    },
    Block {
        duration_label: &'static str,
        newly_applied: bool,
        until: Instant,
    },
}

#[derive(Clone)]
pub struct ReputationStore {
    entries: DashMap<IpAddr, ReputationEntry>,
    config: ReputationConfig,
    cluster_notifier: Arc<RwLock<Option<ClusterNotifier>>>,
}

impl ReputationStore {
    pub fn new(config: ReputationConfig) -> Self {
        Self {
            entries: DashMap::new(),
            config,
            cluster_notifier: Arc::new(RwLock::new(None)),
        }
    }

    pub fn spawn_maintenance_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(self.config.decay_interval_secs)).await;
                self.run_decay_and_cleanup();
            }
        })
    }

    pub fn assess_connection(&self, ip: IpAddr) -> ReputationAction {
        self.assess_connection_at(ip, Instant::now())
    }

    pub fn record_successful_login(&self, ip: IpAddr) {
        self.record_successful_login_at(ip, Instant::now());
    }

    pub fn record_login_disconnect(&self, ip: IpAddr) {
        self.record_login_disconnect_at(ip, Instant::now());
    }

    pub fn record_handshake_timeout(&self, ip: IpAddr) {
        self.record_handshake_timeout_at(ip, Instant::now());
    }

    pub fn record_malformed_frame(&self, ip: IpAddr) {
        self.record_malformed_frame_at(ip, Instant::now());
    }

    pub fn record_rate_limit_hit(&self, ip: IpAddr) {
        self.record_rate_limit_hit_at(ip, Instant::now());
    }

    pub fn set_cluster_notifier(&self, notifier: ClusterNotifier) {
        if let Ok(mut guard) = self.cluster_notifier.write() {
            *guard = Some(notifier);
        }
    }

    pub fn apply_cluster_delta(&self, ip: IpAddr, delta: i32) {
        if !self.config.enabled {
            return;
        }
        let now = Instant::now();
        let mut entry = self
            .entries
            .entry(ip)
            .or_insert_with(|| ReputationEntry::new(now));
        entry.last_seen = now;
        let proposed = clamp_score(entry.score + delta);
        entry.score = crate::cluster::shared_state::take_worst_score(entry.score, proposed);
    }

    fn assess_connection_at(&self, ip: IpAddr, now: Instant) -> ReputationAction {
        if !self.config.enabled {
            return ReputationAction::Allow;
        }

        let mut entry = self
            .entries
            .entry(ip)
            .or_insert_with(|| ReputationEntry::new(now));
        entry.last_seen = now;

        if let Some(until) = entry.penalty_until {
            if until > now {
                return ReputationAction::Block {
                    duration_label: current_penalty_label(entry.penalties_in_hour),
                    newly_applied: false,
                    until,
                };
            }
            entry.penalty_until = None;
        }

        if entry.score < 10 {
            let tier = next_penalty_tier(now, &mut entry);
            let until = apply_penalty_block(now, tier, &self.config, &mut entry);
            return ReputationAction::Block {
                duration_label: penalty_tier_label(tier),
                newly_applied: true,
                until,
            };
        }

        if (25..=49).contains(&entry.score) {
            return ReputationAction::Delay {
                duration: Duration::from_millis(200),
                tier_label: "200ms",
                warn: false,
            };
        }

        if (10..=24).contains(&entry.score) {
            return ReputationAction::Delay {
                duration: Duration::from_millis(500),
                tier_label: "500ms",
                warn: true,
            };
        }

        ReputationAction::Allow
    }

    fn record_successful_login_at(&self, ip: IpAddr, now: Instant) {
        if !self.config.enabled {
            return;
        }
        let mut entry = self
            .entries
            .entry(ip)
            .or_insert_with(|| ReputationEntry::new(now));
        entry.last_seen = now;
        entry.consecutive_violations = 0;
        entry.score = clamp_score(entry.score + 5);
        self.publish_delta(ip, 5);
    }

    fn record_login_disconnect_at(&self, ip: IpAddr, now: Instant) {
        if !self.config.enabled {
            return;
        }
        self.apply_violation(ip, now, 10, false);
    }

    fn record_handshake_timeout_at(&self, ip: IpAddr, now: Instant) {
        if !self.config.enabled {
            return;
        }
        self.apply_violation(ip, now, 15, false);
    }

    fn record_malformed_frame_at(&self, ip: IpAddr, now: Instant) {
        if !self.config.enabled {
            return;
        }
        self.apply_violation(ip, now, 20, false);
    }

    fn record_rate_limit_hit_at(&self, ip: IpAddr, now: Instant) {
        if !self.config.enabled {
            return;
        }
        self.apply_violation(ip, now, 25, true);
    }

    fn apply_violation(
        &self,
        ip: IpAddr,
        now: Instant,
        base_penalty: i32,
        repeated_escalation: bool,
    ) {
        let mut entry = self
            .entries
            .entry(ip)
            .or_insert_with(|| ReputationEntry::new(now));
        entry.last_seen = now;

        let repeated = entry
            .last_violation
            .is_some_and(|last| now.saturating_duration_since(last) <= VIOLATION_WINDOW);
        if repeated {
            entry.consecutive_violations = entry.consecutive_violations.saturating_add(1);
        } else {
            entry.consecutive_violations = 1;
        }
        entry.last_violation = Some(now);

        let mut penalty = base_penalty;
        if repeated_escalation && repeated {
            penalty += 30;
        }
        entry.score = clamp_score(entry.score - penalty);

        if entry.consecutive_violations >= 3 {
            entry.score = 0;
            let _ = apply_penalty_block(now, PenaltyTier::Max, &self.config, &mut entry);
        }
        self.publish_delta(ip, -penalty);
    }

    fn run_decay_and_cleanup(&self) {
        if !self.config.enabled {
            return;
        }
        self.run_decay_and_cleanup_at(Instant::now());
    }

    fn run_decay_and_cleanup_at(&self, now: Instant) {
        let cleanup_after = Duration::from_secs(self.config.cleanup_timeout_secs);
        self.entries.retain(|_, entry| {
            if now.saturating_duration_since(entry.last_seen) > cleanup_after {
                return false;
            }

            if entry.score < NEUTRAL_SCORE {
                entry.score = clamp_score(entry.score + 2);
            } else if entry.score > NEUTRAL_SCORE {
                entry.score = clamp_score(entry.score - 2);
            }

            if entry
                .last_violation
                .is_some_and(|last| now.saturating_duration_since(last) > VIOLATION_WINDOW)
            {
                entry.consecutive_violations = 0;
            }

            true
        });
    }

    fn publish_delta(&self, ip: IpAddr, delta: i32) {
        if let Ok(guard) = self.cluster_notifier.read()
            && let Some(notifier) = guard.as_ref()
        {
            notifier(ip, delta);
        }
    }

    #[cfg(test)]
    pub fn set_score_for_test(&self, ip: IpAddr, score: i32) {
        let now = Instant::now();
        let mut entry = self
            .entries
            .entry(ip)
            .or_insert_with(|| ReputationEntry::new(now));
        entry.last_seen = now;
        entry.score = clamp_score(score);
        if entry.score >= 10 {
            entry.penalty_until = None;
        }
    }

    #[cfg(test)]
    fn score_for_test(&self, ip: IpAddr) -> i32 {
        self.entries
            .get(&ip)
            .map(|entry| entry.score)
            .unwrap_or(NEUTRAL_SCORE)
    }
}

fn clamp_score(score: i32) -> i32 {
    score.clamp(MIN_SCORE, MAX_SCORE)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PenaltyTier {
    First,
    Second,
    Max,
}

fn next_penalty_tier(now: Instant, entry: &mut ReputationEntry) -> PenaltyTier {
    if entry
        .last_penalty_at
        .is_none_or(|last| now.saturating_duration_since(last) > PENALTY_ESCALATION_WINDOW)
    {
        entry.penalties_in_hour = 1;
        return PenaltyTier::First;
    }

    entry.penalties_in_hour = entry.penalties_in_hour.saturating_add(1);
    match entry.penalties_in_hour {
        1 => PenaltyTier::First,
        2 => PenaltyTier::Second,
        _ => PenaltyTier::Max,
    }
}

fn apply_penalty_block(
    now: Instant,
    tier: PenaltyTier,
    config: &ReputationConfig,
    entry: &mut ReputationEntry,
) -> Instant {
    let duration = match tier {
        PenaltyTier::First => Duration::from_secs(config.block_duration_first_secs),
        PenaltyTier::Second => Duration::from_secs(config.block_duration_second_secs),
        PenaltyTier::Max => Duration::from_secs(config.block_duration_max_secs),
    };
    entry.last_penalty_at = Some(now);
    if matches!(tier, PenaltyTier::Max) {
        entry.penalties_in_hour = entry.penalties_in_hour.max(3);
    }
    let until = now + duration;
    entry.penalty_until = Some(until);
    until
}

fn penalty_tier_label(tier: PenaltyTier) -> &'static str {
    match tier {
        PenaltyTier::First => "30s",
        PenaltyTier::Second => "2min",
        PenaltyTier::Max => "10min",
    }
}

fn current_penalty_label(penalties_in_hour: u32) -> &'static str {
    match penalties_in_hour {
        0 | 1 => "30s",
        2 => "2min",
        _ => "10min",
    }
}

pub fn connection_block_message() -> &'static str {
    CONNECTION_BLOCK_MESSAGE
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn test_config() -> ReputationConfig {
        ReputationConfig::default()
    }

    #[test]
    fn score_clamps_within_bounds() {
        assert_eq!(clamp_score(-100), 0);
        assert_eq!(clamp_score(0), 0);
        assert_eq!(clamp_score(42), 42);
        assert_eq!(clamp_score(100), 100);
        assert_eq!(clamp_score(999), 100);
    }

    #[test]
    fn decay_moves_toward_neutral() {
        let store = ReputationStore::new(test_config());
        let ip_low = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_high = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip_neutral = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        store.set_score_for_test(ip_low, 30);
        store.set_score_for_test(ip_high, 70);
        store.set_score_for_test(ip_neutral, 50);

        store.run_decay_and_cleanup_at(Instant::now());
        assert_eq!(store.score_for_test(ip_low), 32);
        assert_eq!(store.score_for_test(ip_high), 68);
        assert_eq!(store.score_for_test(ip_neutral), 50);
    }

    #[test]
    fn three_violations_trigger_max_penalty() {
        let store = ReputationStore::new(test_config());
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let now = Instant::now();

        store.record_rate_limit_hit_at(ip, now);
        store.record_rate_limit_hit_at(ip, now + Duration::from_secs(1));
        store.record_rate_limit_hit_at(ip, now + Duration::from_secs(2));

        let action = store.assess_connection_at(ip, now + Duration::from_secs(3));
        assert!(matches!(
            action,
            ReputationAction::Block {
                duration_label: "10min",
                ..
            }
        ));
        assert_eq!(store.score_for_test(ip), 0);
    }

    #[test]
    fn delay_tiers_match_score_ranges() {
        let store = ReputationStore::new(test_config());
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

        store.set_score_for_test(ip, 80);
        assert_eq!(store.assess_connection(ip), ReputationAction::Allow);

        store.set_score_for_test(ip, 60);
        assert_eq!(store.assess_connection(ip), ReputationAction::Allow);

        store.set_score_for_test(ip, 30);
        assert!(matches!(
            store.assess_connection(ip),
            ReputationAction::Delay {
                tier_label: "200ms",
                ..
            }
        ));

        store.set_score_for_test(ip, 20);
        assert!(matches!(
            store.assess_connection(ip),
            ReputationAction::Delay {
                tier_label: "500ms",
                warn: true,
                ..
            }
        ));

        store.set_score_for_test(ip, 5);
        assert!(matches!(
            store.assess_connection(ip),
            ReputationAction::Block { .. }
        ));
    }
}
