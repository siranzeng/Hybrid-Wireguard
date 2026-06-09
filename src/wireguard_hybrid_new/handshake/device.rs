use byteorder::{ByteOrder, LittleEndian};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::collections::hash_map;
use std::collections::{HashMap, VecDeque};
use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use zerocopy::AsBytes;

use rand_core::{CryptoRng, RngCore};

use clear_on_drop::clear::Clear;

use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use super::macs;
use super::messages::{session_index, CookieReply, Initiation, Response, SessionId};
use super::messages::{TYPE_COOKIE_REPLY, TYPE_INITIATION, TYPE_RESPONSE};
use super::noise;
use super::peer::Peer;
use super::ratelimiter::RateLimiter;
use super::types::*;

use super::crypto_params::*;

const MAX_PEER_PER_DEVICE: usize = 1 << 20;

// HASH
use blake2::Blake2s;
type HMACBlake2s = hmac::Hmac<Blake2s>;

// ==========================================
// ==========================================

const TOKEN_BUCKET_CAPACITY: u32 = 10;
const TOKEN_REFILL_PER_SEC: u32 = 5;
const SLIDING_WINDOW_DURATION: Duration = Duration::from_secs(30);
const BEHAVIOR_WINDOW_DURATION: Duration = Duration::from_secs(60);
const CONSECUTIVE_FAILURE_THRESHOLD: u32 = 2;
const CPU_WARN_LOW: f32 = 0.60;
const CPU_WARN_HIGH: f32 = 0.70;
const CONN_WARN_LOW: f32 = 800.0;
const CONN_WARN_HIGH: f32 = 1000.0;
const RATE_WARN_LOW: f32 = 3.0;
const RATE_WARN_HIGH: f32 = 5.0;
const MEM_WARN_LOW: f32 = 0.70;
const MEM_WARN_HIGH: f32 = 0.85;
const FD_WARN_LOW: f32 = 0.75;
const FD_WARN_HIGH: f32 = 0.90;
const GRADIENT_THRESHOLD_MIN_CHECK: f32 = 0.30;
const RESOURCE_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
const HALF_OPEN_REAP_INTERVAL: Duration = Duration::from_secs(15);
const MALICIOUS_TIMEOUT_RATIO: f32 = 0.80;
const MALICIOUS_MIN_SAMPLES: usize = 3;
const HALF_OPEN_QUOTA_NORMAL: usize = 64;
const HALF_OPEN_QUOTA_GRADIENT: usize = 16;
const HALF_OPEN_QUOTA_HARD: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrecheckDecision {
    Allow,
    Challenge,
    Drop,
}

struct IpState {
    tokens: u32,
    last_refill: Instant,
    request_times: VecDeque<Instant>,
    success_times: VecDeque<Instant>,
    failure_times: VecDeque<Instant>,
    timeout_events: VecDeque<(Instant, bool)>,
    consecutive_failures: u32,
    half_open: usize,
    banned_until: Option<Instant>,
    last_activity: Instant,
}

impl IpState {
    fn new() -> Self {
        Self {
            tokens: TOKEN_BUCKET_CAPACITY,
            last_refill: Instant::now(),
            request_times: VecDeque::new(),
            success_times: VecDeque::new(),
            failure_times: VecDeque::new(),
            timeout_events: VecDeque::new(),
            consecutive_failures: 0,
            half_open: 0,
            banned_until: None,
            last_activity: Instant::now(),
        }
    }

    fn refill_tokens(&mut self) {
        let now = Instant::now();
        let elapsed_secs = now.duration_since(self.last_refill).as_secs() as u32;
        if elapsed_secs > 0 {
            self.tokens = (self.tokens + elapsed_secs.saturating_mul(TOKEN_REFILL_PER_SEC))
                .min(TOKEN_BUCKET_CAPACITY);
            self.last_refill = now;
        }
    }

    fn clean_windows(&mut self) {
        let now = Instant::now();
        let cutoff = now - SLIDING_WINDOW_DURATION;
        while self.request_times.front().map_or(false, |t| *t < cutoff) {
            self.request_times.pop_front();
        }
        let behavior_cutoff = now - BEHAVIOR_WINDOW_DURATION;
        while self
            .success_times
            .front()
            .map_or(false, |t| *t < behavior_cutoff)
        {
            self.success_times.pop_front();
        }
        while self
            .failure_times
            .front()
            .map_or(false, |t| *t < behavior_cutoff)
        {
            self.failure_times.pop_front();
        }
        while self
            .timeout_events
            .front()
            .map_or(false, |(t, _)| *t < behavior_cutoff)
        {
            self.timeout_events.pop_front();
        }
    }

    fn success_rate(&self) -> Option<f32> {
        let total = self.success_times.len() + self.failure_times.len();
        if total == 0 {
            None
        } else {
            Some(self.success_times.len() as f32 / total as f32)
        }
    }
}

///
///
pub struct GradientDosChecker {
    ip_states: Arc<std::sync::RwLock<HashMap<IpAddr, IpState>>>,
    global_metrics: Arc<std::sync::RwLock<SystemMetrics>>,
    metric_samples: Arc<std::sync::RwLock<VecDeque<MetricSample>>>,
    half_open_by_id: Arc<std::sync::RwLock<HashMap<u32, (IpAddr, Instant)>>>,
    last_reap: Arc<std::sync::RwLock<Instant>>,
    rollback_to_hard_thresholds: Arc<std::sync::RwLock<bool>>,
    resource_sampler: Arc<Mutex<ResourceSampler>>,
}

#[derive(Clone, Copy, Debug)]
struct SystemMetrics {
    cpu: f32,
    mem: f32,
    fd: f32,
}

#[derive(Clone, Copy, Debug)]
struct MetricSample {
    at: Instant,
    metrics: SystemMetrics,
    half_open_total: f32,
}

#[derive(Clone, Copy)]
struct CpuSnapshot {
    idle: u64,
    total: u64,
}

struct ResourceSampler {
    last_sample: Option<Instant>,
    last_cpu: Option<CpuSnapshot>,
}

impl GradientDosChecker {
    pub fn new() -> Self {
        Self {
            ip_states: Arc::new(std::sync::RwLock::new(HashMap::new())),
            global_metrics: Arc::new(std::sync::RwLock::new(SystemMetrics {
                cpu: 0.1,
                mem: 0.1,
                fd: 0.1,
            })),
            metric_samples: Arc::new(std::sync::RwLock::new(VecDeque::new())),
            half_open_by_id: Arc::new(std::sync::RwLock::new(HashMap::new())),
            last_reap: Arc::new(std::sync::RwLock::new(Instant::now())),
            rollback_to_hard_thresholds: Arc::new(std::sync::RwLock::new(false)),
            resource_sampler: Arc::new(Mutex::new(ResourceSampler {
                last_sample: None,
                last_cpu: None,
            })),
        }
    }

    fn gradient_ratio(value: f32, warn: f32, high: f32) -> f32 {
        if value >= high {
            1.0
        } else if value >= warn {
            GRADIENT_THRESHOLD_MIN_CHECK
                + (value - warn) / (high - warn) * (1.0 - GRADIENT_THRESHOLD_MIN_CHECK)
        } else {
            0.0
        }
    }

    fn timeout_for_ratio(ratio: f32) -> Duration {
        if ratio >= 1.0 {
            Duration::from_secs(5)
        } else if ratio > 0.0 {
            Duration::from_secs(15)
        } else {
            Duration::from_secs(30)
        }
    }

    fn half_open_quota_for_ratio(ratio: f32) -> usize {
        if ratio >= 1.0 {
            HALF_OPEN_QUOTA_HARD
        } else if ratio > 0.0 {
            HALF_OPEN_QUOTA_GRADIENT
        } else {
            HALF_OPEN_QUOTA_NORMAL
        }
    }

    fn prune_metric_samples(samples: &mut VecDeque<MetricSample>, now: Instant) {
        let cutoff = now - SLIDING_WINDOW_DURATION;
        while samples.front().map_or(false, |sample| sample.at < cutoff) {
            samples.pop_front();
        }
    }

    fn record_metric_sample(&self, now: Instant) {
        let metrics = *self.global_metrics.read().unwrap();
        let half_open_total = self.half_open_by_id.read().unwrap().len() as f32;
        let mut samples = self.metric_samples.write().unwrap();

        Self::prune_metric_samples(&mut samples, now);
        if samples.back().map_or(false, |sample| {
            now.duration_since(sample.at) < RESOURCE_SAMPLE_INTERVAL
        }) {
            return;
        }

        samples.push_back(MetricSample {
            at: now,
            metrics,
            half_open_total,
        });
    }

    fn sustained_resource_ratio(&self, now: Instant) -> f32 {
        let mut samples = self.metric_samples.write().unwrap();
        Self::prune_metric_samples(&mut samples, now);

        let min_span = SLIDING_WINDOW_DURATION.saturating_sub(RESOURCE_SAMPLE_INTERVAL);
        let sustained_for_full_window = samples
            .front()
            .map_or(false, |first| now.duration_since(first.at) >= min_span);
        if !sustained_for_full_window || samples.is_empty() {
            return 0.0;
        }

        let count = samples.len() as f32;
        let (cpu, mem, fd, half_open_total) =
            samples
                .iter()
                .fold((0.0, 0.0, 0.0, 0.0), |(cpu, mem, fd, half_open), sample| {
                    (
                        cpu + sample.metrics.cpu,
                        mem + sample.metrics.mem,
                        fd + sample.metrics.fd,
                        half_open + sample.half_open_total,
                    )
                });

        Self::gradient_ratio(cpu / count, CPU_WARN_LOW, CPU_WARN_HIGH)
            .max(Self::gradient_ratio(
                mem / count,
                MEM_WARN_LOW,
                MEM_WARN_HIGH,
            ))
            .max(Self::gradient_ratio(fd / count, FD_WARN_LOW, FD_WARN_HIGH))
            .max(Self::gradient_ratio(
                half_open_total / count,
                CONN_WARN_LOW,
                CONN_WARN_HIGH,
            ))
    }

    pub fn set_rollback_to_hard_thresholds(&self, enabled: bool) {
        *self.rollback_to_hard_thresholds.write().unwrap() = enabled;
    }

    fn current_global_ratio(&self, state: Option<&IpState>) -> f32 {
        let now = Instant::now();
        self.record_metric_sample(now);

        let metrics = *self.global_metrics.read().unwrap();
        let half_open_total = self.half_open_by_id.read().unwrap().len() as f32;
        let rate = state
            .map(|s| s.request_times.len() as f32 / SLIDING_WINDOW_DURATION.as_secs() as f32)
            .unwrap_or(0.0);

        if metrics.cpu >= CPU_WARN_HIGH
            || metrics.mem >= MEM_WARN_HIGH
            || metrics.fd >= FD_WARN_HIGH
            || half_open_total >= CONN_WARN_HIGH
            || rate >= RATE_WARN_HIGH
        {
            return 1.0;
        }

        if *self.rollback_to_hard_thresholds.read().unwrap() {
            return 0.0;
        }

        self.sustained_resource_ratio(now).max(Self::gradient_ratio(
            rate,
            RATE_WARN_LOW,
            RATE_WARN_HIGH,
        ))
    }

    pub fn precheck<R: RngCore + CryptoRng>(
        &self,
        src: &SocketAddr,
        has_valid_cookie: bool,
        rng: &mut R,
    ) -> PrecheckDecision {
        let src_ip = src.ip();
        let now = Instant::now();

        let mut ip_states = self.ip_states.write().unwrap();

        ip_states.retain(|_, s| now.duration_since(s.last_activity) < Duration::from_secs(300));

        let state = ip_states.entry(src_ip).or_insert_with(IpState::new);
        state.last_activity = now;

        if state.banned_until.map_or(false, |until| until > now) {
            log::warn!(
                "[DoS] {} is temporarily limited after half-open timeouts.",
                src
            );
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            return PrecheckDecision::Drop;
        }

        if !has_valid_cookie {
            state.refill_tokens();
            if state.tokens == 0 {
                log::warn!("[DoS] {} token bucket empty — drop.", src);
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                state.failure_times.push_back(now);
                return PrecheckDecision::Drop;
            }
            state.tokens = state.tokens.saturating_sub(1);
        }

        state.clean_windows();
        state.request_times.push_back(now);

        let behavior_trigger = state.consecutive_failures >= CONSECUTIVE_FAILURE_THRESHOLD
            || state.success_rate().map_or(false, |rate| {
                (state.success_times.len() + state.failure_times.len()) >= 3 && rate < 0.30
            });

        let p_challenge = self.current_global_ratio(Some(state));
        let half_open_quota = Self::half_open_quota_for_ratio(p_challenge);

        if state.half_open >= half_open_quota {
            log::warn!(
                "[DoS] {} half-open quota reached ({}/{}).",
                src,
                state.half_open,
                half_open_quota
            );
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            state.failure_times.push_back(now);
            return PrecheckDecision::Drop;
        }

        if has_valid_cookie {
            return PrecheckDecision::Allow;
        }

        if behavior_trigger {
            log::warn!("[DoS] {} behavior check requires Cookie.", src);
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            state.failure_times.push_back(now);
            return PrecheckDecision::Challenge;
        }

        if p_challenge > 0.0 {
            let rand_val: f32 = (rng.next_u32() as f32) / (u32::MAX as f32);
            if rand_val < p_challenge {
                log::info!(
                    "[DoS] Gradient challenge for {} (p={:.2})",
                    src,
                    p_challenge
                );
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                state.failure_times.push_back(now);
                return PrecheckDecision::Challenge;
            }
        }

        PrecheckDecision::Allow
    }

    pub fn record_success(&self, src_ip: IpAddr) {
        if let Ok(mut states) = self.ip_states.write() {
            if let Some(state) = states.get_mut(&src_ip) {
                let now = Instant::now();
                state.consecutive_failures = 0;
                state.success_times.push_back(now);
                state.timeout_events.push_back((now, false));
                state.clean_windows();
            }
        }
    }

    pub fn record_failure(&self, src_ip: IpAddr) {
        if let Ok(mut states) = self.ip_states.write() {
            let state = states.entry(src_ip).or_insert_with(IpState::new);
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            state.failure_times.push_back(Instant::now());
            state.clean_windows();
        }
    }

    pub fn update_global_cpu_usage(&self, usage: f32) {
        self.global_metrics.write().unwrap().cpu = usage.clamp(0.0, 1.0);
        self.record_metric_sample(Instant::now());
    }

    pub fn update_resource_usage(&self, memory: f32, fd: f32) {
        {
            let mut metrics = self.global_metrics.write().unwrap();
            metrics.mem = memory.clamp(0.0, 1.0);
            metrics.fd = fd.clamp(0.0, 1.0);
        }
        self.record_metric_sample(Instant::now());
    }

    pub fn sample_runtime_metrics(&self) {
        #[cfg(target_os = "linux")]
        {
            let now = Instant::now();
            let mut sampler = self.resource_sampler.lock().unwrap();
            if sampler.last_sample.map_or(false, |last| {
                now.duration_since(last) < RESOURCE_SAMPLE_INTERVAL
            }) {
                return;
            }
            sampler.last_sample = Some(now);

            let cpu = linux_cpu_usage(&mut sampler.last_cpu);
            let mem = linux_memory_usage();
            let fd = linux_fd_usage();
            drop(sampler);

            if cpu.is_none() && mem.is_none() && fd.is_none() {
                self.set_rollback_to_hard_thresholds(true);
                return;
            }

            {
                let mut metrics = self.global_metrics.write().unwrap();
                if let Some(cpu) = cpu {
                    metrics.cpu = cpu.clamp(0.0, 1.0);
                }
                if let Some(mem) = mem {
                    metrics.mem = mem.clamp(0.0, 1.0);
                }
                if let Some(fd) = fd {
                    metrics.fd = fd.clamp(0.0, 1.0);
                }
            }
            self.set_rollback_to_hard_thresholds(false);
            self.record_metric_sample(now);
        }
    }

    pub fn register_half_open(&self, id: u32, src_ip: IpAddr) {
        self.half_open_by_id
            .write()
            .unwrap()
            .insert(id, (src_ip, Instant::now()));
        if let Ok(mut states) = self.ip_states.write() {
            let state = states.entry(src_ip).or_insert_with(IpState::new);
            state.half_open = state.half_open.saturating_add(1);
        }
    }

    pub fn release_half_open(&self, id: u32) {
        if let Some((src_ip, _)) = self.half_open_by_id.write().unwrap().remove(&id) {
            if let Ok(mut states) = self.ip_states.write() {
                if let Some(state) = states.get_mut(&src_ip) {
                    state.half_open = state.half_open.saturating_sub(1);
                }
            }
        }
    }

    pub fn reap_expired_half_open(&self) -> Vec<u32> {
        {
            let mut last = self.last_reap.write().unwrap();
            if last.elapsed() < HALF_OPEN_REAP_INTERVAL {
                return Vec::new();
            }
            *last = Instant::now();
        }

        let ratio = self.current_global_ratio(None);
        let timeout = Self::timeout_for_ratio(ratio);
        let now = Instant::now();
        let mut expired = Vec::new();
        {
            let mut half_open = self.half_open_by_id.write().unwrap();
            half_open.retain(|id, (ip, born)| {
                let keep = now.duration_since(*born) < timeout;
                if !keep {
                    expired.push((*id, *ip));
                }
                keep
            });
        }

        let mut expired_ids = Vec::with_capacity(expired.len());
        if let Ok(mut states) = self.ip_states.write() {
            for (id, ip) in expired {
                expired_ids.push(id);
                let state = states.entry(ip).or_insert_with(IpState::new);
                state.half_open = state.half_open.saturating_sub(1);
                state.timeout_events.push_back((now, true));
                state.clean_windows();
                let total = state.timeout_events.len();
                let timed_out = state
                    .timeout_events
                    .iter()
                    .filter(|(_, timeout)| *timeout)
                    .count();
                if total >= MALICIOUS_MIN_SAMPLES
                    && (timed_out as f32 / total as f32) >= MALICIOUS_TIMEOUT_RATIO
                {
                    state.banned_until = Some(now + BEHAVIOR_WINDOW_DURATION);
                }
            }
        }
        expired_ids
    }
}

#[cfg(target_os = "linux")]
fn linux_cpu_snapshot() -> Option<CpuSnapshot> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let line = stat.lines().next()?;
    let mut fields = line.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }

    let values: Vec<u64> = fields
        .filter_map(|field| field.parse::<u64>().ok())
        .collect();
    if values.len() < 4 {
        return None;
    }

    let idle = values.get(3).copied().unwrap_or(0) + values.get(4).copied().unwrap_or(0);
    let total = values.iter().copied().sum();
    Some(CpuSnapshot { idle, total })
}

#[cfg(target_os = "linux")]
fn linux_cpu_usage(previous: &mut Option<CpuSnapshot>) -> Option<f32> {
    let current = linux_cpu_snapshot()?;
    let usage = previous.as_ref().and_then(|prev| {
        let total_delta = current.total.saturating_sub(prev.total);
        if total_delta == 0 {
            return None;
        }
        let idle_delta = current.idle.saturating_sub(prev.idle);
        Some(1.0 - idle_delta as f32 / total_delta as f32)
    });
    *previous = Some(current);
    usage
}

#[cfg(target_os = "linux")]
fn linux_memory_usage() -> Option<f32> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kb = None;
    let mut available_kb = None;

    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            total_kb = line
                .split_whitespace()
                .nth(1)
                .and_then(|value| value.parse::<f32>().ok());
        } else if line.starts_with("MemAvailable:") {
            available_kb = line
                .split_whitespace()
                .nth(1)
                .and_then(|value| value.parse::<f32>().ok());
        }
    }

    let total = total_kb?;
    let available = available_kb?;
    if total <= 0.0 {
        return None;
    }
    Some(((total - available) / total).clamp(0.0, 1.0))
}

#[cfg(target_os = "linux")]
fn linux_fd_usage() -> Option<f32> {
    let used = std::fs::read_dir("/proc/self/fd").ok()?.count() as f32;
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;

    for line in limits.lines() {
        if line.starts_with("Max open files") {
            let soft_limit = line
                .split_whitespace()
                .nth(3)
                .and_then(|value| value.parse::<f32>().ok())?;
            if soft_limit <= 0.0 {
                return None;
            }
            return Some((used / soft_limit).clamp(0.0, 1.0));
        }
    }

    None
}

fn addr_to_mac_bytes(addr: &SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(a) => {
            let mut v = Vec::with_capacity(6);
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&a.port().to_le_bytes());
            v
        }
        SocketAddr::V6(a) => {
            let mut v = Vec::with_capacity(18);
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&a.port().to_le_bytes());
            v
        }
    }
}

pub struct KeyState {
    pub(super) sk: StaticSecret,
    pub(super) pk: PublicKey,
    pub(super) sk_pq: oqs::kem::SecretKey,
    pub(super) pk_pq: oqs::kem::PublicKey,
    pub(super) pk_hash: [u8; SIZE_HASH],
    pub(super) cookie_root_secret: [u8; SIZE_HASH],
}

/// The device is generic over an "opaque" type
/// which can be used to associate the public key with this value.
pub struct Device<O> {
    keyst: Option<KeyState>,
    id_map: DashMap<u32, [u8; SIZE_HASH]>,
    id_to_sid: DashMap<u32, SessionId>,
    sid_map: DashMap<SessionId, [u8; SIZE_HASH]>,
    pk_map: HashMap<[u8; SIZE_HASH], Peer<O>>,
    limiter: Mutex<RateLimiter>,
    pub gradient_dos_checker: GradientDosChecker,
    device_validator: Option<macs::Validator>,
    ri_key: Option<[u8; 8]>,
}

pub struct Iter<'a, O> {
    iter: hash_map::Iter<'a, [u8; SIZE_HASH], Peer<O>>,
}

impl<'a, O> Iterator for Iter<'a, O> {
    type Item = (&'a [u8; SIZE_HASH], &'a O);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()
            .map(|(pk_hash, peer)| (pk_hash, &peer.opaque))
    }
}

impl<O> Device<O> {
    pub fn clear(&mut self) {
        self.id_map.clear();
        self.id_to_sid.clear();
        self.sid_map.clear();
        self.pk_map.clear();
    }

    pub fn hash_static_keys(pk: &PublicKey, pk_pq: &oqs::kem::PublicKey) -> [u8; SIZE_HASH] {
        HASH!(pk.as_bytes(), pk_pq.as_ref()).into()
    }

    pub fn len(&self) -> usize {
        self.pk_map.len()
    }

    pub fn iter(&self) -> Iter<O> {
        Iter {
            iter: self.pk_map.iter(),
        }
    }

    pub fn get(&self, pk_hash: &[u8; SIZE_HASH]) -> Option<&O> {
        self.pk_map.get(pk_hash).map(|peer| &peer.opaque)
    }

    pub fn contains_key(&self, pk_hash: &[u8; SIZE_HASH]) -> bool {
        self.pk_map.contains_key(pk_hash)
    }
}

impl<O> Device<O> {
    pub fn new() -> Device<O> {
        Device {
            keyst: None,
            id_map: DashMap::new(),
            id_to_sid: DashMap::new(),
            sid_map: DashMap::new(),
            pk_map: HashMap::new(),
            limiter: Mutex::new(RateLimiter::new()),
            gradient_dos_checker: GradientDosChecker::new(),
            device_validator: None,
            ri_key: None,
        }
    }

    fn derive_cookie_root_secret(
        sk: &StaticSecret,
        sk_pq: &oqs::kem::SecretKey,
    ) -> [u8; SIZE_HASH] {
        let mut material = Vec::with_capacity(SIZE_X25519_POINT + sk_pq.as_ref().len());
        material.extend_from_slice(&sk.to_bytes());
        material.extend_from_slice(sk_pq.as_ref());
        KDF1!(&HASH!(b"hybrid-wireguard-cookie-root-v1"), &material[..])
    }

    pub fn set_ri_key(&mut self, ri_key: Option<[u8; 8]>) {
        self.ri_key = ri_key;
    }

    pub fn get_ri_key(&self) -> Option<[u8; 8]> {
        self.ri_key
    }

    fn effective_ri_key(&self, peer: &Peer<O>) -> [u8; 8] {
        self.ri_key.unwrap_or_else(|| {
            let ratchet = peer.ratchet.lock();
            let hash = HASH!(b"hybrid-wireguard-ri-v2.3", &ratchet.k_ri);
            let mut key = [0u8; 8];
            key.copy_from_slice(&hash[..8]);
            key
        })
    }

    #[cfg(test)]
    pub(super) fn forget_remote_ratchet_for_test(
        &mut self,
        pk_hash: &[u8; SIZE_HASH],
    ) -> Result<(), ConfigError> {
        let peer = self
            .pk_map
            .get_mut(pk_hash)
            .ok_or_else(|| ConfigError::new("No such public key"))?;
        let mut ratchet = peer.ratchet.lock();
        ratchet.remote_pub = None;
        ratchet.remote_kid = None;
        Ok(())
    }

    fn update_ss(&mut self) -> (Vec<u32>, Option<[u8; SIZE_HASH]>) {
        let mut same = None;
        let mut ids = Vec::with_capacity(self.pk_map.len());
        for (pk_hash, peer) in self.pk_map.iter_mut() {
            if let Some(key) = self.keyst.as_ref() {
                if &key.pk_hash == pk_hash {
                    same = Some(pk_hash.clone());
                    peer.ss.clear()
                } else {
                    let pk = peer.pk;
                    peer.ss = *key.sk.diffie_hellman(&pk).as_bytes();
                }
            } else {
                peer.ss.clear();
            }
            if let Some(id) = peer.reset_state() {
                ids.push(id)
            }
        }
        (ids, same)
    }

    /// Update the device's static key pair.
    ///
    /// Also refreshes `device_validator` so that the device can generate
    /// CookieReplies in the gradient pre-check phase (before peer identity is known).
    /// The validator's cookie_key = HASH("cookie--", pk_hash), which matches the
    /// cookie_key of every peer's Generator that was initialised with this device's pk_hash.
    pub fn set_sk(&mut self, sk: Option<(StaticSecret, oqs::kem::SecretKey, oqs::kem::PublicKey)>) {
        self.keyst = sk.map(|sk| {
            let pk = PublicKey::from(&sk.0);
            let cookie_root_secret = Self::derive_cookie_root_secret(&sk.0, &sk.1);
            KeyState {
                pk,
                pk_hash: Device::<O>::hash_static_keys(&pk, &sk.2),
                sk: sk.0,
                sk_pq: sk.1,
                pk_pq: sk.2,
                cookie_root_secret,
            }
        });

        self.device_validator = self
            .keyst
            .as_ref()
            .map(|ks| macs::Validator::new_device(&ks.pk_hash, &ks.cookie_root_secret));

        let (ids, same) = self.update_ss();
        for id in ids {
            self.release(id)
        }
        same.map(|pk_hash| {
            self.pk_map.remove(&pk_hash);
        });
    }

    pub fn get_sk(&self) -> Option<(&StaticSecret, &oqs::kem::SecretKey, &oqs::kem::PublicKey)> {
        self.keyst
            .as_ref()
            .map(|key| (&key.sk, &key.sk_pq, &key.pk_pq))
    }

    pub fn add(
        &mut self,
        pk: &PublicKey,
        pk_pq: &oqs::kem::PublicKey,
        opaque: O,
    ) -> Result<(), ConfigError> {
        if self.pk_map.len() > MAX_PEER_PER_DEVICE {
            return Err(ConfigError::new("Too many peers for device"));
        }

        let pk_hash = Device::<O>::hash_static_keys(pk, pk_pq);
        if let Some(key) = self.keyst.as_ref() {
            if &pk_hash == &key.pk_hash {
                return Err(ConfigError::new("Public key of peer matches the device"));
            }
        }

        let keyst = self
            .keyst
            .as_ref()
            .ok_or_else(|| ConfigError::new("Device key not set"))?;

        self.pk_map.insert(
            pk_hash,
            Peer::new(
                pk.clone(),
                pk_pq.clone(),
                &keyst.pk,
                &keyst.pk_pq,
                &keyst.cookie_root_secret,
                *keyst.sk.diffie_hellman(pk).as_bytes(),
                opaque,
            ),
        );

        Ok(())
    }

    pub fn remove(&mut self, pk_hash: &[u8; SIZE_HASH]) -> Result<(), ConfigError> {
        self.pk_map
            .remove(pk_hash)
            .ok_or_else(|| ConfigError::new("Public key not in device"))?;
        self.id_map.retain(|_, v| v != pk_hash);
        self.sid_map.retain(|_, v| v != pk_hash);
        self.id_to_sid
            .retain(|id, sid| self.id_map.contains_key(id) && self.sid_map.contains_key(sid));
        Ok(())
    }

    pub fn set_psk(&mut self, pk_hash: &[u8; SIZE_HASH], psk: Psk) -> Result<(), ConfigError> {
        match self.pk_map.get_mut(pk_hash) {
            Some(mut peer) => {
                peer.set_psk(psk);
                Ok(())
            }
            _ => Err(ConfigError::new("No such public key")),
        }
    }

    pub fn get_psk(&self, pk: &[u8; SIZE_HASH]) -> Result<Psk, ConfigError> {
        match self.pk_map.get(pk) {
            Some(peer) => Ok(peer.psk),
            _ => Err(ConfigError::new("No such public key")),
        }
    }

    pub fn release(&self, id: u32) {
        self.gradient_dos_checker.release_half_open(id);
        let old = self.id_map.remove(&id);
        if let Some((_, sid)) = self.id_to_sid.remove(&id) {
            self.sid_map.remove(&sid);
        }
        assert!(old.is_some(), "released id not allocated");
    }

    pub fn begin<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        pk_hash: &[u8; SIZE_HASH],
    ) -> Result<Vec<u8>, HandshakeError> {
        match (self.keyst.as_ref(), self.pk_map.get(pk_hash)) {
            (_, None) => Err(HandshakeError::UnknownPublicKey),
            (None, _) => Err(HandshakeError::UnknownPublicKey),
            (Some(keyst), Some(peer)) => {
                let (local, local_sid) = self.allocate_session(rng, peer.pk_hash.clone());
                let mut msg = Initiation::default();

                let ri_key = self.effective_ri_key(peer);
                noise::create_initiation(rng, keyst, peer, local_sid, &ri_key, &mut msg.noise)
                    .map_err(|e| {
                        self.release(local);
                        e
                    })?;

                peer.macs
                    .lock()
                    .generate(msg.noise.as_bytes(), &mut msg.macs);

                Ok(msg.as_bytes().to_owned())
            }
        }
    }

    pub fn process<'a, R: RngCore + CryptoRng>(
        &'a self,
        rng: &mut R,
        msg: &[u8],
        src: Option<SocketAddr>,
    ) -> Result<Output<'a, O>, HandshakeError> {
        if msg.len() < 4 {
            return Err(HandshakeError::InvalidMessageFormat);
        }

        let keyst = match self.keyst.as_ref() {
            Some(key) => key,
            None => return Ok((None, None, None)),
        };

        self.gradient_dos_checker.sample_runtime_metrics();
        for id in self.gradient_dos_checker.reap_expired_half_open() {
            self.id_map.remove(&id);
            if let Some((_, sid)) = self.id_to_sid.remove(&id) {
                self.sid_map.remove(&sid);
            }
        }

        match LittleEndian::read_u32(msg) {
            TYPE_INITIATION => {
                let msg = Initiation::parse(msg)?;
                let src_for_accounting = src;

                if let Some(src_addr) = src.as_ref() {
                    let pre_check_cookie_valid =
                        self.device_validator.as_ref().map_or(false, |v| {
                            v.check_mac2(msg.noise.as_bytes(), src_addr, &msg.macs)
                        });

                    match self
                        .gradient_dos_checker
                        .precheck(src_addr, pre_check_cookie_valid, rng)
                    {
                        PrecheckDecision::Allow => {}
                        PrecheckDecision::Drop => return Ok((None, None, None)),
                        PrecheckDecision::Challenge => {
                            if let Some(validator) = &self.device_validator {
                                let mut reply = CookieReply::default();
                                validator.create_cookie_reply(
                                    rng,
                                    &msg.noise.f_sender,
                                    src_addr,
                                    &msg.macs,
                                    &mut reply,
                                );
                                log::info!(
                                    "[DoS] Pre-check challenge: sending CookieReply to {}",
                                    src_addr
                                );
                                return Ok((None, Some(reply.as_bytes().to_owned()), None));
                            }
                            return Ok((None, None, None));
                        }
                    }

                    if !pre_check_cookie_valid {
                        if let Some(validator) = &self.device_validator {
                            let mut reply = CookieReply::default();
                            validator.create_cookie_reply(
                                rng,
                                &msg.noise.f_sender,
                                src_addr,
                                &msg.macs,
                                &mut reply,
                            );
                            log::info!(
                                "[DoS] Cookie gate: challenging {} before expensive initiation processing",
                                src_addr
                            );
                            return Ok((None, Some(reply.as_bytes().to_owned()), None));
                        }
                        return Ok((None, None, None));
                    }
                }

                let (peer, pk_hash, st_intermediate) =
                    match noise::consume_initiation_first_part(self, keyst, &msg.noise) {
                        Ok(v) => v,
                        Err(e) => {
                            if let Some(src) = src_for_accounting {
                                self.gradient_dos_checker.record_failure(src.ip());
                            }
                            return Err(e);
                        }
                    };

                if let Err(e) = peer
                    .macs_validator
                    .lock()
                    .check_mac1(msg.noise.as_bytes(), &msg.macs)
                {
                    if let Some(src) = src_for_accounting {
                        self.gradient_dos_checker.record_failure(src.ip());
                    }
                    return Err(e);
                }

                if let Some(src) = src {
                    if !self.limiter.lock().unwrap().allow(&src.ip()) {
                        self.gradient_dos_checker.record_failure(src.ip());
                        return Err(HandshakeError::RateLimited);
                    }
                }

                let st = noise::consume_initiation_second_part(
                    self,
                    &msg.noise,
                    st_intermediate,
                    peer,
                    self.get_ri_key(),
                )
                .map_err(|e| {
                    if let Some(src) = src_for_accounting {
                        self.gradient_dos_checker.record_failure(src.ip());
                    }
                    e
                })?;

                let (local, local_sid) = self.allocate_session(rng, pk_hash);
                if let Some(src) = src_for_accounting {
                    self.gradient_dos_checker
                        .register_half_open(local, src.ip());
                }
                let mut resp = Response::default();

                let keys = noise::create_response(rng, peer, local_sid, st, &mut resp.noise)
                    .map_err(|e| {
                        self.release(local);
                        if let Some(src) = src_for_accounting {
                            self.gradient_dos_checker.record_failure(src.ip());
                        }
                        e
                    })?;

                if let Some(src) = src_for_accounting {
                    self.gradient_dos_checker.record_success(src.ip());
                }

                peer.macs
                    .lock()
                    .generate(resp.noise.as_bytes(), &mut resp.macs);

                Ok((
                    Some(&peer.opaque),
                    Some(resp.as_bytes().to_owned()),
                    Some(keys),
                ))
            }
            TYPE_RESPONSE => {
                let msg = Response::parse(msg)?;

                let peer = self.lookup_sid(&msg.noise.f_receiver)?;
                noise::verify_response_hash(&msg.noise)?;
                peer.macs_validator
                    .lock()
                    .check_mac1(msg.noise.as_bytes(), &msg.macs)?;

                if let Some(src) = src {
                    if !peer
                        .macs_validator
                        .lock()
                        .check_mac2(msg.noise.as_bytes(), &src, &msg.macs)
                    {
                        let mut reply = Default::default();
                        peer.macs_validator.lock().create_cookie_reply(
                            rng,
                            &msg.noise.f_sender,
                            &src,
                            &msg.macs,
                            &mut reply,
                        );
                        return Ok((None, Some(reply.as_bytes().to_owned()), None));
                    }

                    if !self.limiter.lock().unwrap().allow(&src.ip()) {
                        return Err(HandshakeError::RateLimited);
                    }
                }

                let ri_key = self.effective_ri_key(peer);
                noise::consume_response(keyst, &msg.noise, peer, &ri_key)
            }
            TYPE_COOKIE_REPLY => {
                let msg = CookieReply::parse(msg)?;

                let peer = self.lookup_sid(&msg.f_receiver)?;
                peer.macs.lock().process(&msg)?;

                Ok((None, None, None))
            }
            _ => Err(HandshakeError::InvalidMessageFormat),
        }
    }

    pub(super) fn lookup_pk(&self, pk_hash: &[u8; SIZE_HASH]) -> Result<&Peer<O>, HandshakeError> {
        self.pk_map
            .get(pk_hash)
            .ok_or(HandshakeError::UnknownPublicKey)
    }

    pub(super) fn lookup_id(&self, id: u32) -> Result<&Peer<O>, HandshakeError> {
        let hpk = self
            .id_map
            .get(&id)
            .ok_or(HandshakeError::UnknownReceiverId)?;

        match self.pk_map.get(hpk.as_bytes()) {
            Some(peer) => Ok(peer),
            _ => unreachable!(),
        }
    }

    pub(super) fn lookup_sid(&self, sid: &SessionId) -> Result<&Peer<O>, HandshakeError> {
        let hpk = self
            .sid_map
            .get(sid)
            .ok_or(HandshakeError::UnknownReceiverId)?;

        match self.pk_map.get(hpk.as_bytes()) {
            Some(peer) => Ok(peer),
            _ => unreachable!(),
        }
    }

    fn allocate_session<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        pk_hash: [u8; SIZE_HASH],
    ) -> (u32, SessionId) {
        loop {
            let mut sid = [0u8; SIZE_SESSION_ID];
            rng.fill_bytes(&mut sid);
            let id = session_index(&sid);
            if id == 0 || self.id_map.contains_key(&id) || self.sid_map.contains_key(&sid) {
                continue;
            }
            if let Entry::Vacant(entry) = self.id_map.entry(id) {
                entry.insert(pk_hash);
                self.id_to_sid.insert(id, sid);
                self.sid_map.insert(sid, pk_hash);
                return (id, sid);
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::rngs::OsRng;
    use std::collections::HashSet;

    #[derive(Default)]
    struct ZeroRng;

    impl RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for ZeroRng {}

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn unique_shared_secrets(sk_bs: [u8; SIZE_X25519_POINT], pk1_bs: [u8; SIZE_X25519_POINT], pk2_bs: [u8; SIZE_X25519_POINT]) {

            let sk = StaticSecret::from(sk_bs);
            let pk1 = PublicKey::from(pk1_bs);
            let pk2 = PublicKey::from(pk2_bs);
            assert_eq!(pk1.as_bytes(), &pk1_bs);
            assert_eq!(pk2.as_bytes(), &pk2_bs);

            let kemalg = oqs::kem::Kem::new(STATIC_KEM_ALG).unwrap();
            let (pk_pq, sk_pq) = kemalg.keypair().unwrap();
            let (pk1_pq, sk1_pq) = kemalg.keypair().unwrap();
            let (pk2_pq, sk2_pq) = kemalg.keypair().unwrap();

            let mut dev : Device<u32> = Device::new();
            dev.set_sk(Some((sk, sk_pq, pk_pq)));

            let hash1 = Device::<u32>::hash_static_keys(&pk1, &pk1_pq);

            dev.add(&pk1, &pk1_pq, 1).unwrap();
            if dev.add(&pk2, &pk2_pq, 0).is_err() {
                assert_eq!(pk1_bs, pk2_bs);
                assert_eq!(*dev.get(&hash1).unwrap(), 1);
            }

            // every shared secret is unique
            let mut ss: HashSet<[u8; 32]> = HashSet::new();
            for peer in dev.pk_map.values() {
                ss.insert(peer.ss);
            }
            assert_eq!(ss.len(), dev.len());
        }
    }

    #[test]
    fn precheck_drops_when_token_bucket_empty() {
        let checker = GradientDosChecker::new();
        let src: SocketAddr = "198.51.100.10:12345".parse().unwrap();

        for _ in 0..TOKEN_BUCKET_CAPACITY {
            assert_eq!(
                checker.precheck(&src, false, &mut OsRng),
                PrecheckDecision::Allow
            );
        }

        assert_eq!(
            checker.precheck(&src, false, &mut OsRng),
            PrecheckDecision::Drop
        );
    }

    #[test]
    fn precheck_challenges_at_cpu_hard_threshold() {
        let checker = GradientDosChecker::new();
        let src: SocketAddr = "198.51.100.11:12345".parse().unwrap();
        checker.update_global_cpu_usage(0.75);

        assert_eq!(
            checker.precheck(&src, false, &mut OsRng),
            PrecheckDecision::Challenge
        );
        assert_eq!(
            checker.precheck(&src, true, &mut OsRng),
            PrecheckDecision::Allow
        );
    }

    #[test]
    fn precheck_drops_when_half_open_quota_is_full() {
        let checker = GradientDosChecker::new();
        let src: SocketAddr = "198.51.100.12:12345".parse().unwrap();

        for id in 1..=HALF_OPEN_QUOTA_NORMAL as u32 {
            checker.register_half_open(id, src.ip());
        }

        assert_eq!(
            checker.precheck(&src, true, &mut OsRng),
            PrecheckDecision::Drop
        );
    }

    #[test]
    fn rollback_disables_warning_gradient_but_keeps_hard_thresholds() {
        let checker = GradientDosChecker::new();
        let metrics = SystemMetrics {
            cpu: 0.65,
            mem: 0.1,
            fd: 0.1,
        };
        let now = Instant::now();
        *checker.global_metrics.write().unwrap() = metrics;
        checker
            .metric_samples
            .write()
            .unwrap()
            .push_back(MetricSample {
                at: now - SLIDING_WINDOW_DURATION.saturating_sub(RESOURCE_SAMPLE_INTERVAL),
                metrics,
                half_open_total: 0.0,
            });

        let src1: SocketAddr = "198.51.100.13:12345".parse().unwrap();
        assert_eq!(
            checker.precheck(&src1, false, &mut ZeroRng),
            PrecheckDecision::Challenge
        );

        checker.set_rollback_to_hard_thresholds(true);
        let src2: SocketAddr = "198.51.100.14:12345".parse().unwrap();
        assert_eq!(
            checker.precheck(&src2, false, &mut ZeroRng),
            PrecheckDecision::Allow
        );

        checker.update_global_cpu_usage(0.75);
        let src3: SocketAddr = "198.51.100.15:12345".parse().unwrap();
        assert_eq!(
            checker.precheck(&src3, false, &mut ZeroRng),
            PrecheckDecision::Challenge
        );
    }
}
