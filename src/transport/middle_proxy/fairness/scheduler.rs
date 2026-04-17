use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::model::{
    AdmissionDecision, DispatchAction, DispatchCandidate, DispatchFeedback, FlowFairnessState,
    FlowPressureClass, FlowSchedulerState, PressureState, QueuedFrame, SchedulerDecision,
    StandingQueueState,
};
use super::pressure::{PressureConfig, PressureEvaluator, PressureSignals};

#[derive(Debug, Clone)]
pub(crate) struct WorkerFairnessConfig {
    pub(crate) worker_id: u16,
    pub(crate) max_active_flows: usize,
    pub(crate) max_total_queued_bytes: u64,
    pub(crate) max_flow_queued_bytes: u64,
    pub(crate) base_quantum_bytes: u32,
    pub(crate) pressured_quantum_bytes: u32,
    pub(crate) penalized_quantum_bytes: u32,
    pub(crate) standing_queue_min_age: Duration,
    pub(crate) standing_queue_min_backlog_bytes: u64,
    pub(crate) standing_stall_threshold: u8,
    pub(crate) max_consecutive_stalls_before_shed: u8,
    pub(crate) max_consecutive_stalls_before_close: u8,
    pub(crate) soft_bucket_count: usize,
    pub(crate) soft_bucket_share_pct: u8,
    pub(crate) pressure: PressureConfig,
}

impl Default for WorkerFairnessConfig {
    fn default() -> Self {
        Self {
            worker_id: 0,
            max_active_flows: 4096,
            max_total_queued_bytes: 16 * 1024 * 1024,
            max_flow_queued_bytes: 512 * 1024,
            base_quantum_bytes: 32 * 1024,
            pressured_quantum_bytes: 16 * 1024,
            penalized_quantum_bytes: 8 * 1024,
            standing_queue_min_age: Duration::from_millis(250),
            standing_queue_min_backlog_bytes: 64 * 1024,
            standing_stall_threshold: 3,
            max_consecutive_stalls_before_shed: 4,
            max_consecutive_stalls_before_close: 16,
            soft_bucket_count: 64,
            soft_bucket_share_pct: 25,
            pressure: PressureConfig::default(),
        }
    }
}

struct FlowEntry {
    fairness: FlowFairnessState,
    queue: VecDeque<QueuedFrame>,
}

impl FlowEntry {
    fn new(flow_id: u64, worker_id: u16, bucket_id: usize) -> Self {
        Self {
            fairness: FlowFairnessState::new(flow_id, worker_id, bucket_id),
            queue: VecDeque::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WorkerFairnessSnapshot {
    pub(crate) pressure_state: PressureState,
    pub(crate) active_flows: usize,
    pub(crate) total_queued_bytes: u64,
    pub(crate) standing_flows: usize,
    pub(crate) backpressured_flows: usize,
    pub(crate) scheduler_rounds: u64,
    pub(crate) deficit_grants: u64,
    pub(crate) deficit_skips: u64,
    pub(crate) enqueue_rejects: u64,
    pub(crate) shed_drops: u64,
    pub(crate) fairness_penalties: u64,
    pub(crate) downstream_stalls: u64,
}

pub(crate) struct WorkerFairnessState {
    config: WorkerFairnessConfig,
    pressure: PressureEvaluator,
    flows: HashMap<u64, FlowEntry>,
    active_ring: VecDeque<u64>,
    total_queued_bytes: u64,
    bucket_queued_bytes: Vec<u64>,
    bucket_active_flows: Vec<usize>,
    standing_flow_count: usize,
    backpressured_flow_count: usize,
    scheduler_rounds: u64,
    deficit_grants: u64,
    deficit_skips: u64,
    enqueue_rejects: u64,
    shed_drops: u64,
    fairness_penalties: u64,
    downstream_stalls: u64,
}

impl WorkerFairnessState {
    pub(crate) fn new(config: WorkerFairnessConfig, now: Instant) -> Self {
        let bucket_count = config.soft_bucket_count.max(1);
        Self {
            config,
            pressure: PressureEvaluator::new(now),
            flows: HashMap::new(),
            active_ring: VecDeque::new(),
            total_queued_bytes: 0,
            bucket_queued_bytes: vec![0; bucket_count],
            bucket_active_flows: vec![0; bucket_count],
            standing_flow_count: 0,
            backpressured_flow_count: 0,
            scheduler_rounds: 0,
            deficit_grants: 0,
            deficit_skips: 0,
            enqueue_rejects: 0,
            shed_drops: 0,
            fairness_penalties: 0,
            downstream_stalls: 0,
        }
    }

    pub(crate) fn pressure_state(&self) -> PressureState {
        self.pressure.state()
    }

    pub(crate) fn snapshot(&self) -> WorkerFairnessSnapshot {
        WorkerFairnessSnapshot {
            pressure_state: self.pressure.state(),
            active_flows: self.flows.len(),
            total_queued_bytes: self.total_queued_bytes,
            standing_flows: self.standing_flow_count,
            backpressured_flows: self.backpressured_flow_count,
            scheduler_rounds: self.scheduler_rounds,
            deficit_grants: self.deficit_grants,
            deficit_skips: self.deficit_skips,
            enqueue_rejects: self.enqueue_rejects,
            shed_drops: self.shed_drops,
            fairness_penalties: self.fairness_penalties,
            downstream_stalls: self.downstream_stalls,
        }
    }

    pub(crate) fn enqueue_data(
        &mut self,
        conn_id: u64,
        flags: u32,
        data: Bytes,
        now: Instant,
    ) -> AdmissionDecision {
        let frame = QueuedFrame {
            conn_id,
            flags,
            data,
            enqueued_at: now,
        };
        let frame_bytes = frame.queued_bytes();

        if self.pressure.state() == PressureState::Saturated {
            self.pressure
                .note_admission_reject(now, &self.config.pressure);
            self.enqueue_rejects = self.enqueue_rejects.saturating_add(1);
            return AdmissionDecision::RejectSaturated;
        }

        if self.total_queued_bytes.saturating_add(frame_bytes) > self.config.max_total_queued_bytes
        {
            self.pressure
                .note_admission_reject(now, &self.config.pressure);
            self.enqueue_rejects = self.enqueue_rejects.saturating_add(1);
            self.evaluate_pressure(now, true);
            return AdmissionDecision::RejectWorkerCap;
        }

        if !self.flows.contains_key(&conn_id) && self.flows.len() >= self.config.max_active_flows {
            self.pressure
                .note_admission_reject(now, &self.config.pressure);
            self.enqueue_rejects = self.enqueue_rejects.saturating_add(1);
            self.evaluate_pressure(now, true);
            return AdmissionDecision::RejectWorkerCap;
        }

        let bucket_id = self.bucket_for(conn_id);
        let bucket_cap = self
            .config
            .max_total_queued_bytes
            .saturating_mul(self.config.soft_bucket_share_pct.max(1) as u64)
            .saturating_div(100)
            .max(self.config.max_flow_queued_bytes);
        if self.bucket_queued_bytes[bucket_id].saturating_add(frame_bytes) > bucket_cap {
            self.pressure
                .note_admission_reject(now, &self.config.pressure);
            self.enqueue_rejects = self.enqueue_rejects.saturating_add(1);
            self.evaluate_pressure(now, true);
            return AdmissionDecision::RejectBucketCap;
        }

        let entry = if let Some(flow) = self.flows.get_mut(&conn_id) {
            flow
        } else {
            self.bucket_active_flows[bucket_id] =
                self.bucket_active_flows[bucket_id].saturating_add(1);
            self.flows.insert(
                conn_id,
                FlowEntry::new(conn_id, self.config.worker_id, bucket_id),
            );
            self.flows
                .get_mut(&conn_id)
                .expect("flow inserted must be retrievable")
        };

        if entry.fairness.pending_bytes.saturating_add(frame_bytes)
            > self.config.max_flow_queued_bytes
        {
            self.pressure
                .note_admission_reject(now, &self.config.pressure);
            self.enqueue_rejects = self.enqueue_rejects.saturating_add(1);
            self.evaluate_pressure(now, true);
            return AdmissionDecision::RejectFlowCap;
        }

        if self.pressure.state() >= PressureState::Shedding
            && entry.fairness.standing_state == StandingQueueState::Standing
        {
            self.pressure
                .note_admission_reject(now, &self.config.pressure);
            self.enqueue_rejects = self.enqueue_rejects.saturating_add(1);
            self.evaluate_pressure(now, true);
            return AdmissionDecision::RejectStandingFlow;
        }

        entry.fairness.pending_bytes = entry.fairness.pending_bytes.saturating_add(frame_bytes);
        if entry.fairness.queue_started_at.is_none() {
            entry.fairness.queue_started_at = Some(now);
        }
        entry.queue.push_back(frame);

        self.total_queued_bytes = self.total_queued_bytes.saturating_add(frame_bytes);
        self.bucket_queued_bytes[bucket_id] =
            self.bucket_queued_bytes[bucket_id].saturating_add(frame_bytes);

        if !entry.fairness.in_active_ring {
            entry.fairness.in_active_ring = true;
            self.active_ring.push_back(conn_id);
        }

        self.evaluate_pressure(now, true);
        AdmissionDecision::Admit
    }

    pub(crate) fn next_decision(&mut self, now: Instant) -> SchedulerDecision {
        self.scheduler_rounds = self.scheduler_rounds.saturating_add(1);
        self.evaluate_pressure(now, false);

        let active_len = self.active_ring.len();
        for _ in 0..active_len {
            let Some(conn_id) = self.active_ring.pop_front() else {
                break;
            };

            let mut candidate = None;
            let mut requeue_active = false;
            let mut drained_bytes = 0u64;
            let mut bucket_id = 0usize;
            let pressure_state = self.pressure.state();

            if let Some(flow) = self.flows.get_mut(&conn_id) {
                bucket_id = flow.fairness.bucket_id;

                if flow.queue.is_empty() {
                    flow.fairness.in_active_ring = false;
                    flow.fairness.scheduler_state = FlowSchedulerState::Idle;
                    flow.fairness.pending_bytes = 0;
                    flow.fairness.queue_started_at = None;
                    continue;
                }

                Self::classify_flow(&self.config, pressure_state, now, &mut flow.fairness);

                let quantum =
                    Self::effective_quantum_bytes(&self.config, pressure_state, &flow.fairness);
                flow.fairness.deficit_bytes = flow
                    .fairness
                    .deficit_bytes
                    .saturating_add(i64::from(quantum));
                self.deficit_grants = self.deficit_grants.saturating_add(1);

                let front_len = flow.queue.front().map_or(0, |front| front.queued_bytes());
                if flow.fairness.deficit_bytes < front_len as i64 {
                    flow.fairness.consecutive_skips =
                        flow.fairness.consecutive_skips.saturating_add(1);
                    self.deficit_skips = self.deficit_skips.saturating_add(1);
                    requeue_active = true;
                } else if let Some(frame) = flow.queue.pop_front() {
                    drained_bytes = frame.queued_bytes();
                    flow.fairness.pending_bytes =
                        flow.fairness.pending_bytes.saturating_sub(drained_bytes);
                    flow.fairness.deficit_bytes = flow
                        .fairness
                        .deficit_bytes
                        .saturating_sub(drained_bytes as i64);
                    flow.fairness.consecutive_skips = 0;
                    flow.fairness.queue_started_at =
                        flow.queue.front().map(|front| front.enqueued_at);
                    requeue_active = !flow.queue.is_empty();
                    if !requeue_active {
                        flow.fairness.scheduler_state = FlowSchedulerState::Idle;
                        flow.fairness.in_active_ring = false;
                    }
                    candidate = Some(DispatchCandidate {
                        pressure_state,
                        flow_class: flow.fairness.pressure_class,
                        frame,
                    });
                }
            }

            if drained_bytes > 0 {
                self.total_queued_bytes = self.total_queued_bytes.saturating_sub(drained_bytes);
                self.bucket_queued_bytes[bucket_id] =
                    self.bucket_queued_bytes[bucket_id].saturating_sub(drained_bytes);
            }

            if requeue_active {
                if let Some(flow) = self.flows.get_mut(&conn_id) {
                    flow.fairness.in_active_ring = true;
                }
                self.active_ring.push_back(conn_id);
            }

            if let Some(candidate) = candidate {
                return SchedulerDecision::Dispatch(candidate);
            }
        }

        SchedulerDecision::Idle
    }

    pub(crate) fn apply_dispatch_feedback(
        &mut self,
        conn_id: u64,
        candidate: DispatchCandidate,
        feedback: DispatchFeedback,
        now: Instant,
    ) -> DispatchAction {
        match feedback {
            DispatchFeedback::Routed => {
                if let Some(flow) = self.flows.get_mut(&conn_id) {
                    flow.fairness.last_drain_at = Some(now);
                    flow.fairness.recent_drain_bytes = flow
                        .fairness
                        .recent_drain_bytes
                        .saturating_add(candidate.frame.queued_bytes());
                    flow.fairness.consecutive_stalls = 0;
                    if flow.fairness.scheduler_state != FlowSchedulerState::Idle {
                        flow.fairness.scheduler_state = FlowSchedulerState::Active;
                    }
                }
                self.evaluate_pressure(now, false);
                DispatchAction::Continue
            }
            DispatchFeedback::QueueFull => {
                self.pressure.note_route_stall(now, &self.config.pressure);
                self.downstream_stalls = self.downstream_stalls.saturating_add(1);
                let Some(flow) = self.flows.get_mut(&conn_id) else {
                    self.evaluate_pressure(now, true);
                    return DispatchAction::Continue;
                };

                flow.fairness.consecutive_stalls =
                    flow.fairness.consecutive_stalls.saturating_add(1);
                flow.fairness.scheduler_state = FlowSchedulerState::Backpressured;
                flow.fairness.pressure_class = FlowPressureClass::Backpressured;

                let state = self.pressure.state();
                let should_shed_frame = matches!(state, PressureState::Saturated)
                    || (matches!(state, PressureState::Shedding)
                        && flow.fairness.standing_state == StandingQueueState::Standing
                        && flow.fairness.consecutive_stalls
                            >= self.config.max_consecutive_stalls_before_shed);

                if should_shed_frame {
                    self.shed_drops = self.shed_drops.saturating_add(1);
                    self.fairness_penalties = self.fairness_penalties.saturating_add(1);
                } else {
                    let frame_bytes = candidate.frame.queued_bytes();
                    flow.queue.push_front(candidate.frame);
                    flow.fairness.pending_bytes =
                        flow.fairness.pending_bytes.saturating_add(frame_bytes);
                    flow.fairness.queue_started_at =
                        flow.queue.front().map(|front| front.enqueued_at);
                    self.total_queued_bytes = self.total_queued_bytes.saturating_add(frame_bytes);
                    self.bucket_queued_bytes[flow.fairness.bucket_id] = self.bucket_queued_bytes
                        [flow.fairness.bucket_id]
                        .saturating_add(frame_bytes);
                    if !flow.fairness.in_active_ring {
                        flow.fairness.in_active_ring = true;
                        self.active_ring.push_back(conn_id);
                    }
                }

                if flow.fairness.consecutive_stalls
                    >= self.config.max_consecutive_stalls_before_close
                    && self.pressure.state() == PressureState::Saturated
                {
                    self.remove_flow(conn_id);
                    self.evaluate_pressure(now, true);
                    return DispatchAction::CloseFlow;
                }

                self.evaluate_pressure(now, true);
                DispatchAction::Continue
            }
            DispatchFeedback::ChannelClosed | DispatchFeedback::NoConn => {
                self.remove_flow(conn_id);
                self.evaluate_pressure(now, true);
                DispatchAction::CloseFlow
            }
        }
    }

    pub(crate) fn remove_flow(&mut self, conn_id: u64) {
        let Some(entry) = self.flows.remove(&conn_id) else {
            return;
        };

        self.bucket_active_flows[entry.fairness.bucket_id] =
            self.bucket_active_flows[entry.fairness.bucket_id].saturating_sub(1);

        let mut reclaimed = 0u64;
        for frame in entry.queue {
            reclaimed = reclaimed.saturating_add(frame.queued_bytes());
        }
        self.total_queued_bytes = self.total_queued_bytes.saturating_sub(reclaimed);
        self.bucket_queued_bytes[entry.fairness.bucket_id] =
            self.bucket_queued_bytes[entry.fairness.bucket_id].saturating_sub(reclaimed);
    }

    fn evaluate_pressure(&mut self, now: Instant, force: bool) {
        let mut standing = 0usize;
        let mut backpressured = 0usize;

        for flow in self.flows.values_mut() {
            Self::classify_flow(&self.config, self.pressure.state(), now, &mut flow.fairness);
            if flow.fairness.standing_state == StandingQueueState::Standing {
                standing = standing.saturating_add(1);
            }
            if matches!(
                flow.fairness.scheduler_state,
                FlowSchedulerState::Backpressured
                    | FlowSchedulerState::Penalized
                    | FlowSchedulerState::SheddingCandidate
            ) {
                backpressured = backpressured.saturating_add(1);
            }
        }

        self.standing_flow_count = standing;
        self.backpressured_flow_count = backpressured;

        let _ = self.pressure.maybe_evaluate(
            now,
            &self.config.pressure,
            self.config.max_total_queued_bytes,
            PressureSignals {
                active_flows: self.flows.len(),
                total_queued_bytes: self.total_queued_bytes,
                standing_flows: standing,
                backpressured_flows: backpressured,
            },
            force,
        );
    }

    fn classify_flow(
        config: &WorkerFairnessConfig,
        pressure_state: PressureState,
        now: Instant,
        fairness: &mut FlowFairnessState,
    ) {
        if fairness.pending_bytes == 0 {
            fairness.pressure_class = FlowPressureClass::Healthy;
            fairness.standing_state = StandingQueueState::Transient;
            fairness.scheduler_state = FlowSchedulerState::Idle;
            fairness.penalty_score = fairness.penalty_score.saturating_sub(1);
            return;
        }

        let queue_age = fairness
            .queue_started_at
            .map(|ts| now.saturating_duration_since(ts))
            .unwrap_or_default();
        let drain_stalled = fairness
            .last_drain_at
            .map(|ts| now.saturating_duration_since(ts) >= config.standing_queue_min_age)
            .unwrap_or(true);

        let standing = fairness.pending_bytes >= config.standing_queue_min_backlog_bytes
            && queue_age >= config.standing_queue_min_age
            && (fairness.consecutive_stalls >= config.standing_stall_threshold || drain_stalled);

        if standing {
            fairness.standing_state = StandingQueueState::Standing;
            fairness.pressure_class = FlowPressureClass::Standing;
            fairness.penalty_score = fairness.penalty_score.saturating_add(1);
            fairness.scheduler_state = if pressure_state >= PressureState::Shedding {
                FlowSchedulerState::SheddingCandidate
            } else {
                FlowSchedulerState::Penalized
            };
            return;
        }

        fairness.standing_state = StandingQueueState::Transient;
        if fairness.consecutive_stalls > 0 {
            fairness.pressure_class = FlowPressureClass::Backpressured;
            fairness.scheduler_state = FlowSchedulerState::Backpressured;
        } else if fairness.pending_bytes >= config.standing_queue_min_backlog_bytes {
            fairness.pressure_class = FlowPressureClass::Bursty;
            fairness.scheduler_state = FlowSchedulerState::Active;
        } else {
            fairness.pressure_class = FlowPressureClass::Healthy;
            fairness.scheduler_state = FlowSchedulerState::Active;
        }
        fairness.penalty_score = fairness.penalty_score.saturating_sub(1);
    }

    fn effective_quantum_bytes(
        config: &WorkerFairnessConfig,
        pressure_state: PressureState,
        fairness: &FlowFairnessState,
    ) -> u32 {
        let penalized = matches!(
            fairness.scheduler_state,
            FlowSchedulerState::Penalized | FlowSchedulerState::SheddingCandidate
        );

        if penalized {
            return config.penalized_quantum_bytes.max(1);
        }

        match pressure_state {
            PressureState::Normal => config.base_quantum_bytes.max(1),
            PressureState::Pressured => config.pressured_quantum_bytes.max(1),
            PressureState::Shedding => config.pressured_quantum_bytes.max(1),
            PressureState::Saturated => config.penalized_quantum_bytes.max(1),
        }
    }

    fn bucket_for(&self, conn_id: u64) -> usize {
        (conn_id as usize) % self.bucket_queued_bytes.len().max(1)
    }
}
