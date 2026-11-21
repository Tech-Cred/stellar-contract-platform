//! In-process background jobs for long-running analysis (#48).
//!
//! The queue is deterministic and clock-injected: every state transition takes
//! a `now` timestamp, so tests do not depend on the wall clock. Enqueue is
//! idempotent when an idempotency key is supplied, concurrency is bounded, and
//! failures are recorded and retried up to `max_attempts` before becoming final.

use std::collections::BTreeMap;

use observatory_core::{ObservatoryError, Result};
use serde::{Deserialize, Serialize};

/// Maximum retained jobs.
pub const MAX_JOBS: usize = 10_000;
/// Maximum attempts accepted for one job.
pub const MAX_ATTEMPTS: u32 = 10;

/// Lifecycle state of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Waiting to run.
    Queued,
    /// Currently running.
    Running,
    /// Finished successfully.
    Succeeded,
    /// Failed permanently after the attempt budget.
    Failed,
    /// Cancelled before it started.
    Cancelled,
}

/// A background job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    /// Stable job id.
    pub id: String,
    /// Caller-defined kind (for example `analysis.inspect`).
    pub kind: String,
    /// Current state.
    pub state: JobState,
    /// Attempts started so far.
    pub attempts: u32,
    /// Attempt budget.
    pub max_attempts: u32,
    /// Idempotency key, when supplied.
    pub idempotency_key: Option<String>,
    /// Creation timestamp.
    pub created_at: u64,
    /// Start of the current/last attempt.
    pub started_at: Option<u64>,
    /// Completion timestamp.
    pub finished_at: Option<u64>,
    /// Last recorded error.
    pub error: Option<String>,
    /// Result payload for a successful job.
    pub result: Option<String>,
}

/// A bounded, in-process job queue.
#[derive(Debug)]
pub struct JobQueue {
    jobs: BTreeMap<String, Job>,
    idempotency: BTreeMap<String, String>,
    next_id: u64,
    max_concurrency: usize,
}

impl JobQueue {
    /// Create a queue allowing at most `max_concurrency` running jobs.
    #[must_use]
    pub fn new(max_concurrency: usize) -> Self {
        JobQueue {
            jobs: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            next_id: 0,
            max_concurrency: max_concurrency.max(1),
        }
    }

    /// Enqueue a job, returning the existing job for a repeated idempotency key.
    pub fn enqueue(
        &mut self,
        kind: &str,
        idempotency_key: Option<&str>,
        max_attempts: Option<u32>,
        now: u64,
    ) -> Result<Job> {
        let kind = kind.trim();
        if kind.is_empty() || kind.len() > 64 {
            return Err(ObservatoryError::invalid("kind must be 1-64 characters"));
        }
        let attempts = max_attempts.unwrap_or(3);
        if attempts == 0 || attempts > MAX_ATTEMPTS {
            return Err(ObservatoryError::invalid(format!(
                "max_attempts must be between 1 and {MAX_ATTEMPTS}"
            )));
        }
        if let Some(key) = idempotency_key {
            if let Some(existing) = self.idempotency.get(key).and_then(|id| self.jobs.get(id)) {
                return Ok(existing.clone());
            }
        }
        if self.jobs.len() >= MAX_JOBS {
            return Err(ObservatoryError::invalid("job queue is full"));
        }

        self.next_id += 1;
        let id = format!("job-{:016x}", self.next_id);
        let job = Job {
            id: id.clone(),
            kind: kind.to_string(),
            state: JobState::Queued,
            attempts: 0,
            max_attempts: attempts,
            idempotency_key: idempotency_key.map(str::to_string),
            created_at: now,
            started_at: None,
            finished_at: None,
            error: None,
            result: None,
        };
        self.jobs.insert(id.clone(), job.clone());
        if let Some(key) = idempotency_key {
            self.idempotency.insert(key.to_string(), id);
        }
        Ok(job)
    }

    /// Look up a job by id.
    #[must_use]
    pub fn job(&self, id: &str) -> Option<&Job> {
        self.jobs.get(id)
    }

    /// All jobs, ordered by id.
    #[must_use]
    pub fn jobs(&self) -> Vec<Job> {
        self.jobs.values().cloned().collect()
    }

    /// Number of currently running jobs.
    #[must_use]
    pub fn running(&self) -> usize {
        self.jobs
            .values()
            .filter(|job| job.state == JobState::Running)
            .count()
    }

    /// Start the next queued job if concurrency permits.
    pub fn start_next(&mut self, now: u64) -> Option<Job> {
        if self.running() >= self.max_concurrency {
            return None;
        }
        let id = self
            .jobs
            .values()
            .find(|job| job.state == JobState::Queued)
            .map(|job| job.id.clone())?;
        let job = self.jobs.get_mut(&id)?;
        job.state = JobState::Running;
        job.attempts += 1;
        job.started_at = Some(now);
        Some(job.clone())
    }

    /// Mark a running job successful.
    pub fn complete(&mut self, id: &str, result: impl Into<String>, now: u64) -> bool {
        match self.jobs.get_mut(id) {
            Some(job) if job.state == JobState::Running => {
                job.state = JobState::Succeeded;
                job.result = Some(result.into());
                job.error = None;
                job.finished_at = Some(now);
                true
            }
            _ => false,
        }
    }

    /// Record a failure, requeueing while attempts remain.
    pub fn fail(&mut self, id: &str, error: impl Into<String>, now: u64) -> bool {
        let error = error.into();
        match self.jobs.get_mut(id) {
            Some(job) if job.state == JobState::Running => {
                job.error = Some(error);
                if job.attempts < job.max_attempts {
                    job.state = JobState::Queued;
                    job.started_at = None;
                } else {
                    job.state = JobState::Failed;
                    job.finished_at = Some(now);
                }
                true
            }
            _ => false,
        }
    }

    /// Cancel a queued job.
    pub fn cancel(&mut self, id: &str, now: u64) -> bool {
        match self.jobs.get_mut(id) {
            Some(job) if job.state == JobState::Queued => {
                job.state = JobState::Cancelled;
                job.finished_at = Some(now);
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_is_idempotent_and_bounded() {
        let mut queue = JobQueue::new(1);
        let first = queue.enqueue("analysis", Some("k1"), Some(2), 10).unwrap();
        let second = queue.enqueue("analysis", Some("k1"), Some(2), 11).unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(queue.jobs().len(), 1);
        assert!(queue.enqueue("", None, None, 12).is_err());
        assert!(queue.enqueue("x", None, Some(0), 12).is_err());
    }

    #[test]
    fn concurrency_is_bounded_and_failures_retry_then_persist() {
        let mut queue = JobQueue::new(1);
        let job = queue.enqueue("analysis", None, Some(2), 0).unwrap();
        assert!(queue.start_next(1).is_some());
        assert!(queue.start_next(2).is_none(), "concurrency is one");
        assert!(queue.fail(&job.id, "boom", 3));
        assert_eq!(queue.job(&job.id).unwrap().state, JobState::Queued);
        assert!(queue.start_next(4).is_some());
        assert!(queue.fail(&job.id, "boom again", 5));
        let stored = queue.job(&job.id).unwrap();
        assert_eq!(stored.state, JobState::Failed);
        assert_eq!(stored.error.as_deref(), Some("boom again"));
    }

    #[test]
    fn complete_and_cancel_are_explicit() {
        let mut queue = JobQueue::new(1);
        let job = queue.enqueue("analysis", None, None, 0).unwrap();
        assert!(queue.cancel(&job.id, 1));
        assert_eq!(queue.job(&job.id).unwrap().state, JobState::Cancelled);
        assert!(!queue.start_next(2).is_some());

        let job = queue.enqueue("analysis", None, None, 3).unwrap();
        assert!(queue.start_next(4).is_some());
        assert!(queue.complete(&job.id, "ok", 5));
        assert_eq!(queue.job(&job.id).unwrap().state, JobState::Succeeded);
    }
}
