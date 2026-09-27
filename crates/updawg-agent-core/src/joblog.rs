//! A job's log, streamed to the gateway while it runs (DAWG-101).
//!
//! Every line the package manager prints, and a few of the agent's own, is
//! kept here with a sequence number and sent in batches of NDJSON: every
//! [`FLUSH_EVERY`] while the job runs, and all of what is left before the
//! job's report. The gateway stores each batch as it arrives, so somebody
//! watching the portal sees apt working rather than a spinner.
//!
//! # A log never holds up a job
//!
//! Sending is best effort. A batch that fails is kept and tried again with the
//! next; one the gateway refuses for good is dropped; and at most
//! [`MAX_PENDING`] lines wait, the oldest going first, so an unreachable
//! gateway costs memory that is bounded and never an install that stalls.
//! The report that follows is what the proposal settles on, not the log.

use crate::jobs::Reporter;
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use updawg_protocol::{Job, LogLine, LogStream};

/// How often buffered lines are sent while a job runs.
pub const FLUSH_EVERY: Duration = Duration::from_secs(2);
/// The most lines in one batch. The gateway takes up to 1,000.
pub const BATCH: usize = 500;
/// The most lines kept waiting for an unreachable gateway.
pub const MAX_PENDING: usize = 20_000;
/// Where the sequence resumes after a reboot. The count is not persisted
/// across one, so the second half of a job's log starts well clear of the
/// first; the gateway takes sequence numbers up to ten million.
pub const AFTER_REBOOT: u64 = 5_000_000;

struct Pending {
    lines: VecDeque<LogLine>,
    next_seq: u64,
    dropped: u64,
}

pub struct JobLog {
    job: Job,
    reporter: Arc<dyn Reporter>,
    pending: std::sync::Mutex<Pending>,
    /// Held while a batch is in flight, so the flusher and `finish` never send
    /// the same lines twice or out of order.
    sending: Mutex<()>,
    flusher: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl JobLog {
    /// Start a job's log, numbering from `first_seq`, with a flusher running.
    pub fn start(reporter: Arc<dyn Reporter>, job: Job, first_seq: u64) -> Arc<Self> {
        let log = Arc::new(Self {
            job,
            reporter,
            pending: std::sync::Mutex::new(Pending {
                lines: VecDeque::new(),
                next_seq: first_seq,
                dropped: 0,
            }),
            sending: Mutex::new(()),
            flusher: std::sync::Mutex::new(None),
        });
        let weak = Arc::downgrade(&log);
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(FLUSH_EVERY).await;
                let Some(log) = weak.upgrade() else { return };
                log.send_one().await;
            }
        });
        if let Ok(mut flusher) = log.flusher.lock() {
            *flusher = Some(handle);
        }
        log
    }

    /// One of the agent's own lines: what it is about to do, what it did.
    pub fn agent(&self, line: impl Into<String>) {
        let line = line.into();
        tracing::info!(job = %self.job.id, "{line}");
        self.push(LogStream::Agent, line);
    }

    fn push(&self, stream: LogStream, line: String) {
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        let seq = pending.next_seq;
        pending.next_seq += 1;
        pending.lines.push_back(LogLine {
            at: chrono::Utc::now(),
            stream,
            line,
            seq,
        });
        if pending.lines.len() > MAX_PENDING {
            pending.lines.pop_front();
            pending.dropped += 1;
        }
    }

    /// Send one batch, if there is anything. `true` if lines remain.
    async fn send_one(&self) -> bool {
        let _one_at_a_time = self.sending.lock().await;
        let batch: Vec<LogLine> = {
            let Ok(pending) = self.pending.lock() else {
                return false;
            };
            pending.lines.iter().take(BATCH).cloned().collect()
        };
        if batch.is_empty() {
            return false;
        }
        let Ok(ndjson) = LogLine::to_ndjson(&batch) else {
            return false;
        };
        let sent = match self.reporter.logs(&self.job, ndjson).await {
            Ok(stored) => {
                if !stored {
                    tracing::warn!(job = %self.job.id, lines = batch.len(), "the gateway refused a log batch; dropped it");
                }
                true
            }
            Err(error) => {
                tracing::debug!(job = %self.job.id, error = format!("{error:#}"), "could not send a log batch; will retry");
                false
            }
        };
        let Ok(mut pending) = self.pending.lock() else {
            return false;
        };
        if sent {
            // Only what was sent: the flusher may have pushed more meanwhile,
            // and the oldest may have been dropped for room. Match by seq.
            let last = batch.last().map_or(0, |l| l.seq);
            while pending.lines.front().is_some_and(|l| l.seq <= last) {
                pending.lines.pop_front();
            }
        }
        sent && !pending.lines.is_empty()
    }

    /// Stop the flusher and send what is left, trying a few times. Called
    /// before the job's report, and before a reboot, which may be the last
    /// chance this process has.
    pub async fn finish(&self) {
        if let Ok(mut flusher) = self.flusher.lock()
            && let Some(handle) = flusher.take()
        {
            handle.abort();
        }
        let dropped = self.pending.lock().map_or(0, |p| p.dropped);
        if dropped > 0 {
            self.agent(format!(
                "{dropped} earlier lines were not sent: the gateway could not be reached while they were kept"
            ));
            if let Ok(mut pending) = self.pending.lock() {
                pending.dropped = 0;
            }
        }
        let mut failures = 0;
        loop {
            let before = self.pending.lock().map_or(0, |p| p.lines.len());
            if before == 0 {
                return;
            }
            let more = self.send_one().await;
            let after = self.pending.lock().map_or(0, |p| p.lines.len());
            if after < before {
                failures = 0;
            } else {
                failures += 1;
                if failures >= 3 {
                    tracing::warn!(job = %self.job.id, lines = after, "gave up sending the rest of the job's log");
                    return;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            if !more && after == 0 {
                return;
            }
        }
    }
}

impl std::fmt::Debug for JobLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobLog")
            .field("job", &self.job.id)
            .finish_non_exhaustive()
    }
}

impl Drop for JobLog {
    fn drop(&mut self) {
        if let Ok(mut flusher) = self.flusher.lock()
            && let Some(handle) = flusher.take()
        {
            handle.abort();
        }
    }
}

impl updawg_backends::LogSink for JobLog {
    fn line(&self, line: &str) {
        tracing::info!(job = %self.job.id, "{line}");
        self.push(LogStream::Stdout, line.to_owned());
    }
}
