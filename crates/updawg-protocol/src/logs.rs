//! Job logs: `POST /agent/v1/jobs/{job_id}/logs`.
//!
//! Sent as batched NDJSON — one [`LogLine`] per line — so a long apply streams
//! rather than arriving all at once when it finishes. Logs go to object storage
//! rather than the database; at fleet scale they are the largest thing the
//! system writes and the least useful to query relationally.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    /// Output from the agent itself.
    Agent,
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LogLine {
    pub at: DateTime<Utc>,
    pub stream: LogStream,
    pub line: String,
    /// Position in the job's output, so the server can order and deduplicate
    /// batches that arrive out of order or twice.
    pub seq: u64,
}

impl LogLine {
    /// Render a batch as NDJSON.
    pub fn to_ndjson(lines: &[Self]) -> Result<String, serde_json::Error> {
        let mut out = String::new();
        for line in lines {
            out.push_str(&serde_json::to_string(line)?);
            out.push('\n');
        }
        Ok(out)
    }

    /// Parse a batch of NDJSON, skipping blank lines.
    pub fn from_ndjson(body: &str) -> Result<Vec<Self>, serde_json::Error> {
        body.lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndjson_round_trips_and_tolerates_trailing_newlines() {
        let lines = vec![
            LogLine {
                at: Utc::now(),
                stream: LogStream::Agent,
                line: "starting".into(),
                seq: 0,
            },
            LogLine {
                at: Utc::now(),
                stream: LogStream::Stdout,
                line: "Setting up openssl".into(),
                seq: 1,
            },
        ];
        let body = LogLine::to_ndjson(&lines).unwrap();
        assert_eq!(body.matches('\n').count(), 2);
        let back = LogLine::from_ndjson(&format!("{body}\n\n")).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[1].seq, 1);
    }
}
