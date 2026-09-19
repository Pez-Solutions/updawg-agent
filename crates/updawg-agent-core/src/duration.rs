//! Human-written durations.
//!
//! `agent.toml` says `"6h"`, not `21600`. Operators edit this file by hand, and
//! a number of seconds is a thing you have to decode before you can review it.

use std::{fmt, time::Duration};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseDurationError {
    #[error("empty duration")]
    Empty,
    #[error("`{0}` has no unit — write 30s, 5m, 6h or 2d")]
    MissingUnit(String),
    #[error("`{unit}` is not a known unit in `{input}` — use s, m, h or d")]
    UnknownUnit { input: String, unit: String },
    #[error("`{0}` is not a number")]
    NotANumber(String),
}

/// Parse `30s`, `5m`, `6h`, `2d`.
///
/// Deliberately strict: a bare number is rejected rather than guessed at. The
/// difference between `30` meaning seconds and meaning minutes is the
/// difference between a polite agent and one hammering the gateway.
pub fn parse(input: &str) -> Result<Duration, ParseDurationError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ParseDurationError::Empty);
    }

    let split = s.find(|c: char| !c.is_ascii_digit());
    let Some(idx) = split else {
        return Err(ParseDurationError::MissingUnit(s.to_string()));
    };
    if idx == 0 {
        return Err(ParseDurationError::NotANumber(s.to_string()));
    }

    let (value, unit) = s.split_at(idx);
    let value: u64 = value
        .parse()
        .map_err(|_| ParseDurationError::NotANumber(s.to_string()))?;

    let seconds = match unit {
        "s" => value,
        "m" => value * 60,
        "h" => value * 3600,
        "d" => value * 86_400,
        other => {
            return Err(ParseDurationError::UnknownUnit {
                input: s.to_string(),
                unit: other.to_string(),
            });
        }
    };
    Ok(Duration::from_secs(seconds))
}

/// A duration that serialises back to the form a human wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanDuration(pub Duration);

impl HumanDuration {
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        self.0
    }
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.as_secs();
        if s.is_multiple_of(86_400) && s > 0 {
            write!(f, "{}d", s / 86_400)
        } else if s.is_multiple_of(3600) && s > 0 {
            write!(f, "{}h", s / 3600)
        } else if s.is_multiple_of(60) && s > 0 {
            write!(f, "{}m", s / 60)
        } else {
            write!(f, "{s}s")
        }
    }
}

impl<'de> serde::Deserialize<'de> for HumanDuration {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse(&s)
            .map(HumanDuration)
            .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for HumanDuration {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_unit() {
        assert_eq!(parse("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse("6h").unwrap(), Duration::from_secs(21_600));
        assert_eq!(parse("2d").unwrap(), Duration::from_secs(172_800));
    }

    #[test]
    fn a_bare_number_is_rejected_rather_than_guessed() {
        assert_eq!(
            parse("30"),
            Err(ParseDurationError::MissingUnit("30".into()))
        );
    }

    #[test]
    fn unknown_units_say_what_is_allowed() {
        let err = parse("6w").unwrap_err();
        assert!(err.to_string().contains("use s, m, h or d"));
    }

    #[test]
    fn round_trips_through_display() {
        for s in ["30s", "5m", "6h", "2d"] {
            let d = HumanDuration(parse(s).unwrap());
            assert_eq!(d.to_string(), s);
        }
    }

    #[test]
    fn whitespace_and_empty_input_are_handled() {
        assert_eq!(parse("  6h  ").unwrap(), Duration::from_secs(21_600));
        assert_eq!(parse("   "), Err(ParseDurationError::Empty));
    }
}
