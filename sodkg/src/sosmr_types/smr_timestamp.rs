use chrono::{DateTime, Local, Utc};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{self, Debug, Display, Formatter},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use utoipa::ToSchema;

/// The number of microseconds in a second.
pub const MICROSECONDS_PER_SECOND: u64 = 1_000_000;

/// Timestamps used by SMR-related types. Respects the bounds of [chrono::DateTime].
#[derive(Clone, Copy, Default, Hash, Eq, Ord, PartialEq, PartialOrd, ToSchema)]
pub struct SmrTimestamp {
    /// The timestamp as measured in the number of microseconds since the unix epoch.
    timestamp: u64,
}

impl SmrTimestamp {
    /// Returns the maximum [SmrTimestamp].
    pub fn maximum() -> Self {
        Self {
            timestamp: Self::max_microseconds(),
        }
    }

    /// Returns the current [SmrTimestamp].
    pub fn now() -> Self {
        // u64::MAX in microseconds is 584,492 years from the Unix epoch, so this cast should
        // not fail any time soon.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("UNIX_EPOCH must be in the past")
            .as_micros() as u64;
        Self { timestamp: now }
    }

    /// Returns the [SmrTimestamp] that is `microseconds_since_unix_epoch` after [UNIX_EPOCH].
    /// If `microseconds_since_unix_epoch` is larger than the maximum [SmrTimestamp], returns
    /// the maximum [SmrTimestamp] instead.
    pub fn new_from(microseconds_since_unix_epoch: u64) -> Self {
        let maybe_unsafe = Self {
            timestamp: microseconds_since_unix_epoch,
        };
        maybe_unsafe.bound()
    }

    /// Returns a new [SmrTimestamp] derived from the given number of seconds since the Unix epoch.
    /// If the derivation leads to an overflow, then [Self::maximum] is returned.
    pub fn new_from_seconds(seconds_since_unix_epoch: u64) -> Self {
        seconds_since_unix_epoch
            .checked_mul(MICROSECONDS_PER_SECOND)
            .map(Self::new_from)
            .unwrap_or(Self::maximum())
    }

    /// Returns the [SmrTimestamp] that is `in_future` seconds from now. Returns [Self::maximum] if
    /// `in_future` overflows when converted to microseconds, or when added to [Self::now].
    pub fn seconds_from_now(in_future: u64) -> Self {
        let now = Self::now();
        // Ensure that the number of seconds does not overflow when converted to microseconds.
        let Some(microseconds_to_add) = in_future.checked_mul(MICROSECONDS_PER_SECOND) else {
            return Self::maximum();
        };
        // Ensure that the total number of microseconds does not overflow.
        let Some(maybe_unsafe_future) = now.timestamp.checked_add(microseconds_to_add) else {
            return Self::maximum();
        };
        // Ensure that the total number of microseconds is within the bound dictated by [chrono].
        Self::new_from(maybe_unsafe_future)
    }

    pub fn unix_epoch() -> Self {
        Self { timestamp: 0 }
    }

    pub fn as_duration(self) -> Duration {
        Duration::from_micros(self.timestamp)
    }

    /// Returns the number of seconds that `self` is greater than `t` if `self` is more recent than
    /// `t`, or `0` if `t` more recent than `self`.
    pub fn seconds_since(&self, t: SmrTimestamp) -> u64 {
        let d1 = self.as_duration();
        let d2 = t.as_duration();

        if d1 > d2 {
            (d1 - d2).as_secs()
        } else {
            0
        }
    }

    /// Returns the number of microseconds that `self` is greater than `t` if `self` is more recent
    /// than `t`, or `0` if `t` more recent than `self`.
    pub fn microseconds_since(&self, t: SmrTimestamp) -> u64 {
        let d1 = self.as_duration();
        let d2 = t.as_duration();

        if d1 > d2 {
            // u64::MAX in microseconds is 584,492 years from the Unix epoch, so this cast should
            // not fail.
            (d1 - d2).as_micros() as u64
        } else {
            0
        }
    }

    pub fn to_le_bytes(self) -> [u8; 8] {
        self.timestamp.to_le_bytes()
    }

    pub fn to_be_bytes(self) -> [u8; 8] {
        self.timestamp.to_be_bytes()
    }

    /// Converts the timestamp to a date-time in the local timezone formatted according to ISO 8601.
    pub fn local_date_time_string(self) -> String {
        DateTime::<Local>::from(self).to_rfc3339()
    }

    /// Converts the timestamp to a date-time in the UTC timezone formatted according to ISO 8601.
    pub fn utc_date_time_string(self) -> String {
        DateTime::<Utc>::from(self).to_rfc3339()
    }

    /// Returns `true` iff this [SmrTimestamp] represents a time in the past.
    pub fn is_past(&self) -> bool {
        self.seconds_since(SmrTimestamp::now()) == 0
    }

    fn max_microseconds() -> u64 {
        let max = DateTime::<Utc>::MAX_UTC.timestamp_micros();

        if max.is_negative() {
            // Will only execute this branch if [chrono] has a bug. Return 0 to be safe.
            0
        } else {
            // It should be reasonable to assume that a non-negative i64 will always fit into a u64.
            max as u64
        }
    }

    /// Ensures that this [SmrTimestamp] is no greater than [chrono::DateTime::MAX_UTC].
    /// This guarantees that conversions from [SmrTimestamp] to [DateTime] will always succeed.
    /// This is necessary because [DateTime::from] will panic if the input value cannot be
    /// converted into a [DateTime] (despite the interface giving the impression that all inputs
    /// are valid).
    ///
    /// We would currently prefer not to have to use [Result]s wherever [SmrTimestamp] is used,
    /// so choose to bound it instead of returning an [Err] when the input is too large. There
    /// should be no reasonable use-case in intended context of use (i.e. in the Supra blockchain),
    /// where an [SmrTimestamp] should need to be greater than [chrono::DateTime::MAX_UTC].
    fn bound(mut self) -> Self {
        let max = Self::max_microseconds();

        let bounded = if self.timestamp > max {
            max
        } else {
            self.timestamp
        };

        self.timestamp = bounded;
        self
    }
}

impl Debug for SmrTimestamp {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("SmrTimestamp")
            .field("timestamp", &self.timestamp)
            .field("local_date_time", &self.local_date_time_string())
            .field("utc_date_time", &self.utc_date_time_string())
            .finish()
    }
}

impl Display for SmrTimestamp {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{self:?}")
    }
}

impl From<SmrTimestamp> for DateTime<Local> {
    fn from(t: SmrTimestamp) -> Self {
        let d = UNIX_EPOCH + t.as_duration();
        DateTime::<Local>::from(d)
    }
}

impl From<SmrTimestamp> for DateTime<Utc> {
    fn from(t: SmrTimestamp) -> Self {
        let d = UNIX_EPOCH + t.as_duration();
        DateTime::<Utc>::from(d)
    }
}

impl From<SmrTimestamp> for u64 {
    fn from(t: SmrTimestamp) -> Self {
        t.timestamp
    }
}

impl From<u64> for SmrTimestamp {
    fn from(t: u64) -> Self {
        Self::new_from(t)
    }
}

impl<'de> Deserialize<'de> for SmrTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            Timestamp::deserialize(deserializer)
                .map(SmrTimestamp::from)
                .map_err(de::Error::custom)
        } else {
            let microseconds_since_unix_epoch = u64::deserialize(deserializer)?;
            Ok(SmrTimestamp::new_from(microseconds_since_unix_epoch))
        }
    }
}

impl Serialize for SmrTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let human_readable_timestamp = Timestamp::from(self);
            // Serialize to a human-readable string.
            human_readable_timestamp.serialize(serializer)
        } else {
            // Serialize to a compact binary representation.
            self.timestamp.serialize(serializer)
        }
    }
}

/// A human-readable version of [SmrTimestamp] used for serde.
#[derive(Debug, Deserialize, Serialize)]
struct Timestamp {
    microseconds_since_unix_epoch: u64,
    utc_date_time: String,
}

impl Display for Timestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<&SmrTimestamp> for Timestamp {
    fn from(t: &SmrTimestamp) -> Self {
        Self {
            microseconds_since_unix_epoch: t.timestamp,
            utc_date_time: t.utc_date_time_string(),
        }
    }
}

impl From<Timestamp> for SmrTimestamp {
    fn from(t: Timestamp) -> Self {
        Self::new_from(t.microseconds_since_unix_epoch)
    }
}
