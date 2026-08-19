//! Audit errors.
//!
//! The important one is [`AuditError::AllDevicesFailed`]. It exists so that the
//! server has something to fail the request with: if no device accepted the record,
//! the access must not happen, and the caller gets a `503` rather than a secret.

use core::fmt;

/// Something went wrong while recording an audit entry.
#[derive(Debug)]
pub enum AuditError {
    /// A sink was constructed with no devices.
    ///
    /// A secret store without an audit trail is a configuration error in this
    /// project, not an operating mode. The server refuses to start.
    NoDevices,
    /// No configured device accepted the record.
    ///
    /// **Fail closed:** the request must be refused and no secret served. An access
    /// that could not be logged but happened anyway is worse than an access that
    /// failed — that trade is the reason this project exists.
    AllDevicesFailed {
        /// What each device said, in configuration order.
        failures: Vec<DeviceFailure>,
    },
    /// The entry could not be serialized.
    Encode(serde_json::Error),
}

/// One device's failure.
#[derive(Debug)]
pub struct DeviceFailure {
    /// The device that failed, as named in configuration.
    pub device: String,
    /// What went wrong.
    pub reason: String,
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDevices => f.write_str(
                "no audit device is configured; a secret store without an audit trail \
                 is a configuration error",
            ),
            Self::AllDevicesFailed { failures } => {
                f.write_str("no audit device accepted the record:")?;
                for failure in failures {
                    write!(f, " [{}: {}]", failure.device, failure.reason)?;
                }
                Ok(())
            }
            Self::Encode(error) => write!(f, "could not encode the audit entry: {error}"),
        }
    }
}

impl core::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            _ => None,
        }
    }
}

/// Why a chain does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    /// The sequence number of the record where the problem was found.
    pub seq: u64,
    /// What is wrong.
    pub kind: BreakKind,
}

/// The shape of a chain break.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakKind {
    /// The stored hash is not the hash of the stored bytes: the record was edited.
    HashMismatch,
    /// The record does not chain to its predecessor: a record was removed,
    /// reordered, or inserted.
    PrevHashMismatch,
    /// Sequence numbers are not consecutive.
    SequenceGap {
        /// The sequence number that was expected.
        expected: u64,
    },
    /// The stored bytes are not a record this build can read.
    Malformed {
        /// What went wrong, without the content.
        detail: String,
    },
    /// The record claims a sequence number that disagrees with its own payload.
    SequenceMismatch {
        /// What the payload says.
        payload_seq: u64,
    },
    /// The record at an anchored sequence number does not have the anchored hash.
    ///
    /// The one break a chain cannot produce on its own: the records are internally
    /// consistent and contradict evidence kept outside the store. See
    /// [`crate::anchor`].
    AnchorMismatch {
        /// The hash the anchor recorded, hexadecimal.
        anchored: String,
        /// The hash the stored record has now, hexadecimal.
        stored: String,
    },
    /// The records in hand cannot be attached to the anchor at all.
    ///
    /// Not a verdict about them — a refusal to give one. Reporting success for an
    /// anchor that was never checked would be the worse answer.
    AnchorUnreachable {
        /// The highest sequence number the records in hand reach, or zero if there
        /// are none.
        head_seq: u64,
    },
}

impl fmt::Display for ChainBreak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "audit chain breaks at sequence {}: ", self.seq)?;
        match &self.kind {
            BreakKind::HashMismatch => f.write_str(
                "the stored hash does not match the stored record, so the record was modified",
            ),
            BreakKind::PrevHashMismatch => f.write_str(
                "the record does not chain to its predecessor, so an entry was removed, \
                 reordered or inserted",
            ),
            BreakKind::SequenceGap { expected } => {
                write!(f, "expected sequence {expected}")
            }
            BreakKind::Malformed { detail } => write!(f, "the record is unreadable: {detail}"),
            BreakKind::SequenceMismatch { payload_seq } => write!(
                f,
                "the record's own sequence number is {payload_seq}, which disagrees with where \
                 it is stored"
            ),
            BreakKind::AnchorMismatch { anchored, stored } => write!(
                f,
                "the stored record hashes to {stored}, but an anchor taken outside the store \
                 recorded {anchored} — either the chain was rewritten, or the anchor belongs \
                 to a different store"
            ),
            BreakKind::AnchorUnreachable { head_seq } => write!(
                f,
                "the records in hand reach sequence {head_seq} and neither contain this \
                 sequence nor continue from it, so the anchor cannot be checked against them"
            ),
        }
    }
}

impl core::error::Error for ChainBreak {}
