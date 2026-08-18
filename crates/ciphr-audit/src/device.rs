//! Devices, and the sink that writes to all of them.
//!
//! # Fail closed
//!
//! If **no** configured device accepts a record, [`AuditSink::record`] returns an
//! error and the caller must refuse the request. Adopted from OpenBao, whose
//! documentation states it plainly: a request is successful if it can be logged to
//! *at least one* configured device. The alternative — serve the secret and skip the
//! log — is exactly the blind spot that disqualified other candidates during the
//! evaluation.
//!
//! The operational consequence is real and intended: a full audit volume takes the
//! service down. That is a monitoring requirement, not a defect to be optimized away
//! later.
//!
//! # Partial failure
//!
//! If one device of two fails, the record is written, the failure is reported in the
//! outcome, and the caller decides what to do with it — surface it on the health
//! endpoint, raise a metric. It is not silently swallowed: a second device that has
//! been failing for a month is a second device that does not exist.

use crate::chain::{Chain, EncodedRecord, HASH_LEN};
use crate::entry::Entry;
use crate::error::{AuditError, DeviceFailure};

/// Somewhere audit records are stored.
///
/// Implementations must make a record durable before returning success. "Written"
/// has to mean written, or fail-closed becomes a promise about a buffer.
///
/// `Send` is required because a device is written to from whichever worker thread is
/// handling a request. It is deliberately **not** `Sync`: a device is used behind the
/// sink's lock, one record at a time, and two threads writing to one file device
/// concurrently would interleave lines — which for a hash chain means a chain that
/// does not verify.
pub trait AuditDevice: Send {
    /// The device's name, as it appears in configuration and in errors.
    fn name(&self) -> &str;

    /// Store a record durably.
    ///
    /// # Errors
    ///
    /// Any failure, described as a string. The sink collects these and decides
    /// whether the request can proceed; a device does not get to make that call.
    fn write(&mut self, record: &EncodedRecord) -> Result<(), String>;

    /// Reopen the underlying resource, if it has one.
    ///
    /// Called on `SIGHUP`, so that an external log rotation can move the file and
    /// have the next write land in a new one. The default does nothing, which is
    /// correct for a device with nothing to reopen.
    ///
    /// # Errors
    ///
    /// Any failure, described as a string.
    fn reopen(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// What happened when a record was written.
#[derive(Debug)]
pub struct Written {
    /// The sequence number the record received.
    pub seq: u64,
    /// The record's hash, which is the new head of the chain.
    pub hash: [u8; HASH_LEN],
    /// Devices that failed. Empty in the normal case.
    ///
    /// Non-empty means the record is stored somewhere but not everywhere, which is
    /// worth surfacing: it is the state in which the audit trail is one disk failure
    /// away from a gap.
    pub failures: Vec<DeviceFailure>,
}

/// Writes every record to every configured device, and owns the chain.
///
/// The chain lives here rather than in a device so that all devices record the same
/// history. Two devices with independent chains would produce two sequences that
/// cannot be compared, which is most of the value of having a second one.
pub struct AuditSink {
    devices: Vec<Box<dyn AuditDevice>>,
    chain: Chain,
}

impl AuditSink {
    /// Build a sink over at least one device.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::NoDevices`] if the list is empty. The server refuses to
    /// start in that case: a secret store with no audit trail is a configuration
    /// error, not a mode of operation.
    pub fn new(devices: Vec<Box<dyn AuditDevice>>, chain: Chain) -> Result<Self, AuditError> {
        if devices.is_empty() {
            return Err(AuditError::NoDevices);
        }
        Ok(Self { devices, chain })
    }

    /// The sequence number the next record will get.
    pub fn next_seq(&self) -> u64 {
        self.chain.next_seq()
    }

    /// The current head of the chain.
    pub fn head_hash(&self) -> [u8; HASH_LEN] {
        self.chain.head_hash()
    }

    /// The configured device names, in order.
    pub fn device_names(&self) -> Vec<&str> {
        self.devices.iter().map(|device| device.name()).collect()
    }

    /// Record an entry.
    ///
    /// Called **before** the response is produced, never after: an entry written
    /// afterwards is an entry that a crash in between turns into an unlogged access.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::AllDevicesFailed`] if no device accepted the record. The
    /// chain does not advance in that case, so the sequence number is reused by the
    /// next attempt and no gap appears — a gap is indistinguishable from a deleted
    /// entry, and an audit trail that cries tampering after a disk error is one
    /// nobody will trust.
    pub fn record(&mut self, entry: &Entry, now_millis: i64) -> Result<Written, AuditError> {
        let record = self.chain.encode(entry, now_millis)?;

        let mut failures = Vec::new();
        for device in &mut self.devices {
            if let Err(reason) = device.write(&record) {
                failures.push(DeviceFailure {
                    device: device.name().to_owned(),
                    reason,
                });
            }
        }

        if failures.len() == self.devices.len() {
            return Err(AuditError::AllDevicesFailed { failures });
        }

        self.chain.commit(&record);
        Ok(Written {
            seq: record.seq,
            hash: record.hash,
            failures,
        })
    }

    /// Ask every device to reopen its underlying resource.
    ///
    /// Failures are collected rather than returned early: one device failing to
    /// reopen must not stop the others from doing so.
    pub fn reopen(&mut self) -> Vec<DeviceFailure> {
        let mut failures = Vec::new();
        for device in &mut self.devices {
            if let Err(reason) = device.reopen() {
                failures.push(DeviceFailure {
                    device: device.name().to_owned(),
                    reason,
                });
            }
        }
        failures
    }
}

#[cfg(test)]
mod tests {
    use super::{AuditDevice, AuditSink};
    use crate::chain::{Chain, EncodedRecord};
    use crate::entry::{Action, Entry};
    use crate::error::AuditError;

    /// A device that stores records in memory, and can be told to fail.
    struct Recorder {
        name: &'static str,
        failing: bool,
        stored: Vec<EncodedRecord>,
    }

    impl Recorder {
        fn working(name: &'static str) -> Self {
            Self {
                name,
                failing: false,
                stored: Vec::new(),
            }
        }

        fn failing(name: &'static str) -> Self {
            Self {
                name,
                failing: true,
                stored: Vec::new(),
            }
        }
    }

    impl AuditDevice for Recorder {
        fn name(&self) -> &str {
            self.name
        }

        fn write(&mut self, record: &EncodedRecord) -> Result<(), String> {
            if self.failing {
                return Err("device is configured to fail".to_owned());
            }
            self.stored.push(record.clone());
            Ok(())
        }
    }

    fn entry() -> Entry {
        Entry::allowed(Action::Read)
    }

    #[test]
    fn a_sink_needs_at_least_one_device() {
        assert!(matches!(
            AuditSink::new(Vec::new(), Chain::new()),
            Err(AuditError::NoDevices)
        ));
    }

    #[test]
    fn a_record_goes_to_every_device() {
        let mut sink = AuditSink::new(
            vec![
                Box::new(Recorder::working("a")),
                Box::new(Recorder::working("b")),
            ],
            Chain::new(),
        )
        .expect("two devices");

        let written = sink.record(&entry(), 1).expect("write");
        assert_eq!(written.seq, 1);
        assert!(written.failures.is_empty());
        assert_eq!(sink.next_seq(), 2);
        assert_eq!(sink.device_names(), ["a", "b"]);
    }

    #[test]
    fn one_device_failing_is_reported_but_not_fatal() {
        let mut sink = AuditSink::new(
            vec![
                Box::new(Recorder::failing("broken")),
                Box::new(Recorder::working("working")),
            ],
            Chain::new(),
        )
        .expect("two devices");

        let written = sink.record(&entry(), 1).expect("one device accepted it");
        assert_eq!(written.failures.len(), 1);
        assert_eq!(written.failures[0].device, "broken");
        // The chain advanced, because the record is stored somewhere.
        assert_eq!(sink.next_seq(), 2);
    }

    #[test]
    fn all_devices_failing_is_fatal_and_leaves_no_gap() {
        // The fail-closed test. The caller must refuse the request, and the sequence
        // number must be reusable so that a disk error does not look like tampering.
        let mut sink = AuditSink::new(
            vec![
                Box::new(Recorder::failing("a")),
                Box::new(Recorder::failing("b")),
            ],
            Chain::new(),
        )
        .expect("two devices");

        let error = sink.record(&entry(), 1).expect_err("must fail closed");
        match error {
            AuditError::AllDevicesFailed { failures } => {
                assert_eq!(failures.len(), 2);
            }
            other => panic!("expected AllDevicesFailed, got {other}"),
        }

        assert_eq!(sink.next_seq(), 1, "the sequence number must be reused");
        assert_eq!(sink.head_hash(), Chain::new().head_hash());
    }

    #[test]
    fn a_recovered_device_continues_the_chain_without_a_gap() {
        let mut sink =
            AuditSink::new(vec![Box::new(Recorder::failing("a"))], Chain::new()).expect("one");
        assert!(sink.record(&entry(), 1).is_err());

        // Replace the failing device with a working one, as a restart would.
        let mut sink =
            AuditSink::new(vec![Box::new(Recorder::working("a"))], Chain::new()).expect("one");
        let written = sink.record(&entry(), 2).expect("write");
        assert_eq!(written.seq, 1, "no sequence number was burned");
    }
}
