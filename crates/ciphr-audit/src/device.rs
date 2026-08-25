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
//! # Partial failure, and why a device is then stopped
//!
//! If one device of two fails, the record is still written by the other and the request
//! proceeds. The failure is reported in the outcome, so a caller can surface it — a
//! second device that has been failing for a month is a second device that does not
//! exist.
//!
//! **The device that failed is then quarantined and written to no more.** Finding F6 of
//! the review of 2026-08-24. The chain is shared and the devices are not: when one device
//! misses a committed record, the next record it *does* accept carries a `prev_hash`
//! naming a record that is not in it. That file no longer verifies, and what it looks
//! like is a trail somebody edited — produced by a disk that was briefly full.
//!
//! Quarantine trades one property for another and it is worth being explicit about
//! which. A quarantined device stops gaining history, so its copy is incomplete. What it
//! keeps is the property that makes a copy worth having: everything in it verifies, end
//! to end, and where it stops is visible. An incomplete trail that says so beats a
//! complete-looking one that cannot be checked.
//!
//! Quarantine happens **after** the chain advances, never before. If no device accepted
//! the record the chain does not advance, nothing was committed, and nobody missed
//! anything — so a total outage quarantines nothing and the service recovers on its own.
//!
//! # Restart does not undo it
//!
//! A quarantine held only in memory would be lifted by the restart an operator performs
//! *because* a device failed, and the first record after that restart would splice the
//! file exactly as before. So [`AuditSink::new`] asks every device where it thinks it is
//! and compares that with the chain: a device holding records but standing behind the
//! chain head has missed some, and starts quarantined.
//!
//! An **empty** device is not quarantined. That is the ordinary state after a log
//! rotation or `ciphr audit cut`, and it is also the documented way back: archive what
//! the device holds, and it begins a new segment whose first record names a `prev_hash`
//! the archive explains.

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

    /// The sequence number of the last record this device holds.
    ///
    /// `Ok(None)` means the device holds nothing — a fresh file, or one that rotation
    /// has moved away. `Err` means the device cannot say, which is not the same answer
    /// and is not treated as one: the sink leaves such a device alone rather than
    /// guessing it is in sync or guessing it is not.
    ///
    /// Used once, at startup, to find a device that missed records while the process was
    /// not running — or while an earlier process was. See the module documentation.
    ///
    /// # Errors
    ///
    /// Any failure, described as a string.
    fn head_seq(&self) -> Result<Option<u64>, String>;

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
    /// Devices this record put into quarantine. Empty in the normal case.
    ///
    /// A device appears here exactly once, on the record it missed. Afterwards it is in
    /// [`AuditSink::quarantined`] and is not written to again.
    pub quarantined: Vec<Quarantined>,
}

/// Why a device stopped being written to, and where it stopped.
///
/// Carries no path and no operating-system error. A device name and two sequence numbers
/// are what a reader of `/v1/health` may have; the reason the device gave belongs in the
/// process log, which is the same rule the failure reasons already follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quarantined {
    /// The device's name.
    pub device: String,
    /// The last sequence number it is known to hold, if it holds anything.
    pub last_held: Option<u64>,
    /// The first sequence number it is known to have missed.
    pub missed_from: u64,
}

/// One device and whether the sink is still writing to it.
struct Slot {
    device: Box<dyn AuditDevice>,
    /// Set once the device has missed a committed record. Never cleared while this
    /// process runs: there is no way back that does not involve somebody looking at the
    /// file.
    quarantined: Option<Quarantined>,
}

/// Writes every record to every configured device, and owns the chain.
///
/// The chain lives here rather than in a device so that all devices record the same
/// history. Two devices with independent chains would produce two sequences that
/// cannot be compared, which is most of the value of having a second one.
pub struct AuditSink {
    slots: Vec<Slot>,
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

        // Where the chain says the last record was. `next_seq` is what the *next* record
        // gets, so the head is one below it, and zero means nothing has been recorded.
        let head = chain.next_seq().saturating_sub(1);

        let slots = devices
            .into_iter()
            .map(|device| {
                let quarantined = match device.head_seq() {
                    // Holds records, and stands somewhere other than the chain head. It
                    // missed what happened in between -- or, if it is ahead, the chain
                    // did, which is what restoring an older store beside a live audit
                    // file looks like. Both are a disagreement about history, and this
                    // process may not write into it.
                    Ok(Some(seq)) if seq != head => Some(Quarantined {
                        device: device.name().to_owned(),
                        last_held: Some(seq),
                        missed_from: seq.saturating_add(1),
                    }),
                    // Two different facts, one decision.
                    //
                    // `Ok(None)` -- in step, or empty. Empty is the ordinary state after
                    // a rotation or `ciphr audit cut`, and it is the way back from a
                    // quarantine: what the device held is archived, and it starts a new
                    // segment.
                    //
                    // `Err` -- it cannot say. A device that does not know where it is has
                    // not been shown to have missed anything, and stopping it on a shrug
                    // would make an unreadable file worse than a corrupt one.
                    Ok(_) | Err(_) => None,
                };
                Slot {
                    device,
                    quarantined,
                }
            })
            .collect();

        Ok(Self { slots, chain })
    }

    /// Every device that is not being written to, and where each one stopped.
    ///
    /// Empty in the ordinary case. Non-empty means the deployment has fewer copies of
    /// its trail than its configuration says, which is a thing to page somebody about
    /// rather than a thing to notice at the next audit.
    pub fn quarantined(&self) -> Vec<Quarantined> {
        self.slots
            .iter()
            .filter_map(|slot| slot.quarantined.clone())
            .collect()
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
    ///
    /// Every configured device, quarantined or not. A device that vanished from this
    /// list when it stopped accepting records would be a device nobody notices is gone.
    pub fn device_names(&self) -> Vec<&str> {
        self.slots.iter().map(|slot| slot.device.name()).collect()
    }

    /// Record an entry.
    ///
    /// Called **before** the response is produced, never after: an entry written
    /// afterwards is an entry that a crash in between turns into an unlogged access.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::AllDevicesFailed`] if no device accepted the record — or
    /// if every device is quarantined, which is the same situation reached by a
    /// different route and gets the same answer. The chain does not advance in that
    /// case, so the sequence number is reused by the next attempt and no gap appears: a
    /// gap is indistinguishable from a deleted entry, and an audit trail that cries
    /// tampering after a disk error is one nobody will trust.
    ///
    /// A device that fails here is quarantined, **after** the chain advances. See the
    /// module documentation for what that trades and why.
    pub fn record(&mut self, entry: &Entry, now_millis: i64) -> Result<Written, AuditError> {
        let record = self.chain.encode(entry, now_millis)?;

        let mut failures = Vec::new();
        let mut attempted = 0usize;
        for slot in &mut self.slots {
            if slot.quarantined.is_some() {
                continue;
            }
            attempted += 1;
            if let Err(reason) = slot.device.write(&record) {
                failures.push(DeviceFailure {
                    device: slot.device.name().to_owned(),
                    reason,
                });
            }
        }

        // Nothing was stored, by either route: every device refused, or there was no
        // device left to ask. Quarantining every device is fail-closed and not a quiet
        // downgrade to running without a trail.
        if attempted == 0 || failures.len() == attempted {
            return Err(AuditError::AllDevicesFailed { failures });
        }

        // Committed. From here the record is part of the history, so a device that
        // refused it has missed something and may not write the next one after it.
        self.chain.commit(&record);

        let mut quarantined = Vec::new();
        for slot in &mut self.slots {
            if slot.quarantined.is_some() {
                continue;
            }
            let name = slot.device.name();
            if failures.iter().any(|failure| failure.device == name) {
                let stopped = Quarantined {
                    device: name.to_owned(),
                    last_held: record.seq.checked_sub(1),
                    missed_from: record.seq,
                };
                quarantined.push(stopped.clone());
                slot.quarantined = Some(stopped);
            }
        }

        Ok(Written {
            seq: record.seq,
            hash: record.hash,
            failures,
            quarantined,
        })
    }

    /// Ask every device to reopen its underlying resource.
    ///
    /// Failures are collected rather than returned early: one device failing to
    /// reopen must not stop the others from doing so.
    /// A quarantined device is asked too, and that is deliberate: rotation is how a
    /// device is emptied, and an emptied device is what the next start can let back in.
    /// Refusing to reopen it would make the way back need a stopped service.
    pub fn reopen(&mut self) -> Vec<DeviceFailure> {
        let mut failures = Vec::new();
        for slot in &mut self.slots {
            if let Err(reason) = slot.device.reopen() {
                failures.push(DeviceFailure {
                    device: slot.device.name().to_owned(),
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

        /// What this double has actually stored, which is what a real device reports.
        fn head_seq(&self) -> Result<Option<u64>, String> {
            Ok(self.stored.last().map(|record| record.seq))
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

    /// A device that stores records and can be made to fail from a chosen point on.
    struct Flaky {
        name: &'static str,
        fail_from: Option<u64>,
        stored: Vec<EncodedRecord>,
    }

    impl Flaky {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                fail_from: None,
                stored: Vec::new(),
            }
        }
    }

    impl AuditDevice for Flaky {
        fn name(&self) -> &str {
            self.name
        }

        fn head_seq(&self) -> Result<Option<u64>, String> {
            Ok(self.stored.last().map(|record| record.seq))
        }

        fn write(&mut self, record: &EncodedRecord) -> Result<(), String> {
            if self.fail_from.is_some_and(|from| record.seq >= from) {
                return Err("the volume is full".to_owned());
            }
            self.stored.push(record.clone());
            Ok(())
        }
    }

    /// A device that cannot say where it is.
    struct Mute;

    impl AuditDevice for Mute {
        fn name(&self) -> &'static str {
            "mute"
        }

        fn head_seq(&self) -> Result<Option<u64>, String> {
            Err("this device cannot report a head".to_owned())
        }

        fn write(&mut self, _record: &EncodedRecord) -> Result<(), String> {
            Ok(())
        }
    }

    /// The heart of F6: a device that misses a committed record is not written to again.
    ///
    /// Before this, it kept being written to — and the next record it accepted carried a
    /// `prev_hash` naming a record that is not in that file. The file then fails to
    /// verify at that point, permanently, and what it looks like is an edited trail. It
    /// was produced by a disk that was briefly full.
    #[test]
    fn a_device_that_misses_a_record_is_quarantined_and_not_written_to_again() {
        let a = Flaky::new("a");
        let mut b = Flaky::new("b");
        b.fail_from = Some(2);
        let mut sink = AuditSink::new(vec![Box::new(a), Box::new(b)], Chain::new()).expect("sink");

        // One record both devices take.
        let first = sink.record(&entry(), 1).expect("first");
        assert!(first.failures.is_empty());
        assert!(first.quarantined.is_empty());

        // The second is refused by `b`, stored by `a`, and the chain advances.
        let second = sink.record(&entry(), 2).expect("second");
        assert_eq!(second.failures.len(), 1, "one device refused");
        assert_eq!(second.quarantined.len(), 1, "and is stopped for it");
        assert_eq!(second.quarantined[0].device, "b");
        assert_eq!(
            second.quarantined[0].last_held,
            Some(1),
            "it holds everything up to the record before the one it missed"
        );
        assert_eq!(second.quarantined[0].missed_from, 2);

        // The third is not offered to `b` at all, so it does not appear as a failure
        // either -- which is the difference between a device that refuses and a device
        // nobody is asking.
        let third = sink.record(&entry(), 3).expect("third");
        assert!(
            third.failures.is_empty(),
            "a quarantined device is not asked, so it cannot fail"
        );
        assert!(
            third.quarantined.is_empty(),
            "and it is reported as newly quarantined exactly once"
        );

        let stopped = sink.quarantined();
        assert_eq!(stopped.len(), 1);
        assert_eq!(stopped[0].device, "b");
    }

    /// A total failure quarantines nobody, because nothing was committed.
    ///
    /// The ordering that makes this work: the chain advances *before* the quarantine
    /// decision, so a record no device stored is a record no device missed. Without it, a
    /// full disk that comes back would leave every device stopped and the service dead
    /// until somebody restarted it -- turning a transient outage into an incident.
    #[test]
    fn a_record_nobody_stored_quarantines_nobody() {
        let mut a = Flaky::new("a");
        let mut b = Flaky::new("b");
        a.fail_from = Some(1);
        b.fail_from = Some(1);
        let mut sink = AuditSink::new(vec![Box::new(a), Box::new(b)], Chain::new()).expect("sink");

        assert!(matches!(
            sink.record(&entry(), 1),
            Err(AuditError::AllDevicesFailed { .. })
        ));
        assert!(
            sink.quarantined().is_empty(),
            "nothing was committed, so nothing was missed"
        );

        // And the sequence number was not consumed, so the retry is record one.
        assert_eq!(sink.next_seq(), 1);
    }

    /// The last device standing is never quarantined, because its failure is a total
    /// failure.
    ///
    /// This falls out of the ordering rather than being a rule of its own, and it is the
    /// reason quarantine cannot walk a deployment down to no devices one failure at a
    /// time. When only one device is left, its refusal means nothing was committed, so
    /// the chain does not advance and there is nothing for it to have missed: the request
    /// is refused, fail-closed, and the device stays eligible for the next attempt.
    #[test]
    fn the_last_device_standing_is_refused_rather_than_quarantined() {
        let mut a = Flaky::new("a");
        let mut b = Flaky::new("b");
        a.fail_from = Some(2);
        b.fail_from = Some(3);
        let mut sink = AuditSink::new(vec![Box::new(a), Box::new(b)], Chain::new()).expect("sink");

        sink.record(&entry(), 1).expect("both take the first");
        sink.record(&entry(), 2)
            .expect("b takes the second, a is stopped");

        // `b` is now alone, and refuses. Nothing is stored, so the request fails.
        assert!(matches!(
            sink.record(&entry(), 3),
            Err(AuditError::AllDevicesFailed { .. })
        ));
        assert_eq!(
            sink.quarantined().len(),
            1,
            "still only `a`: `b` refused a record that was never committed"
        );
        assert_eq!(
            sink.next_seq(),
            3,
            "and the sequence number was not consumed"
        );

        // Still listed. A device that vanished from the inventory when it stopped
        // accepting records is a device nobody notices is gone.
        assert_eq!(sink.device_names().len(), 2);
    }

    /// A sink whose every device is quarantined at startup refuses rather than serving.
    ///
    /// Reachable only through the startup comparison — two devices that both fell behind
    /// while this process was not running — because a write failure can never stop the
    /// last one. Fail-closed either way: running with no device to write to would be
    /// running with no audit trail, which is the one thing this crate exists to prevent.
    #[test]
    fn every_device_quarantined_at_startup_refuses_to_record() {
        let mut chain = Chain::new();
        for at in 1..=2i64 {
            let record = chain.encode(&entry(), at).expect("encode");
            chain.commit(&record);
        }

        // Neither device holds anything past the first record, and the chain is at two.
        let mut a = Flaky::new("a");
        let mut b = Flaky::new("b");
        let seeding = Chain::new();
        let first = seeding.encode(&entry(), 1).expect("encode");
        a.write(&first).expect("a takes the first");
        b.write(&first).expect("b takes the first");

        let mut sink = AuditSink::new(
            vec![Box::new(a), Box::new(b)],
            Chain::resume(2, chain.head_hash()),
        )
        .expect("sink");

        assert_eq!(sink.quarantined().len(), 2);
        assert!(
            matches!(
                sink.record(&entry(), 3),
                Err(AuditError::AllDevicesFailed { .. })
            ),
            "no device left to write to is the same answer as every device refusing"
        );
    }

    /// A device standing behind the chain starts quarantined, so a restart does not
    /// undo the protection.
    ///
    /// This is the half that matters most in practice: the operator's first response to a
    /// failing device is to restart the service, and an in-memory quarantine would be
    /// lifted by exactly that action — the first record after the restart splicing the
    /// file just as before.
    #[test]
    fn a_device_behind_the_chain_starts_quarantined() {
        let mut behind = Flaky::new("behind");
        let mut current = Flaky::new("current");

        // Give both a shared history, then let one fall behind, the way a process that
        // has already exited would have left them.
        let mut chain = Chain::new();
        for at in 1..=3i64 {
            let record = chain.encode(&entry(), at).expect("encode");
            current.write(&record).expect("current takes it");
            if at < 3 {
                behind.write(&record).expect("behind takes the first two");
            }
            chain.commit(&record);
        }

        let sink = AuditSink::new(
            vec![Box::new(behind), Box::new(current)],
            Chain::resume(3, chain.head_hash()),
        )
        .expect("sink");

        let stopped = sink.quarantined();
        assert_eq!(stopped.len(), 1, "only the one that fell behind");
        assert_eq!(stopped[0].device, "behind");
        assert_eq!(stopped[0].last_held, Some(2));
        assert_eq!(stopped[0].missed_from, 3);
    }

    /// An empty device is not quarantined, because that is what rotation leaves behind.
    ///
    /// The way back from a quarantine, and the reason it is not a dead end: archive what
    /// the device holds, and it starts a new segment. Quarantining an empty device would
    /// break every deployment that rotates its audit file, which is all of them that run
    /// long enough.
    #[test]
    fn an_empty_device_beside_a_running_chain_is_not_quarantined() {
        let fresh = Flaky::new("fresh");
        let mut chain = Chain::new();
        let record = chain.encode(&entry(), 1).expect("encode");
        chain.commit(&record);

        let sink = AuditSink::new(vec![Box::new(fresh)], Chain::resume(1, chain.head_hash()))
            .expect("sink");
        assert!(sink.quarantined().is_empty());
    }

    /// A device that cannot report a head is left alone rather than guessed about.
    #[test]
    fn a_device_that_cannot_report_its_head_is_not_quarantined() {
        let mut chain = Chain::new();
        let record = chain.encode(&entry(), 1).expect("encode");
        chain.commit(&record);

        let sink = AuditSink::new(vec![Box::new(Mute)], Chain::resume(1, chain.head_hash()))
            .expect("sink");
        assert!(
            sink.quarantined().is_empty(),
            "not shown to have missed anything is not the same as shown to be in step"
        );
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
