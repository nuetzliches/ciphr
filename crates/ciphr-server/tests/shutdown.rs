//! Which signals ask the server to stop.
//!
//! Unix only, and its own test binary on purpose. The claim can only be checked by
//! raising a real signal, and a signal with no handler terminates the process it is
//! raised in — which is exactly the defect this guards against. Alone in a binary, a
//! regression costs these two tests; sharing one, it would cost every result in it.
//!
//! What was wrong before: the graceful shutdown awaited `tokio::signal::ctrl_c`, which
//! on Unix is SIGINT and nothing else, while a container runtime stops a service with
//! SIGTERM. `docker-entrypoint.sh` `exec`s the binary specifically so that signal
//! arrives at the process rather than at a shell — and then nothing was listening for
//! it.

#![cfg(unix)]

use std::time::Duration;

use tokio::signal::unix::{SignalKind, signal};

/// Raise a signal at this process, without a dependency for it.
///
/// `sh -c 'kill …'` rather than `libc::raise`: there is no way to do this from `std`,
/// and a C library in the dependency graph of a service that reads every secret in a
/// deployment is not worth one test's convenience.
fn raise(signal_name: &str) {
    let pid = std::process::id();
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("kill -{signal_name} {pid}"))
        .status()
        .expect("run kill");
    assert!(status.success(), "kill -{signal_name} must succeed");
}

/// Wait for `stop_requested` to complete while raising `signal_name` until it does.
///
/// Repeated rather than sent once after a sleep, because the two orderings have very
/// different costs: a signal sent before the function under test has registered its
/// stream is simply consumed by the guard the caller holds, so retrying costs a
/// millisecond — whereas a sleep long enough to make that impossible is a guess that
/// gets shorter every time the machine gets busier.
async fn stops_on(signal_name: &str) -> bool {
    let waiting = tokio::spawn(ciphr_server::server::stop_requested());
    tokio::pin!(waiting);

    for _ in 0..50 {
        raise(signal_name);
        match tokio::time::timeout(Duration::from_millis(100), &mut waiting).await {
            Ok(joined) => return joined.expect("the task did not panic"),
            Err(_) => continue,
        }
    }
    panic!("stop_requested did not complete after 50 {signal_name} signals");
}

#[tokio::test]
async fn sigterm_asks_the_server_to_stop() {
    // Registered here, before anything is raised, so that a signal arriving ahead of
    // the registration inside `stop_requested` cannot terminate this process. tokio
    // delivers a signal to every stream registered for it, so this observes rather
    // than intercepts — the function under test still does its own registration and
    // still has to receive the signal on its own stream.
    let _guard = signal(SignalKind::terminate()).expect("register SIGTERM");

    assert!(
        stops_on("TERM").await,
        "SIGTERM is how a container runtime stops a service; it has to reach the graceful shutdown"
    );
}

#[tokio::test]
async fn sigint_still_asks_the_server_to_stop() {
    // The other half of the claim, and the reason this is two tests rather than one:
    // the fix must not become "SIGTERM instead of SIGINT". A person with the process
    // in the foreground presses Ctrl-C, and that must keep working.
    let _guard = signal(SignalKind::interrupt()).expect("register SIGINT");

    assert!(
        stops_on("INT").await,
        "Ctrl-C must still stop the server gracefully"
    );
}
