//! Graceful process shutdown for SHPH long-running sessions.
//!
//! Installs SIGINT/SIGTERM handlers (on unix) that flip a process-wide
//! `AtomicBool`. Session loops poll `shutdown_requested()` so that Ctrl+C or a
//! service manager stop results in a clean teardown: the transport loop closes,
//! the control-plane guard rolls back, and final metrics are emitted.

use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Returns true once a shutdown signal (SIGINT/SIGTERM on unix) was received.
pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
}

/// Clears the shutdown flag. Primarily useful in tests that exercise the loop.
#[allow(dead_code)]
pub fn reset_shutdown() {
    SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
}

/// Request a shutdown programmatically (used by tests and the down path).
#[allow(dead_code)]
pub fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

/// Install SIGINT/SIGTERM handlers that mark shutdown requested.
///
/// Safe to call once at process start. On non-unix targets this is a no-op.
/// After this returns, a subsequent real signal will cause
/// `shutdown_requested()` to return true.
pub fn install_signal_handlers() {
    #[cfg(unix)]
    unsafe {
        install_unix_handlers();
    }
    #[cfg(windows)]
    unsafe {
        install_windows_handlers();
    }
}

#[cfg(unix)]
unsafe fn install_unix_handlers() {
    extern "C" fn handle(_sig: libc::c_int) {
        SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
    }

    let mut action: libc::sigaction = std::mem::zeroed();
    action.sa_sigaction = handle as *const () as usize;
    action.sa_flags = 0;
    libc::sigemptyset(&mut action.sa_mask);

    // Ignore failure: if installation fails we only lose graceful shutdown
    // and fall back to default termination; that is not fatal.
    libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
    libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
}

// NOTE: Windows graceful-shutdown via a console control handler requires
// `SetConsoleCtrlHandler`, which is a Win32 API not exposed by the `libc`
// crate. Adding a `windows-sys`/`winapi` dependency is tracked as an A.2
// follow-up so it can be compiled and verified on the Windows toolchain.
// Until then the Windows build relies on default Ctrl+C termination; the
// connect loop's stdin read still checks `shutdown_requested()` between lines.
#[cfg(windows)]
unsafe fn install_windows_handlers() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_reset_shutdown_roundtrip() {
        reset_shutdown();
        assert!(!shutdown_requested());
        request_shutdown();
        assert!(shutdown_requested());
        reset_shutdown();
        assert!(!shutdown_requested());
    }
}
