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

/// Install process signal handlers that mark shutdown requested.
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

#[cfg(windows)]
unsafe fn install_windows_handlers() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

    unsafe extern "system" fn handle(ctrl_type: u32) -> windows_sys::core::BOOL {
        const CTRL_C_EVENT: u32 = 0;
        const CTRL_BREAK_EVENT: u32 = 1;
        const CTRL_CLOSE_EVENT: u32 = 2;
        const CTRL_LOGOFF_EVENT: u32 = 5;
        const CTRL_SHUTDOWN_EVENT: u32 = 6;

        if matches!(
            ctrl_type,
            CTRL_C_EVENT
                | CTRL_BREAK_EVENT
                | CTRL_CLOSE_EVENT
                | CTRL_LOGOFF_EVENT
                | CTRL_SHUTDOWN_EVENT
        ) {
            SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
            1
        } else {
            0
        }
    }

    let _ = SetConsoleCtrlHandler(Some(handle), 1);
}

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
