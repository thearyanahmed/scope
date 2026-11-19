use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Cooperative cancellation shared by every source thread.
#[derive(Debug, Clone, Default)]
pub struct StopToken(Arc<(Mutex<bool>, Condvar)>);

impl StopToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stop(&self) {
        let (m, cv) = &*self.0;
        *m.lock().unwrap_or_else(|e| e.into_inner()) = true;
        cv.notify_all();
    }

    pub fn is_stopped(&self) -> bool {
        *self.0.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sleep up to `d`. Returns false if stopped (before or during the sleep).
    pub fn sleep(&self, d: Duration) -> bool {
        let (m, cv) = &*self.0;
        let deadline = Instant::now() + d;
        let mut stopped = m.lock().unwrap_or_else(|e| e.into_inner());
        while !*stopped {
            let now = Instant::now();
            if now >= deadline {
                return true;
            }
            stopped = cv.wait_timeout(stopped, deadline - now).unwrap_or_else(|e| e.into_inner()).0;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_wakes_sleeper() {
        let t = StopToken::new();
        let t2 = t.clone();
        let h = std::thread::spawn(move || t2.sleep(Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(20));
        t.stop();
        assert!(!h.join().unwrap());
        assert!(t.is_stopped());
    }

    #[test]
    fn sleep_times_out() {
        assert!(StopToken::new().sleep(Duration::from_millis(5)));
    }
}
