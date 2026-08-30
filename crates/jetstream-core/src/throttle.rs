//! Rate limiting for transfers.
//!
//! Cheap to implement here for one reason: **the receiver drives the transfer.**
//! It decides when to ask for the next chunk, so slowing down is a matter of
//! asking less often. There is no protocol change, no negotiation, and nothing
//! the sender has to agree to — a sender simply receives fewer requests. It also
//! cannot desync, because there is no shared rate state to disagree about.
//!
//! A token bucket rather than a fixed sleep between chunks. Sleeping a computed
//! interval per chunk sounds equivalent and is not: it turns every scheduling
//! hiccup into permanent lost throughput, because time spent over the interval is
//! never made up. A bucket accumulates allowance while nothing is being read, so
//! a transfer that stalls briefly catches back up to its average instead of
//! drifting below the limit the user set.

use std::sync::Mutex;
use std::time::Duration;

// The runtime's clock, not the system one. Identical in production, and it is
// what makes a rate limiter testable at all: `tokio::time` can advance time
// instantly under `start_paused`, so a test can measure a ten-second average
// without taking ten seconds. With `std::time::Instant` the bucket would refill
// against real time while the sleeps returned immediately, and every test would
// measure an unlimited transfer.
use tokio::time::Instant;

/// How much allowance may accumulate while idle, as a multiple of the limit.
///
/// One second's worth. Enough to smooth over scheduler jitter and a slow disk
/// read, small enough that a transfer resuming after a long pause cannot burst
/// megabytes at once and briefly saturate a link the user was protecting.
const BURST_SECONDS: f64 = 1.0;

/// A byte-rate limit, or no limit at all.
///
/// The limit lives behind a lock rather than being fixed at construction so it
/// can be changed *during* a transfer — which is the interesting case. A user who
/// needs the network back should not have to stop a two-hour copy and start it
/// again to slow it down.
#[derive(Debug, Default)]
pub struct Throttle {
    state: Mutex<Option<Bucket>>,
}

#[derive(Debug)]
struct Bucket {
    /// Bytes per second.
    rate: f64,
    /// Bytes currently allowed.
    allowance: f64,
    last: Instant,
}

impl Throttle {
    /// No limit. Every call to [`Throttle::take`] returns immediately.
    pub fn unlimited() -> Self {
        Self::default()
    }

    /// Limit to `bytes_per_second`. Zero means unlimited, because a limit of zero
    /// would stall the transfer for ever, and "0" is what an empty input field
    /// produces.
    pub fn per_second(bytes_per_second: u64) -> Self {
        let throttle = Self::default();
        throttle.set(bytes_per_second);
        throttle
    }

    /// Change the limit, including while a transfer is running.
    ///
    /// Raising or clearing the limit takes effect at the next chunk. Lowering it
    /// keeps whatever allowance had accumulated, so the transfer eases down to the
    /// new rate rather than stopping dead for a second.
    pub fn set(&self, bytes_per_second: u64) {
        let mut state = self.state.lock().expect("throttle poisoned");

        if bytes_per_second == 0 {
            *state = None;
            return;
        }

        let rate = bytes_per_second as f64;
        match state.as_mut() {
            Some(bucket) => {
                bucket.rate = rate;
                bucket.allowance = bucket.allowance.min(rate * BURST_SECONDS);
            }
            None => {
                *state = Some(Bucket {
                    rate,
                    // Starts empty rather than full: a transfer should approach
                    // its limit from below, not open with a burst.
                    allowance: 0.0,
                    last: Instant::now(),
                });
            }
        }
    }

    pub fn is_limited(&self) -> bool {
        self.state.lock().expect("throttle poisoned").is_some()
    }

    /// The limit in bytes per second, if there is one.
    pub fn limit(&self) -> Option<u64> {
        self.state
            .lock()
            .expect("throttle poisoned")
            .as_ref()
            .map(|bucket| bucket.rate as u64)
    }

    /// Wait until `bytes` may be transferred, then account for them.
    ///
    /// Returns how long it waited, which is only of interest to tests.
    ///
    /// A request larger than one second's allowance is permitted rather than
    /// rejected — it simply waits longer. Refusing it would deadlock a 1 MiB
    /// chunk against a 100 KB/s limit, which is a configuration a user is
    /// entitled to set.
    pub async fn take(&self, bytes: u64) -> Duration {
        let wait = {
            let mut state = self.state.lock().expect("throttle poisoned");
            match state.as_mut() {
                Some(bucket) => {
                    bucket.refill();
                    bucket.reserve(bytes)
                }
                None => Duration::ZERO,
            }
        };

        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        wait
    }
}

impl Bucket {
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;

        let ceiling = self.rate * BURST_SECONDS;
        self.allowance = (self.allowance + elapsed * self.rate).min(ceiling);
    }

    /// Spend `bytes`, returning how long the caller must wait first.
    fn reserve(&mut self, bytes: u64) -> Duration {
        let bytes = bytes as f64;
        self.allowance -= bytes;

        if self.allowance >= 0.0 {
            return Duration::ZERO;
        }

        // Allowance is now negative: that debt is exactly the time to wait, and
        // leaving it negative is what makes the average come out right rather
        // than resetting and losing the remainder.
        Duration::from_secs_f64(-self.allowance / self.rate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unlimited_throttle_never_waits() {
        let throttle = Throttle::unlimited();
        assert!(!throttle.is_limited());
        assert_eq!(throttle.limit(), None);

        for _ in 0..1000 {
            assert_eq!(throttle.take(1_048_576).await, Duration::ZERO);
        }
    }

    #[tokio::test]
    async fn a_zero_limit_means_unlimited_rather_than_stalled() {
        // An empty input box produces 0, and a transfer that never moves again
        // would be a far worse reading of that than "no limit".
        let throttle = Throttle::per_second(0);
        assert!(!throttle.is_limited());
        assert_eq!(throttle.take(1_048_576).await, Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn the_average_rate_converges_on_the_limit() {
        // 1 MB/s, spent in 64 KB requests. Ten seconds of allowance should carry
        // very close to ten megabytes and no more.
        let throttle = Throttle::per_second(1_000_000);
        let start = Instant::now();

        let mut moved = 0u64;
        while start.elapsed() < Duration::from_secs(10) {
            throttle.take(64_000).await;
            moved += 64_000;
        }

        let seconds = start.elapsed().as_secs_f64();
        let rate = moved as f64 / seconds;
        assert!(
            (rate - 1_000_000.0).abs() < 100_000.0,
            "averaged {rate:.0} B/s against a 1 MB/s limit"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_larger_than_the_burst_still_completes() {
        // 1 MiB chunk against a 100 KB/s limit: it must wait, not deadlock.
        let throttle = Throttle::per_second(100_000);
        let waited = throttle.take(1_048_576).await;

        assert!(
            waited >= Duration::from_secs(10),
            "a 1 MiB chunk at 100 KB/s should wait about ten seconds, waited {waited:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn idle_time_accumulates_allowance_but_is_capped() {
        let throttle = Throttle::per_second(1_000_000);

        // Idle far longer than the burst window.
        tokio::time::sleep(Duration::from_secs(60)).await;

        // One second's worth should pass freely...
        assert_eq!(throttle.take(1_000_000).await, Duration::ZERO);
        // ...and the next second's worth must not, or a long pause would let a
        // transfer burst a minute of data in one go.
        assert!(throttle.take(1_000_000).await > Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_limit_can_be_raised_and_cleared_mid_transfer() {
        // The point of a settable limit: a two-hour copy should not have to be
        // stopped and started again to be slowed down or let loose.
        let throttle = Throttle::per_second(100_000);
        assert!(throttle.take(200_000).await > Duration::ZERO);

        throttle.set(0);
        assert!(!throttle.is_limited());
        assert_eq!(throttle.take(10_000_000).await, Duration::ZERO);

        throttle.set(50_000);
        assert_eq!(throttle.limit(), Some(50_000));
        assert!(throttle.take(200_000).await > Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn lowering_a_limit_does_not_carry_over_a_stale_allowance() {
        // A big accumulated allowance must not let a newly-lowered limit be
        // ignored for a while.
        let throttle = Throttle::per_second(10_000_000);
        tokio::time::sleep(Duration::from_secs(5)).await;

        throttle.set(100_000);
        // Allowance is now clamped to one second of the *new* rate, so a request
        // ten times that must wait.
        assert!(throttle.take(1_000_000).await > Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_request_is_not_a_free_burst() {
        // The bucket starts empty, so a transfer approaches its limit from below
        // instead of opening at full speed.
        let throttle = Throttle::per_second(1_000_000);
        assert!(throttle.take(1_000_000).await > Duration::ZERO);
    }
}
