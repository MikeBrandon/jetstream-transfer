//! A transfer rate that holds still.
//!
//! The figure a person reads as "speed" has to be steady enough to read and
//! still follow the network when it really changes. Averaging the last few
//! samples got neither: whoever asked for the number decided when a sample was
//! taken, so a burst of requests squeezed the window to nothing and the speed
//! read zero, and data arriving in lumps made it flip between zero and double.
//!
//! This is an exponential moving average over *time*, not over samples. Each
//! update is weighted by how much time it covers, so it does not matter how
//! often — or how unevenly — it is asked. Updates closer together than
//! [`MIN_INTERVAL`] are ignored rather than allowed to dominate.

use std::time::{Duration, Instant};

/// How quickly the figure follows a change: about three seconds to move most of
/// the way to a new speed. Long enough to iron out lumpy arrivals, short enough
/// that unplugging a cable shows up promptly.
const TIME_CONSTANT: Duration = Duration::from_secs(3);

/// Updates closer together than this are skipped. Below it, the bytes counted in
/// one interval say more about chunk boundaries than about the network.
const MIN_INTERVAL: Duration = Duration::from_millis(200);

/// Updates needed before the figure is trusted enough to base an ETA on.
const SETTLED_AFTER: u32 = 4;

/// For this long after bytes start moving, the figure is the plain average
/// since then, over at least this long. The first interval alone is often one
/// lump of data, and starting the average from it opened every transfer on a
/// spike several times the real speed.
const WARM_UP: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Default)]
pub struct RateMeter {
    last: Option<(Instant, u64)>,
    /// The moment bytes started moving, and the count then.
    origin: Option<(Instant, u64)>,
    rate: f64,
    updates: u32,
}

impl RateMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the running count of bytes moved, as of `now`.
    ///
    /// `moved` must only ever count bytes that crossed the wire. A resume
    /// baseline — what was already there before this attempt — is not speed, and
    /// counting it produced a spike of tens of gigabytes per second on every
    /// resumed transfer.
    pub fn update(&mut self, now: Instant, moved: u64) {
        let Some((then, before)) = self.last else {
            self.last = Some((now, moved));
            return;
        };

        // Nothing has moved yet — still connecting, or waiting for the other
        // side to accept. That wait is not a speed of zero, and averaging it in
        // made the figure crawl up for several seconds once data did flow. The
        // measurement starts with the first bytes.
        if self.updates == 0 && moved == before {
            self.last = Some((now, moved));
            return;
        }

        let elapsed = now.saturating_duration_since(then);
        if elapsed < MIN_INTERVAL {
            return;
        }

        // A counter that went backwards was reset by its owner; start over from
        // here rather than reporting a negative rate.
        if moved < before {
            self.reset();
            self.last = Some((now, moved));
            return;
        }

        let (origin_at, origin_bytes) = *self.origin.get_or_insert((then, before));
        let since_origin = now.saturating_duration_since(origin_at);

        self.rate = if since_origin <= WARM_UP {
            (moved - origin_bytes) as f64 / WARM_UP.as_secs_f64()
        } else {
            let seconds = elapsed.as_secs_f64();
            let instant = (moved - before) as f64 / seconds;
            let weight = 1.0 - (-seconds / TIME_CONSTANT.as_secs_f64()).exp();
            self.rate + weight * (instant - self.rate)
        };

        self.updates += 1;
        self.last = Some((now, moved));
    }

    /// Bytes per second.
    pub fn rate(&self) -> u64 {
        // Below a byte a second is a decayed average of nothing, not a speed.
        if self.rate < 1.0 { 0 } else { self.rate as u64 }
    }

    /// Whether there have been enough updates to estimate time remaining.
    pub fn settled(&self) -> bool {
        self.updates >= SETTLED_AFTER
    }

    /// Seconds to move `remaining` bytes at the current rate, once settled.
    pub fn eta(&self, remaining: u64) -> Option<u64> {
        let rate = self.rate();
        (self.settled() && rate > 0).then(|| remaining.div_ceil(rate))
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(start: Instant, millis: u64) -> Instant {
        start + Duration::from_millis(millis)
    }

    #[test]
    fn a_steady_flow_reads_as_its_rate() {
        let start = Instant::now();
        let mut meter = RateMeter::new();

        // 10 MB/s, sampled every 250 ms.
        for step in 0..=20u64 {
            meter.update(at(start, step * 250), step * 2_500_000);
        }

        let rate = meter.rate();
        assert!((9_900_000..=10_100_000).contains(&rate), "got {rate}");
        assert!(meter.settled());
    }

    #[test]
    fn lumpy_arrivals_do_not_swing_between_zero_and_double() {
        // Eight 1 MiB chunks landing together every 1.6 s — what eight parallel
        // streams on a 5 MB/s link looked like when only whole chunks counted.
        let start = Instant::now();
        let mut meter = RateMeter::new();
        let mut moved = 0u64;
        let mut readings = Vec::new();

        for step in 0..80u64 {
            if step % 8 == 7 {
                moved += 8 * 1024 * 1024;
            }
            meter.update(at(start, step * 200), moved);
            if step > 40 {
                readings.push(meter.rate());
            }
        }

        let low = *readings.iter().min().unwrap();
        let high = *readings.iter().max().unwrap();
        assert!(low > 2_500_000, "dipped to {low} B/s — that is the 'drops to zero' bug");
        assert!(high < 9_000_000, "spiked to {high} B/s");
    }

    #[test]
    fn a_burst_of_callers_cannot_zero_the_rate() {
        let start = Instant::now();
        let mut meter = RateMeter::new();
        for step in 0..=10u64 {
            meter.update(at(start, step * 250), step * 1_000_000);
        }
        let before = meter.rate();

        // Five more asks within a few milliseconds, with nothing new moved.
        for extra in 1..=5u64 {
            meter.update(at(start, 2_500 + extra), 10_000_000);
        }
        assert_eq!(meter.rate(), before);
    }

    #[test]
    fn a_stall_decays_towards_zero_rather_than_freezing() {
        let start = Instant::now();
        let mut meter = RateMeter::new();
        for step in 0..=10u64 {
            meter.update(at(start, step * 250), step * 1_000_000);
        }
        for step in 11..=60u64 {
            meter.update(at(start, step * 250), 10_000_000);
        }
        assert!(meter.rate() < 100_000, "still claiming {} B/s", meter.rate());
    }

    #[test]
    fn waiting_before_the_start_does_not_drag_the_rate_down() {
        let start = Instant::now();
        let mut meter = RateMeter::new();

        // Five seconds waiting for the other side to accept.
        for step in 0..=20u64 {
            meter.update(at(start, step * 250), 0);
        }
        // Then 20 MB/s from the first interval on.
        for step in 1..=4u64 {
            meter.update(at(start, 5_000 + step * 250), step * 5_000_000);
        }

        let rate = meter.rate();
        assert!(rate > 19_000_000, "read {rate} B/s a second into a 20 MB/s transfer");
    }

    #[test]
    fn a_lump_at_the_start_does_not_open_on_a_spike() {
        let start = Instant::now();
        let mut meter = RateMeter::new();
        meter.update(start, 0);
        // Eight 1 MiB chunks landing together in the first 200 ms of a link
        // that averages a few MB/s.
        meter.update(at(start, 200), 8 * 1024 * 1024);

        let rate = meter.rate();
        assert!(rate < 9_000_000, "opened at {rate} B/s");
    }

    #[test]
    fn no_estimate_until_settled() {
        let start = Instant::now();
        let mut meter = RateMeter::new();
        meter.update(start, 0);
        meter.update(at(start, 250), 1_000_000);
        assert_eq!(meter.eta(10_000_000), None);
    }
}
