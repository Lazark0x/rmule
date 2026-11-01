//! The Statistics tab's words: the graphs' window, axis and key hint, and how
//! long the run has been up.

use std::time::Duration;

use crate::state::RateWindow;

/// The graph body before the first data tick. It names *why* the pane is
/// empty, so it does not read as a broken graph.
pub const NO_SAMPLES: &str = "no samples yet — one lands each second";

/// The right end of the axis on a running core.
pub const AXIS_NOW: &str = " now ";

/// The right end of the axis once the core's stream ended.
pub const AXIS_STOPPED: &str = " stopped ";

/// The key hint: the key that walks the window, and what a column is on the
/// window up.
#[must_use]
pub const fn window_hint(window: RateWindow) -> &'static str {
    match window {
        RateWindow::Seconds => " w 1 s a column ",
        RateWindow::Hours => " w 1 min a column ",
        RateWindow::Days => " w 1 h a column ",
    }
}

/// What the title calls the tallest column: a coarse column is a mean, so its
/// height is not the fastest second in it.
#[must_use]
pub const fn tallest(window: RateWindow) -> &'static str {
    match window {
        RateWindow::Seconds => "peak",
        RateWindow::Hours => "busiest minute",
        RateWindow::Days => "busiest hour",
    }
}

/// How long ago the left end of the axis is: a graph left for days reads in
/// days.
#[must_use]
pub fn axis_age(age: Duration) -> String {
    let secs = age.as_secs();
    match secs {
        0..60 => format!(" {secs}s ago "),
        60..3_600 => format!(" {}m ago ", secs / 60),
        3_600..172_800 => format!(" {}h ago ", secs / 3_600),
        _ => format!(" {}d ago ", secs / 86_400),
    }
}

/// How long the run has been up: the two largest units that say it.
#[must_use]
pub fn uptime(up: Duration) -> String {
    let secs = up.as_secs();
    let (days, hours) = (secs / 86_400, secs / 3_600 % 24);
    let (minutes, rest) = (secs / 60 % 60, secs % 60);
    match (days, hours, minutes) {
        (0, 0, 0) => format!("· up {rest}s "),
        (0, 0, _) => format!("· up {minutes}m {rest}s "),
        (0, _, _) => format!("· up {hours}h {minutes}m "),
        _ => format!("· up {days}d {hours}h "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_axis_walks_seconds_minutes_hours_and_days() {
        let reads = |secs| axis_age(Duration::from_secs(secs));
        assert_eq!(reads(59), " 59s ago ");
        assert_eq!(reads(60), " 1m ago ");
        assert_eq!(reads(3_599), " 59m ago ");
        assert_eq!(reads(3_600), " 1h ago ");
        assert_eq!(reads(47 * 3_600), " 47h ago ");
        assert_eq!(reads(48 * 3_600), " 2d ago ");
    }

    #[test]
    fn uptime_says_its_two_largest_units() {
        let reads = |secs| uptime(Duration::from_secs(secs));
        assert_eq!(reads(9), "· up 9s ");
        assert_eq!(reads(125), "· up 2m 5s ");
        assert_eq!(reads(3_660), "· up 1h 1m ");
        assert_eq!(reads(2 * 86_400 + 3 * 3_600 + 59), "· up 2d 3h ");
    }
}
