//! Flow S's verdict: one type, written into `kad-dialed-link-verdict.toml` and
//! read back from it, so a wrapper scores a run by the spelling the run wrote.

use super::HelperLinks;

/// What a run saw, gathered before it is judged.
pub(super) struct Facts<'a> {
    /// The sharing helper's address.
    pub(super) helper_ip: &'a str,
    /// The sharing helper's links with rmule.
    pub(super) dialed: HelperLinks,
    /// The plain helper's links with rmule.
    pub(super) plain: HelperLinks,
    /// rmule's trace handed an ack to the Kad node off the helper's listener port.
    pub(super) trace_ack_from_listener_port: bool,
    /// rmule's TCP verdict reached Open (recorded, not gated).
    pub(super) tcp_open: bool,
}

/// How a flow S run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialedLinkVerdict {
    /// The sharing helper acked on the link rmule dialed, opened no
    /// connect-back, and rmule's trace shows the ack reaching its Kad node.
    Pass,
    /// The topology stood up (rmule dialed the helper) and the claims fell
    /// short of a pass: the counts beside the label say which.
    Observed,
    /// rmule never dialed the sharing helper.
    Fail,
}

impl DialedLinkVerdict {
    /// The verdict of a run from what it saw.
    pub(super) fn judge(facts: &Facts<'_>) -> Self {
        if facts.dialed.dialed_by_rmule == 0 {
            Self::Fail
        } else if facts.dialed.acks_on_dialed > 0
            && facts.dialed.connect_backs == 0
            && facts.trace_ack_from_listener_port
        {
            Self::Pass
        } else {
            Self::Observed
        }
    }

    /// The label the verdict file holds.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Observed => "OBSERVED",
            Self::Fail => "FAIL",
        }
    }

    /// The verdict a verdict file's text records; `None` when it holds none.
    #[must_use]
    pub fn from_verdict_file(text: &str) -> Option<Self> {
        let label = text
            .lines()
            .find_map(|line| line.strip_prefix("verdict = \""))?
            .strip_suffix('"')?;
        [Self::Pass, Self::Observed, Self::Fail]
            .into_iter()
            .find(|verdict| verdict.label() == label)
    }
}

impl Facts<'_> {
    /// The verdict file's text for `verdict`.
    pub(super) fn file_text(&self, verdict: DialedLinkVerdict) -> String {
        let mut text = String::from(
            "# Flow S - a Kad TCP check concluding through a link rmule dialed. The wire\n\
             # counts come from each helper's own tap; the two booleans from rmule's trace.\n",
        );
        text.push_str(&format!("verdict = \"{}\"\n", verdict.label()));
        text.push_str(&format!("sharing_helper = \"{}\"\n", self.helper_ip));
        text.push_str(&format!(
            "rmule_trace_ack_from_listener_port = {}\n",
            self.trace_ack_from_listener_port
        ));
        text.push_str(&format!("rmule_tcp_open = {}\n", self.tcp_open));
        for (name, links) in [
            ("sharing-helper", self.dialed),
            ("plain-helper", self.plain),
        ] {
            text.push_str(&format!("\n[{name}]\n"));
            text.push_str(&format!(
                "links_dialed_by_rmule = {}\n",
                links.dialed_by_rmule
            ));
            text.push_str(&format!(
                "acks_on_dialed_links = {}\n",
                links.acks_on_dialed
            ));
            text.push_str(&format!("connect_back_links = {}\n", links.connect_backs));
            text.push_str(&format!(
                "acks_on_connect_back_links = {}\n",
                links.acks_on_connect_back
            ));
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(dialed: HelperLinks, trace: bool, open: bool) -> Facts<'static> {
        Facts {
            helper_ip: "203.0.113.3",
            dialed,
            plain: HelperLinks::default(),
            trace_ack_from_listener_port: trace,
            tcp_open: open,
        }
    }

    const ACKED: HelperLinks = HelperLinks {
        dialed_by_rmule: 1,
        acks_on_dialed: 1,
        connect_backs: 0,
        acks_on_connect_back: 0,
    };

    #[test]
    fn the_ack_must_ride_the_dialed_link_and_be_acted_on() {
        assert_eq!(
            DialedLinkVerdict::judge(&facts(ACKED, true, false)),
            DialedLinkVerdict::Pass
        );
        let connected_back = HelperLinks {
            connect_backs: 1,
            ..ACKED
        };
        assert_eq!(
            DialedLinkVerdict::judge(&facts(connected_back, true, true)),
            DialedLinkVerdict::Observed
        );
        // The ack on the wire without rmule's trace of it is the dropped ack.
        assert_eq!(
            DialedLinkVerdict::judge(&facts(ACKED, false, true)),
            DialedLinkVerdict::Observed
        );
        assert_eq!(
            DialedLinkVerdict::judge(&facts(HelperLinks::default(), false, false)),
            DialedLinkVerdict::Fail
        );
    }

    #[test]
    fn a_verdict_file_is_read_by_the_label_it_was_written_with() {
        let text = facts(ACKED, true, true).file_text(DialedLinkVerdict::Pass);
        assert_eq!(
            DialedLinkVerdict::from_verdict_file(&text),
            Some(DialedLinkVerdict::Pass)
        );
    }
}
