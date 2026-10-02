//! Flow R's verdict: one type, written into `kad-required-check-verdict.toml`
//! and read back from it, so a wrapper scores a run by the same spelling the
//! run wrote — including the runs already archived.

/// What rmule prints once both self-checks read open.
pub(super) const BOTH_OPEN: &str = "rmule-kad-verdicts tcp=open udp=open";
/// What rmule prints once its TCP self-check reads open, whatever UDP reads.
pub(super) const TCP_OPEN_LINE: &str = "rmule-kad-verdicts tcp=open";

/// How a flow R run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequiredCheckVerdict {
    /// Both verdicts read open.
    Pass,
    /// TCP read open; UDP stayed short (the UDP check found no helper outside
    /// rmule's routing zone).
    TcpOpen,
    /// The topology stood up (rmule serving, a helper dialed back) and TCP
    /// stayed short of open: a documented absence.
    Observed,
    /// The topology never stood up.
    Fail,
}

impl RequiredCheckVerdict {
    /// The verdict of a run from rmule's last diagnostics line (`last_verdicts`)
    /// and what the topology showed.
    pub(super) fn judge(last_verdicts: &str, serving: bool, dialed_back: bool) -> Self {
        if last_verdicts == BOTH_OPEN {
            Self::Pass
        } else if last_verdicts.starts_with(TCP_OPEN_LINE) {
            Self::TcpOpen
        } else if serving && dialed_back {
            Self::Observed
        } else {
            Self::Fail
        }
    }

    /// The label the verdict file holds; archived runs hold the same four.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::TcpOpen => "TCP_OPEN",
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
        [Self::Pass, Self::TcpOpen, Self::Observed, Self::Fail]
            .into_iter()
            .find(|verdict| verdict.label() == label)
    }

    /// Whether rmule's TCP self-check read open: the gate of flow R.
    #[must_use]
    pub const fn tcp_open(self) -> bool {
        matches!(self, Self::Pass | Self::TcpOpen)
    }

    /// The verdict file's line for this verdict.
    pub(super) fn file_line(self) -> String {
        format!("verdict = \"{}\"\n", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four labels are what runs archived before the type existed.
    #[test]
    fn a_verdict_file_is_read_by_the_labels_archived_runs_hold() {
        for (text, verdict) in [
            ("verdict = \"PASS\"\n", RequiredCheckVerdict::Pass),
            (
                "# c\nverdict = \"TCP_OPEN\"\npeer_crypt = \"required\"\n",
                RequiredCheckVerdict::TcpOpen,
            ),
            ("verdict = \"OBSERVED\"\n", RequiredCheckVerdict::Observed),
            ("verdict = \"FAIL\"\n", RequiredCheckVerdict::Fail),
        ] {
            assert_eq!(RequiredCheckVerdict::from_verdict_file(text), Some(verdict));
            assert_eq!(
                verdict.file_line(),
                format!("verdict = \"{}\"\n", verdict.label())
            );
        }
        assert_eq!(
            RequiredCheckVerdict::from_verdict_file("verdict = \"MAYBE\"\n"),
            None
        );
    }

    #[test]
    fn only_a_run_whose_tcp_check_read_open_gates_green() {
        let judged = |line, serving, dialed| RequiredCheckVerdict::judge(line, serving, dialed);
        assert_eq!(judged(BOTH_OPEN, false, false), RequiredCheckVerdict::Pass);
        assert_eq!(
            judged("rmule-kad-verdicts tcp=open udp=unverified", true, true),
            RequiredCheckVerdict::TcpOpen
        );
        assert_eq!(
            judged(
                "rmule-kad-verdicts tcp=firewalled udp=unverified",
                true,
                true
            ),
            RequiredCheckVerdict::Observed
        );
        assert_eq!(
            judged("rmule-kad-verdicts none", true, false),
            RequiredCheckVerdict::Fail
        );
        assert!(RequiredCheckVerdict::Pass.tcp_open() && RequiredCheckVerdict::TcpOpen.tcp_open());
        assert!(!RequiredCheckVerdict::Observed.tcp_open());
    }
}
