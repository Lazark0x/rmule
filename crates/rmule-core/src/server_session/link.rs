//! How a login's link to a server is opened (ADR-0042): plain, or to the
//! server's obfuscation TCP port with the crypt handshake first — aMule's dial
//! gate (`ServerSocket.cpp:786-795`) read against the one Obfuscation Policy
//! at the moment of each dial — and the one plain fallback a failed
//! obfuscated attempt earns (`ServerConnect.cpp:465-470`).

use rmule_net::peer::ObfuscationPolicy;

use crate::service::{LoginLink, PlainLinkReason, ServerConnectFailure};

impl LoginLink {
    /// The link a dial takes under `policy` toward a server whose row says it
    /// takes obfuscated TCP on `obfuscation_port`.
    ///
    /// Obfuscated only when the policy initiates — aMule's
    /// `IsServerCryptLayerTCPRequested()` is `IsClientCryptLayerRequested()`
    /// (`Preferences.h:884`), which `Requested` and `Required` both are — and
    /// the server has said it takes it. Like aMule, `Required` does not refuse
    /// a server that has said nothing: it dials it plain, and withholds only
    /// the fallback after an obfuscated attempt fails.
    pub(crate) fn choose(policy: Option<ObfuscationPolicy>, obfuscation_port: Option<u16>) -> Self {
        if !ObfuscationPolicy::stance_of(policy).requests() {
            return Self::Plain {
                why: PlainLinkReason::PolicyDoesNotInitiate,
            };
        }
        match obfuscation_port {
            Some(port) => Self::Obfuscated { port },
            None => Self::Plain {
                why: PlainLinkReason::ServerNotKnownToObfuscate,
            },
        }
    }

    /// The link to try next after this one failed with `failure` under
    /// `policy`, if any: aMule's single-connect retry, which reconnects
    /// without obfuscation after a crypt connection fails unless the client
    /// requires crypt (`ServerConnect.cpp:465-470`). A failure that is not the
    /// link's — the server refused the login it heard, or the IP filter
    /// stopped the dial before it — earns none.
    pub(crate) fn after_failure(
        self,
        policy: Option<ObfuscationPolicy>,
        failure: ServerConnectFailure,
    ) -> Option<Self> {
        let Self::Obfuscated { .. } = self else {
            return None;
        };
        if ObfuscationPolicy::stance_of(policy).requires() {
            return None;
        }
        match failure {
            ServerConnectFailure::Unreachable
            | ServerConnectFailure::LoginTimedOut
            | ServerConnectFailure::ClosedBeforeAnswer => Some(Self::Plain {
                why: PlainLinkReason::ObfuscatedAttemptFailed,
            }),
            ServerConnectFailure::LoginRefused | ServerConnectFailure::Filtered => None,
        }
    }

    /// The port this link dials obfuscated, `None` for a plain one.
    pub(crate) const fn obfuscated_port(self) -> Option<u16> {
        match self {
            Self::Obfuscated { port } => Some(port),
            Self::Plain { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// aMule's gate: only a policy that initiates dials obfuscated, and only
    /// toward a server that said it takes it — `Required` included, which
    /// dials a silent server plain rather than refusing it.
    #[test]
    fn the_link_follows_the_policy_and_what_the_server_said() {
        use ObfuscationPolicy::{Requested, Required, Supported};
        let plain = |why| LoginLink::Plain { why };
        for (policy, port, link) in [
            (
                None,
                Some(4674),
                plain(PlainLinkReason::PolicyDoesNotInitiate),
            ),
            (
                Some(Supported),
                Some(4674),
                plain(PlainLinkReason::PolicyDoesNotInitiate),
            ),
            (
                Some(Requested),
                Some(4674),
                LoginLink::Obfuscated { port: 4674 },
            ),
            (
                Some(Required),
                Some(4674),
                LoginLink::Obfuscated { port: 4674 },
            ),
            (
                Some(Requested),
                None,
                plain(PlainLinkReason::ServerNotKnownToObfuscate),
            ),
            (
                Some(Required),
                None,
                plain(PlainLinkReason::ServerNotKnownToObfuscate),
            ),
        ] {
            assert_eq!(LoginLink::choose(policy, port), link, "{policy:?} {port:?}");
        }
    }

    /// A refused login was heard over the obfuscated link, so it is no reason
    /// to try a plain one; a plain link has nothing to fall back to.
    #[test]
    fn only_a_failure_of_the_obfuscated_link_earns_a_fallback() {
        let obfuscated = LoginLink::Obfuscated { port: 4674 };
        let requested = Some(ObfuscationPolicy::Requested);
        assert_eq!(
            obfuscated.after_failure(requested, ServerConnectFailure::LoginRefused),
            None
        );
        assert_eq!(
            LoginLink::choose(requested, None)
                .after_failure(requested, ServerConnectFailure::Unreachable),
            None
        );
    }
}
