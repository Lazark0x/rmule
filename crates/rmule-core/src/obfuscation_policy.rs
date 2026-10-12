//! The running core's one **Obfuscation Policy** (ADR-0042/0046): a cell
//! every surface reads at the moment it decides, so a live change through
//! Core Settings reaches the next dial, accept, server login, datagram,
//! crypt-ping and Kad exchange at once, and no surface holds a copy that
//! could disagree.

use std::sync::Arc;

use rmule_net::peer::ObfuscationPolicy;
use rmule_primitives::CryptStance;
use tokio::sync::watch;

/// The node's obfuscation policy, `None` for none (ADR-0046 "One policy, one
/// knob").
///
/// `Core::builder` settles it from `CoreSettings::obfuscation` before anything
/// can read it, and the actor alone writes it after, when the operator changes
/// it live. Every reader asks per decision — a hello's options, an accepted
/// connection's byte-0 rule, a server login's link and crypt flags, a
/// datagram's send gate and receive, the crypt-ping sweep — so what is in
/// force is what the next one does, and a
/// connection that already negotiated keeps what it agreed. The Kad node
/// caches its arming, so its pump waits on [`changes`](Self::changes) and
/// re-arms it.
#[derive(Clone)]
pub(crate) struct SharedObfuscationPolicy(Arc<watch::Sender<Option<ObfuscationPolicy>>>);

impl Default for SharedObfuscationPolicy {
    /// No obfuscation, the posture of a build no settings were given to.
    fn default() -> Self {
        Self::new(None)
    }
}

impl SharedObfuscationPolicy {
    /// A cell holding `policy`.
    pub(crate) fn new(policy: Option<ObfuscationPolicy>) -> Self {
        Self(Arc::new(watch::Sender::new(policy)))
    }

    /// The policy in force now.
    pub(crate) fn get(&self) -> Option<ObfuscationPolicy> {
        *self.0.borrow()
    }

    /// Our own crypt stance now: what a hello, a publish and a CAPS frame
    /// state, and our side of every crypt rule.
    pub(crate) fn stance(&self) -> CryptStance {
        ObfuscationPolicy::stance_of(self.get())
    }

    /// Whether any policy is set: what arms the datagram layers (ADR-0046).
    pub(crate) fn armed(&self) -> bool {
        self.get().is_some()
    }

    /// Put `policy` in force, answering whether it changed anything. Only a
    /// change wakes [`changes`](Self::changes).
    pub(crate) fn set(&self, policy: Option<ObfuscationPolicy>) -> bool {
        self.0.send_if_modified(|held| {
            let changed = *held != policy;
            *held = policy;
            changed
        })
    }

    /// A receiver woken at every change, for a surface that caches its
    /// arming rather than reading per decision.
    pub(crate) fn changes(&self) -> watch::Receiver<Option<ObfuscationPolicy>> {
        self.0.subscribe()
    }
}

/// The word the Run Log states `policy` with.
pub(crate) const fn policy_name(policy: Option<ObfuscationPolicy>) -> &'static str {
    match policy {
        None => "off",
        Some(ObfuscationPolicy::Supported) => "supported",
        Some(ObfuscationPolicy::Requested) => "requested",
        Some(ObfuscationPolicy::Required) => "required",
    }
}
