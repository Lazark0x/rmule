//! The **Port Prediction** counters (ADR-0091's amendment): how many
//! attempts fired, how many extra `0xA1` they cost, and how many met.

use super::DiagnosticsState;

impl DiagnosticsState {
    /// One prediction attempt fired, in either role, sending `probes` extra
    /// `0xA1`.
    pub fn record_natt_prediction_attempt(&self, probes: u64) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let session = &mut inner.session;
        session.natt_prediction_attempts_total =
            session.natt_prediction_attempts_total.saturating_add(1);
        session.natt_prediction_probes_total =
            session.natt_prediction_probes_total.saturating_add(probes);
    }

    /// One pairing met.
    pub fn count_natt_prediction_hit(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_prediction_hits_total =
            inner.session.natt_prediction_hits_total.saturating_add(1);
    }

    /// One introduction that started no plan, or one attempt that did not
    /// fire, and why.
    pub fn record_natt_prediction_refusal(
        &self,
        refusal: crate::diagnostics::NattPredictionRefusal,
    ) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        inner.session.natt_prediction_refusals_total = inner
            .session
            .natt_prediction_refusals_total
            .saturating_add(1);
        inner.session.natt_last_prediction_refusal = Some(refusal);
    }
}
