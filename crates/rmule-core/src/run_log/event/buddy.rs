//! The record of a buddy dial that did not hold a link (ADR-0075, Run Log):
//! the cause is ours and lean, the buddy's address is a peer's and full.

use crate::BuddyDialFailure;
use rmule_primitives::Ipv4Endpoint;

use crate::run_log::codes;
use crate::run_log::record::Record;

pub(super) fn dial_failed(buddy: &Ipv4Endpoint, cause: BuddyDialFailure) -> Record {
    let record = Record::new("buddy.dial_failed").peer_address("buddy", buddy);
    match cause {
        BuddyDialFailure::Dial { cause } => codes::dial_failure(record, cause),
        BuddyDialFailure::HelloIncomplete => record.code("cause", "hello_incomplete"),
        BuddyDialFailure::CryptIncompatible => record.code("cause", "crypt_incompatible"),
        BuddyDialFailure::Stranger => record.code("cause", "stranger"),
    }
}
