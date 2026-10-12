//! The words of the **Player Command** (ADR-0114): its unset Settings row,
//! why a typed command is refused, and the receipt of a saved one.

use crate::player::Unsplittable;

/// What the unset Player Command row reads.
pub const UNSET: &str = "unset — Preview is off";

/// Why a typed Player Command is refused, as the line under the field.
#[must_use]
pub const fn refusal_words(refusal: Unsplittable) -> &'static str {
    match refusal {
        Unsplittable::OpenQuote => "player: a quote is not closed",
        Unsplittable::NoProgram => "player: the first word must name the player, not %PARTFILE",
    }
}

/// What a saved Player Command reads in the Settings receipt.
#[must_use]
pub fn receipt(command: Option<&str>) -> String {
    format!("player → {}", command.unwrap_or("none"))
}
