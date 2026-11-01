//! What a value says while it has none. Each state has its word, so `—` is
//! never the only thing that says which: unknown, not running, no name, none.
//! A measured zero is no absence and reads as a zero.

/// What a cell too narrow for its word draws. The word rides the Off-screen
/// line, and Help says what the mark stands for.
pub const SHORT: &str = "—";

/// A fact nobody has told rmule yet.
pub const UNKNOWN: &str = "unknown";

/// A fact of a run that is not running.
pub const NOT_RUNNING: &str = "not running";

/// A figure no tick has metered yet.
pub const NOT_MEASURED: &str = "not measured";

/// A row whose name is blank.
pub const NO_NAME: &str = "no name";

/// A thing there is none of.
pub const NONE: &str = "none";

/// A search that holds no query of its own.
pub const NO_QUERY: &str = "no query";
