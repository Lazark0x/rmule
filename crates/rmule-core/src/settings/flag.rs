//! **Flags**: the preferences that are on or off, each one line of a table.
//!
//! [`flag_table!`] declares a closed set of them: name, stored key and the
//! value an unset key reads as. Core declares [`Flag`], its own; a front end
//! declares the flags it keeps itself the same way. [`Flags`] holds which of
//! one set are on, and is the one place a flag's stored text is read.
//!
//! The table is a macro because Rust cannot list an enum's variants: by hand
//! each flag is a variant, a row and an entry in an `ALL` nothing checks
//! against the variants, and a flag left out of `ALL` is a key that silently
//! never loads. The macro's whole input is the table.

use std::collections::BTreeSet;

/// What [`flag_table!`] declares: one closed set of flags.
pub trait FlagTable: Copy + Ord + 'static {
    /// Every flag of the set.
    const ALL: &'static [Self];
    /// The `preferences.key` this flag is stored under. Stable: renaming one
    /// would orphan an installed value.
    fn key(self) -> &'static str;
    /// What the flag reads as while nothing is stored under its key.
    fn default_on(self) -> bool;
}

/// Declare a closed set of [`Flags`](crate::Flags): one row per flag, its
/// name, its stored key and whether it is on while unset. The set is an enum,
/// so a table of its words is checked for a missing row at compile time.
#[macro_export]
macro_rules! flag_table {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$row:meta])*
                $flag:ident = $key:expr, on: $on:literal;
            )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        $vis enum $name {
            $(
                $(#[$row])*
                $flag,
            )*
        }

        impl $crate::FlagTable for $name {
            const ALL: &'static [Self] = &[$(Self::$flag),*];

            fn key(self) -> &'static str {
                match self {
                    $(Self::$flag => $key,)*
                }
            }

            fn default_on(self) -> bool {
                match self {
                    $(Self::$flag => $on,)*
                }
            }
        }
    };
}

/// The stored text of a flag's value.
#[must_use]
pub const fn flag_text(on: bool) -> &'static str {
    if on { "true" } else { "false" }
}

/// What the text stored under a flag's key reads as: `unset` while there is
/// none, and on only as [`flag_text`] spells it, so text no build wrote is
/// off whatever the default.
#[must_use]
pub fn flag_reads(stored: Option<&str>, unset: bool) -> bool {
    stored.map_or(unset, |text| text == flag_text(true))
}

/// Which flags of one [`FlagTable`] are on. The default is each flag's own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flags<F: Ord>(BTreeSet<F>);

impl<F: FlagTable> Default for Flags<F> {
    fn default() -> Self {
        Self(
            F::ALL
                .iter()
                .copied()
                .filter(|flag| flag.default_on())
                .collect(),
        )
    }
}

impl<F: FlagTable> Flags<F> {
    /// Every flag as `stored` answers for its key.
    ///
    /// # Errors
    /// The first of `stored`'s.
    pub fn read<E>(
        mut stored: impl FnMut(&'static str) -> Result<Option<String>, E>,
    ) -> Result<Self, E> {
        let mut flags = Self::default();
        for flag in F::ALL {
            flags.set(
                *flag,
                flag_reads(stored(flag.key())?.as_deref(), flag.default_on()),
            );
        }
        Ok(flags)
    }

    /// Whether `flag` is on.
    #[must_use]
    pub fn is_on(&self, flag: F) -> bool {
        self.0.contains(&flag)
    }

    /// Turn `flag` on or off.
    pub fn set(&mut self, flag: F, on: bool) {
        if on {
            self.0.insert(flag);
        } else {
            self.0.remove(&flag);
        }
    }
}

crate::flag_table! {
    /// A **Flag** of core's own: a Core Setting that is on or off, and is
    /// nothing more.
    pub enum Flag {
        /// Whether a session start with an empty server list fetches
        /// `server.met` from
        /// [`server_met_url`](crate::CoreSettings::server_met_url) once
        /// (ADR-0065's first-run fetch,
        /// `rmule_bootstrap::BootstrapConfig::auto_fetch_server_met`).
        AutoFetchServerMet = "auto_fetch_server_met", on: true;
        /// Whether a session start walks
        /// [`server_met_auto_update_urls`](crate::CoreSettings::server_met_auto_update_urls)
        /// (ADR-0065's auto-update, aMule's `AutoServerlist`).
        AutoUpdateServerMet = "auto_update_server_met", on: false;
        /// Whether a Kad start with no contacts may fetch `nodes.dat` from
        /// [`nodes_dat_url`](crate::CoreSettings::nodes_dat_url) itself
        /// (ADR-0067 amendment): the operator's to turn off.
        AutoFetchNodesDat = "auto_fetch_nodes_dat", on: true;
    }
}
