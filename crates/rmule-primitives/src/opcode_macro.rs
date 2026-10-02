//! Value-once opcode enum generator.
//!
//! `opcodes! { enum Name { Variant = 0xNN, ... } }` declares each byte
//! exactly once and generates a `Copy` enum with `as_u8` and
//! `try_from_u8`. A byte reused across two variants is an "unreachable
//! pattern" compile error in the generated `try_from_u8`, so the macro
//! also guards against accidental duplicates.

/// Declare an opcode enum from `Variant = 0xNN` rows, generating `as_u8` and
/// `try_from_u8`.
///
/// Each byte is written exactly once. A byte reused across two variants
/// becomes an unreachable pattern in the generated `try_from_u8` — a compile
/// error, which is the point: duplicate opcodes are otherwise invisible.
#[macro_export]
macro_rules! opcodes {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $variant:ident = $byte:expr ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        $vis enum $name {
            $(
                #[doc = concat!("`", stringify!($variant), "`, wire byte `", stringify!($byte), "`.")]
                $variant
            ),+
        }

        impl $name {
            /// The single wire byte for this opcode.
            #[must_use]
            pub const fn as_u8(self) -> u8 {
                match self {
                    $( Self::$variant => $byte ),+
                }
            }

            /// The opcode for `byte`, or `None` if rmule does not model it.
            #[must_use]
            pub const fn try_from_u8(byte: u8) -> ::core::option::Option<Self> {
                match byte {
                    $( $byte => ::core::option::Option::Some(Self::$variant), )+
                    _ => ::core::option::Option::None,
                }
            }
        }
    };
}
