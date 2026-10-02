//! **The compatible-client code** a mule hello carries in the top byte of
//! `CT_EMULE_VERSION` (and in a legacy `OP_EMULEINFO` block): which program
//! the counterparty says it is. The ids are aMule 2.3.3's `EClientSoftware`
//! (`src/include/protocol/ed2k/ClientSoftware.h:30-47`). A code no table
//! names stays raw in [`CompatibleClient::Unnamed`], never a guessed name.

/// One compatible-client code, as the counterparty sent it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum CompatibleClient {
    /// `SO_EMULE`, `0`: eMule or a mod of it.
    #[default]
    Emule,
    /// `SO_CDONKEY`, `1`.
    Cdonkey,
    /// `SO_LXMULE`, `2`.
    Xmule,
    /// `SO_AMULE`, `3`.
    Amule,
    /// `SO_SHAREAZA` `4`, `SO_NEW2_SHAREAZA` `0x28` and `SO_NEW_SHAREAZA` `0x44`.
    Shareaza,
    /// `SO_EMULEPLUS`, `5`.
    EmulePlus,
    /// `SO_HYDRANODE`, `6`.
    HydraNode,
    /// `SO_NEW2_MLDONKEY` `0x0A` and `SO_NEW_MLDONKEY` `0x98`.
    MlDonkey,
    /// `SO_LPHANT`, `0x14`.
    Lphant,
    /// A code no table above names.
    Unnamed(u8),
}

impl CompatibleClient {
    /// The client a code names.
    pub(super) const fn of(code: u8) -> Self {
        match code {
            0 => Self::Emule,
            1 => Self::Cdonkey,
            2 => Self::Xmule,
            3 => Self::Amule,
            4 | 0x28 | 0x44 => Self::Shareaza,
            5 => Self::EmulePlus,
            6 => Self::HydraNode,
            0x0A | 0x98 => Self::MlDonkey,
            0x14 => Self::Lphant,
            other => Self::Unnamed(other),
        }
    }
}
