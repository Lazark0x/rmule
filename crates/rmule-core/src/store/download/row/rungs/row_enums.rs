//! The frozen copies of the live enums every download row shape from record
//! version 1 to 5 embeds: the lifecycle, the verification authority and the
//! metadata origin. Those shapes' bytes decode by variant position, so each
//! copy keeps the declaration order the versions wrote, and grows into its
//! live type only at the rung onto today's row.

use serde::{Deserialize, Serialize};

use crate::{DownloadLifecycle, DownloadMetadataOrigin, VerificationAuthority};

/// [`DownloadLifecycle`] as record versions 1 to 4 encoded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum DownloadLifecycleV1 {
    Queued,
    Active,
    Paused,
    Failed,
    Completed,
    Cancelled,
}

impl DownloadLifecycleV1 {
    /// The lifecycle as record version 5 keeps it: every state the same.
    pub(super) const fn grown(self) -> DownloadLifecycleV5 {
        match self {
            Self::Queued => DownloadLifecycleV5::Queued,
            Self::Active => DownloadLifecycleV5::Active,
            Self::Paused => DownloadLifecycleV5::Paused,
            Self::Failed => DownloadLifecycleV5::Failed,
            Self::Completed => DownloadLifecycleV5::Completed,
            Self::Cancelled => DownloadLifecycleV5::Cancelled,
        }
    }
}

/// [`DownloadLifecycle`] as record version 5 encoded it: version 1's states
/// with `Completing` appended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum DownloadLifecycleV5 {
    Queued,
    Active,
    Paused,
    Failed,
    Completed,
    Cancelled,
    Completing,
}

impl DownloadLifecycleV5 {
    pub(super) const fn grown(self) -> DownloadLifecycle {
        match self {
            Self::Queued => DownloadLifecycle::Queued,
            Self::Active => DownloadLifecycle::Active,
            Self::Paused => DownloadLifecycle::Paused,
            Self::Failed => DownloadLifecycle::Failed,
            Self::Completed => DownloadLifecycle::Completed,
            Self::Cancelled => DownloadLifecycle::Cancelled,
            Self::Completing => DownloadLifecycle::Completing,
        }
    }
}

/// [`VerificationAuthority`] as record versions 1 to 5 encoded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum VerificationAuthorityV1 {
    LinkPartHashSet,
    PeerHashSet,
    FileHashOnly,
}

impl VerificationAuthorityV1 {
    pub(super) const fn grown(self) -> VerificationAuthority {
        match self {
            Self::LinkPartHashSet => VerificationAuthority::LinkPartHashSet,
            Self::PeerHashSet => VerificationAuthority::PeerHashSet,
            Self::FileHashOnly => VerificationAuthority::FileHashOnly,
        }
    }
}

/// [`DownloadMetadataOrigin`] as record versions 1 to 5 encoded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum DownloadMetadataOriginV1 {
    Link,
    RecoveredLink,
    Unknown,
}

impl DownloadMetadataOriginV1 {
    pub(super) const fn grown(self) -> DownloadMetadataOrigin {
        match self {
            Self::Link => DownloadMetadataOrigin::Link,
            Self::RecoveredLink => DownloadMetadataOrigin::RecoveredLink,
            Self::Unknown => DownloadMetadataOrigin::Unknown,
        }
    }
}
