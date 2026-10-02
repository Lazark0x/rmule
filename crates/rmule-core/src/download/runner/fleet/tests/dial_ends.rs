//! The seeds the human's run held (2026-10-01): sources whose crypt stance no
//! record stated, dialed under a `required` policy through the production
//! dial adapter. Each refusal is told once, with its cause, and counted, and
//! each source keeps its cause after its slot has moved on (ADR-0110).

use std::collections::BTreeSet;

use rmule_net::peer::ObfuscationPolicy;

use super::*;
use crate::service::DialEnd;

/// Three plain High-ID sources: a server row states no crypt byte.
#[derive(Clone)]
struct StancelessSources;

const STANCELESS: [u32; 3] = [0x0100_007F, 0x0200_007F, 0x0300_007F];

impl SourceLookupService for StancelessSources {
    async fn lookup_sources(
        &mut self,
        _target: rmule_primitives::SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        Ok(SourceLookupOutcome {
            client_id: ClientId::from_u32(STANCELESS[0]),
            sources: STANCELESS
                .iter()
                .map(|&id| ExchangedSource::plain(PeerSource::new(ClientId::from_u32(id), 4663)))
                .collect(),
        })
    }
}

#[tokio::test]
async fn a_required_policy_tells_each_stanceless_source_s_refusal_once() {
    let store = crate::open_durable_store_in_memory().expect("in-memory store opens");
    let config = CoreConfig {
        peer_crypt: Some(ObfuscationPolicy::Required),
        ..CoreConfig::default()
    };
    let mut core = Core::builder(config, store)
        .source_lookup(StancelessSources)
        .peer_transfer(crate::RuntimePeerTransferService::new(
            crate::DEFAULT_SLOT_WAIT_TIMEOUT,
        ))
        .build();
    let out_dir = tempfile::tempdir().unwrap();
    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: example_file(),
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        credentials: ctx(0x42, "rmule-core").identity.into(),
        output_path: out_dir.path().join("stanceless.bin"),
    }))
    .await
    .unwrap();

    let mut ended = Vec::new();
    let download_id = loop {
        match next_core_event(&mut core).await {
            CoreEvent::Download(DownloadEvent::DialEnded {
                download_id,
                peer,
                cause,
            }) => {
                assert_eq!(cause, DialEnd::CryptStanceUnknown);
                ended.push(peer);
                if ended.len() == STANCELESS.len() {
                    break download_id;
                }
            }
            CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                panic!("failed before every source was told: {reason:?}")
            }
            _ => {}
        }
    };
    let distinct: BTreeSet<_> = ended.iter().map(ToString::to_string).collect();
    assert_eq!(distinct.len(), STANCELESS.len(), "one refusal per source");

    let snapshot = core.diagnostics_snapshot();
    let row = snapshot
        .downloads
        .get(&download_id)
        .expect("the download's row");
    assert_eq!(row.dials_ended, 3);
    // Two slots dial three sources, so a slot took its next peer after its
    // first refusal; every source still says why its dial ended.
    let kept: BTreeSet<_> = row
        .dial_ends
        .iter()
        .filter(|(_, end)| end.cause == DialEnd::CryptStanceUnknown)
        .map(|(peer, _)| peer.to_string())
        .collect();
    assert_eq!(kept, distinct);
}
