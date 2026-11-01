//! The AICH trees the serve side answers from (ADR-0038): which are built,
//! which file is being built and which wait their turn, and what is owed to
//! whom when a tree lands. One build runs at a time, away from the serve loop;
//! the enactor carries it out and feeds its end back through
//! [`ServeState::on_aich_landed`]. A cache hit answers at once and a file is
//! built once a run, whoever asks and however often.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use rmule_peer::ServerCommand;
use rmule_primitives::{
    AichHashSet, AichRootHash, ED2K_PART_SIZE, EMBLOCKSIZE, FileHash, PeerEndpoint,
};

use super::served::Found;
use super::transfer::not_found;
use super::{ServeDecision, ServeState};
use crate::upload_queue::ScoreModifiers;

/// How a build ended, as the enactor tells it.
#[derive(Clone, Debug)]
pub(in crate::serve) enum AichBuilt {
    /// The tree of the file's bytes.
    Tree(AichHashSet),
    /// The file could not be read to its end.
    Unreadable,
    /// It was told to stop, and did.
    Stopped,
}

/// The one build out.
#[derive(Clone, Copy, Debug)]
struct Running {
    file_hash: FileHash,
    /// Its file left the share set after it started. It holds the one place
    /// until it has landed, and what it landed with counts for nothing.
    stopped: bool,
}

/// See the module docs.
#[derive(Debug, Default)]
pub(super) struct AichTrees {
    /// Every tree built this run, of files still offered. Durable persistence
    /// (known2.met) is deferred.
    built: HashMap<FileHash, AichHashSet>,
    running: Option<Running>,
    /// Files waiting for the build, first asked first, each once.
    queued: VecDeque<FileHash>,
    /// The root each link waits for: its latest ask's, the only one its peer
    /// keeps (`DownloadClient.cpp:1707`), so this is bounded by the links.
    owed: HashMap<PeerEndpoint, FileHash>,
}

impl AichTrees {
    /// Whether `file_hash`'s tree is built.
    pub(super) fn holds(&self, file_hash: FileHash) -> bool {
        self.built.contains_key(&file_hash)
    }

    /// Give `file_hash` its turn, unless it has it already.
    fn queue(&mut self, file_hash: FileHash) {
        let building = self
            .running
            .is_some_and(|running| running.file_hash == file_hash && !running.stopped);
        if !building && !self.holds(file_hash) && !self.queued.contains(&file_hash) {
            self.queued.push_back(file_hash);
        }
    }

    /// The next file to build, when none is out.
    fn start_next(&mut self) -> Option<FileHash> {
        if self.running.is_some() {
            return None;
        }
        let file_hash = self.queued.pop_front()?;
        self.running = Some(Running {
            file_hash,
            stopped: false,
        });
        Some(file_hash)
    }

    /// The peers `file_hash`'s root is owed to, no longer owed.
    fn take_owed(&mut self, file_hash: FileHash) -> Vec<PeerEndpoint> {
        let owed: Vec<PeerEndpoint> = self
            .owed
            .iter()
            .filter(|(_, owed)| **owed == file_hash)
            .map(|(peer, _)| *peer)
            .collect();
        for peer in &owed {
            self.owed.remove(peer);
        }
        owed
    }

    /// `file_hash` left the share set: what is known of it goes, and `true`
    /// says a running build must be told to stop.
    pub(super) fn leave(&mut self, file_hash: FileHash) -> bool {
        self.built.remove(&file_hash);
        self.queued.retain(|queued| *queued != file_hash);
        self.take_owed(file_hash);
        match &mut self.running {
            Some(running) if running.file_hash == file_hash && !running.stopped => {
                running.stopped = true;
                true
            }
            _ => false,
        }
    }

    /// `peer`'s link ended: nothing can reach it. A build it started goes on,
    /// because the tree serves the next asker, and a cancel here would let a
    /// peer buy unlimited reads by asking and leaving (ADR-0038).
    pub(super) fn forget_link(&mut self, peer: PeerEndpoint) {
        self.owed.remove(&peer);
    }
}

impl ServeState {
    /// Answer an AICH master-root ask (`0x9E`, standalone or bundled) from the
    /// file's tree. Without one the build is started or left running, and the
    /// root follows when the tree lands: the link is owed it (ADR-0038). A
    /// Served Download answers nothing: its tree is whole only once the file
    /// is (ADR-0113). A peer whose hello claims no AICH is answered nothing and
    /// starts nothing, as aMule (`ClientTCPSocket.cpp:1618`).
    pub(super) fn answer_aich_root(
        &mut self,
        peer: PeerEndpoint,
        file_hash: FileHash,
    ) -> Vec<ServeDecision> {
        let supports = self
            .identities
            .get(&peer)
            .is_some_and(|i| i.supports_aich());
        if !supports
            || self
                .lookup_for(peer, file_hash)
                .and_then(Found::row)
                .is_none()
        {
            return Vec::new();
        }
        if let Some(tree) = self.aich.built.get(&file_hash) {
            return vec![root_answer(peer, file_hash, tree.master_root())];
        }
        self.aich.owed.insert(peer, file_hash);
        self.aich.queue(file_hash);
        self.next_aich_build().into_iter().collect()
    }

    /// Answer a recovery ask (`0x9B`) quoting `root` for `part`: the branch, or
    /// the refusal at once for anything that cannot be met now, as aMule's
    /// `ProcessAICHRequest` (`DownloadClient.cpp:1646-1695`). Without a tree
    /// the build is started too, and the asker's next ask finds it. No slot is
    /// needed; the requester verifies the branch against the root it trusts.
    pub(super) fn answer_aich_recovery(
        &mut self,
        peer: PeerEndpoint,
        file_hash: FileHash,
        part: u16,
        root: AichRootHash,
    ) -> Vec<ServeDecision> {
        let refused = ServeDecision::Send {
            peer,
            command: ServerCommand::RefuseAich { file_hash },
        };
        let Some(file_size) = self
            .lookup_for(peer, file_hash)
            .and_then(Found::row)
            .map(|entry| entry.file_size)
        else {
            return vec![refused];
        };
        let Some(tree) = self.aich.built.get(&file_hash) else {
            self.aich.queue(file_hash);
            return std::iter::once(refused)
                .chain(self.next_aich_build())
                .collect();
        };
        let part_start = u64::from(part) * ED2K_PART_SIZE;
        let recovery_data = (tree.master_root() == root
            && file_size.saturating_sub(part_start) > EMBLOCKSIZE)
            .then(|| tree.create_part_recovery_data(part_start))
            .flatten();
        vec![match recovery_data {
            Some(recovery_data) => ServeDecision::Send {
                peer,
                command: ServerCommand::AnswerAich {
                    file_hash,
                    part,
                    root,
                    recovery_data,
                },
            },
            None => refused,
        }]
    }

    /// The build of `file_hash` ended. A tree is cached and its owed roots go
    /// out; a build told to stop counts for nothing, whatever it landed with;
    /// a file it could not read stops being offered as any failed read does
    /// (ADR-0106), and each owed link is told so. Either way the next file
    /// takes the build.
    pub(crate) fn on_aich_landed(
        &mut self,
        now: Instant,
        file_hash: FileHash,
        built: AichBuilt,
        modifiers: &dyn ScoreModifiers,
    ) -> Vec<ServeDecision> {
        let Some(running) = self.aich.running.take() else {
            return Vec::new();
        };
        let mut decisions = Vec::new();
        match built {
            _ if running.stopped => {}
            AichBuilt::Tree(tree) => {
                let root = tree.master_root();
                self.aich.built.insert(file_hash, tree);
                decisions.extend(
                    self.aich
                        .take_owed(file_hash)
                        .into_iter()
                        .map(|peer| root_answer(peer, file_hash, root)),
                );
            }
            AichBuilt::Unreadable => {
                let told = self.queue.engaged_peers(file_hash);
                let owed = self.aich.take_owed(file_hash);
                decisions.extend(self.stop_serving(file_hash, now, modifiers));
                decisions.extend(
                    owed.into_iter()
                        .filter(|peer| !told.contains(peer))
                        .map(|peer| not_found(peer, file_hash)),
                );
                decisions.push(ServeDecision::ReadFailed(file_hash));
            }
            AichBuilt::Stopped => {}
        }
        decisions.extend(self.next_aich_build());
        decisions
    }

    /// Start the next build, when none is out, past any file no longer
    /// offered whole.
    fn next_aich_build(&mut self) -> Option<ServeDecision> {
        while let Some(file_hash) = self.aich.start_next() {
            if let Some(entry) = self.lookup(file_hash).and_then(Found::row) {
                return Some(ServeDecision::BuildAichTree {
                    file_hash,
                    path: entry.path.clone(),
                    file_size: entry.file_size,
                });
            }
            self.aich.running = None;
        }
        None
    }
}

fn root_answer(peer: PeerEndpoint, file_hash: FileHash, root: AichRootHash) -> ServeDecision {
    ServeDecision::Send {
        peer,
        command: ServerCommand::AnswerAichFileHash { file_hash, root },
    }
}
