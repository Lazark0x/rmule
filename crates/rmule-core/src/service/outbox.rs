//! The **Outbox** (ADR-0069, "Core never waits on the front end"): where every
//! core task reports, and where the single reader of the event stream reads.
//!
//! A send never waits. A reader that stops reading costs itself detail and
//! costs the node nothing: the Run Log has the event before any weight is
//! read, and [`weight`] says what the queue may do with it. The stream a reader
//! sees is what core said, in the order core said it, less superseded
//! [`Weight::Level`]s and whatever an [`CoreEvent::EventsShed`] counts.
//!
//! The queue ends when the last [`Outbox`] drops, which is how `Core::quit`'s
//! stream says the flush has happened. A [`WeakOutbox`] does not keep it open.

mod weight;

#[cfg(test)]
mod tests;

use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Weak};

use tokio::sync::Notify;
use tokio::sync::mpsc::error::TryRecvError;

use self::weight::{LevelKey, Weight};
use super::CoreEvent;
use crate::run_log::LevelHandle;

/// How many events the queue holds before it sheds its Levels and Notes. A
/// stall this long has lost the reader its place; the Run Log holds the rest.
const ROOM: usize = 1 << 16;

/// A new Outbox over a Run Log `level` and the one stream that reads it.
pub(crate) fn outbox(level: LevelHandle) -> (Outbox, EventStream) {
    outbox_with_room(level, ROOM)
}

fn outbox_with_room(level: LevelHandle, room: usize) -> (Outbox, EventStream) {
    let shared = Arc::new(Shared {
        queue: Mutex::new(Queue::new(room)),
        wake: Notify::new(),
    });
    let open = Arc::new(Open(Arc::clone(&shared)));
    (
        Outbox {
            shared: Arc::clone(&shared),
            open,
            level,
        },
        EventStream { shared },
    )
}

/// A task's door onto the event stream. Cloning shares it; the stream ends
/// when the last clone drops.
#[derive(Clone, Debug)]
pub(crate) struct Outbox {
    shared: Arc<Shared>,
    open: Arc<Open>,
    level: LevelHandle,
}

impl Outbox {
    /// Write `event` to the Run Log and queue it for the reader, without
    /// waiting for anything the reader does.
    pub(crate) fn send(&self, event: CoreEvent) {
        crate::run_log::write(&event.record(), self.level.get());
        let weight = weight::of(&event);
        let shed = {
            let mut queue = self.shared.lock();
            queue.push(event, weight)
        };
        if let Some(count) = shed {
            crate::run_log::write(&CoreEvent::EventsShed { count }.record(), self.level.get());
        }
        self.shared.wake.notify_one();
    }

    /// A door that does not hold the stream open: for a task that outlives
    /// the actor's flush, whose report must not delay quit's end.
    pub(crate) fn downgrade(&self) -> WeakOutbox {
        WeakOutbox {
            shared: Arc::clone(&self.shared),
            open: Arc::downgrade(&self.open),
            level: self.level.clone(),
        }
    }
}

/// An [`Outbox`] that does not keep the stream open.
#[derive(Clone, Debug)]
pub(crate) struct WeakOutbox {
    shared: Arc<Shared>,
    open: Weak<Open>,
    level: LevelHandle,
}

impl WeakOutbox {
    /// The door, while the stream is open.
    pub(crate) fn upgrade(&self) -> Option<Outbox> {
        self.open.upgrade().map(|open| Outbox {
            shared: Arc::clone(&self.shared),
            open,
            level: self.level.clone(),
        })
    }
}

/// The reader's end. Not `Clone`: every fact is delivered once.
#[derive(Debug)]
pub struct EventStream {
    shared: Arc<Shared>,
}

impl EventStream {
    /// The next event, or `None` once every Outbox is gone and the queue
    /// is empty. Cancel safe: an event is taken only as this resolves.
    pub async fn recv(&mut self) -> Option<CoreEvent> {
        loop {
            match self.try_recv() {
                Ok(event) => return Some(event),
                Err(TryRecvError::Disconnected) => return None,
                // A wake stored since the last read ends this at once.
                Err(TryRecvError::Empty) => self.shared.wake.notified().await,
            }
        }
    }

    /// The next event if one is queued now.
    ///
    /// # Errors
    ///
    /// [`TryRecvError::Empty`] with nothing queued,
    /// [`TryRecvError::Disconnected`] with nothing queued and every
    /// Outbox gone.
    pub fn try_recv(&mut self) -> Result<CoreEvent, TryRecvError> {
        let mut queue = self.shared.lock();
        match queue.pop() {
            Some(event) => Ok(event),
            None if queue.closed => Err(TryRecvError::Disconnected),
            None => Err(TryRecvError::Empty),
        }
    }
}

impl Drop for EventStream {
    /// With no reader nothing queued is read, so nothing more is kept.
    fn drop(&mut self) {
        self.shared.lock().unread();
    }
}

/// Held by every [`Outbox`]; its drop is the stream's end.
#[derive(Debug)]
struct Open(Arc<Shared>);

impl Drop for Open {
    fn drop(&mut self) {
        self.0.lock().closed = true;
        self.0.wake.notify_one();
    }
}

#[derive(Debug)]
struct Shared {
    queue: Mutex<Queue>,
    wake: Notify,
}

impl Shared {
    fn lock(&self) -> parking_lot::MutexGuard<'_, Queue> {
        self.queue.lock()
    }
}

/// One held event, or the hole a superseded Level left.
#[derive(Debug)]
enum Slot {
    Edge(CoreEvent),
    Level(LevelKey, CoreEvent),
    Note(CoreEvent),
    Superseded,
}

#[derive(Debug)]
struct Queue {
    slots: VecDeque<Slot>,
    /// The position in the whole stream of `slots[0]`.
    first: u64,
    /// Where each subject's queued Level stands.
    levels: HashMap<LevelKey, u64>,
    /// The length at which the queue next sheds. It grows past the room when
    /// Edges alone fill it, so a shed always frees half of what it read.
    shed_at: usize,
    room: usize,
    closed: bool,
    unread: bool,
}

impl Queue {
    fn new(room: usize) -> Self {
        Self {
            slots: VecDeque::new(),
            first: 0,
            levels: HashMap::new(),
            shed_at: room,
            room,
            closed: false,
            unread: false,
        }
    }

    /// Queue `event`; the count of what a shed dropped, when this send shed.
    fn push(&mut self, event: CoreEvent, weight: Weight) -> Option<u64> {
        if self.unread {
            return None;
        }
        let shed = (self.slots.len() >= self.shed_at)
            .then(|| self.make_room())
            .flatten();
        let slot = match weight {
            Weight::Edge => Slot::Edge(event),
            Weight::Note => Slot::Note(event),
            Weight::Level(key) => {
                self.supersede(&key);
                self.levels.insert(key.clone(), self.next_position());
                Slot::Level(key, event)
            }
        };
        self.slots.push_back(slot);
        shed
    }

    fn next_position(&self) -> u64 {
        self.first + self.slots.len() as u64
    }

    /// Take `key`'s queued value out of its place.
    fn supersede(&mut self, key: &LevelKey) {
        if let Some(position) = self.levels.remove(key) {
            let index = usize::try_from(position - self.first).expect("a held position");
            self.slots[index] = Slot::Superseded;
        }
    }

    /// Close the holes superseded Levels left, and shed only if that was not
    /// enough, so a subject that only ever moves is never counted as lost.
    fn make_room(&mut self) -> Option<u64> {
        self.slots.retain(|slot| !matches!(slot, Slot::Superseded));
        for (index, slot) in self.slots.iter().enumerate() {
            if let Slot::Level(key, _) = slot {
                self.levels.insert(key.clone(), self.first + index as u64);
            }
        }
        (self.slots.len() >= self.shed_at).then(|| self.shed())
    }

    /// Drop every Level and Note and say so with one Edge, which takes in
    /// the count of a shed the reader has not read, so sheds alone never grow
    /// the queue. The count of this shed alone is what it returns.
    fn shed(&mut self) -> u64 {
        let mut dropped = 0;
        let mut unread = 0;
        self.slots.retain(|slot| match slot {
            Slot::Edge(CoreEvent::EventsShed { count }) => {
                unread += count;
                false
            }
            Slot::Edge(_) => true,
            Slot::Level(..) | Slot::Note(_) => {
                dropped += 1;
                false
            }
            Slot::Superseded => false,
        });
        self.levels.clear();
        self.slots.push_back(Slot::Edge(CoreEvent::EventsShed {
            count: dropped + unread,
        }));
        self.shed_at = self.room.max(self.slots.len() * 2);
        dropped
    }

    fn pop(&mut self) -> Option<CoreEvent> {
        while let Some(slot) = self.slots.pop_front() {
            let position = self.first;
            self.first += 1;
            match slot {
                Slot::Edge(event) | Slot::Note(event) => return Some(event),
                Slot::Level(key, event) => {
                    debug_assert_eq!(self.levels.get(&key), Some(&position));
                    self.levels.remove(&key);
                    return Some(event);
                }
                Slot::Superseded => {}
            }
        }
        None
    }

    fn unread(&mut self) {
        self.unread = true;
        self.slots.clear();
        self.levels.clear();
    }
}
