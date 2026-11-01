//! The start's one question to the terminal: what is your ground, does a
//! box-drawing character take one cell, and do you take the kitty keyboard.
//! Device attributes go last, which nearly every terminal answers, so that
//! answer says every other has come, and the wait is that long, not a timeout.
//!
//! A terminal that stays silent costs [`FIRST_PAINT_BOUND`] and then draws. An
//! answer later than that would reach the input pump as keys, so [`Tail`]
//! reads the line for a while first, cuts out what is an answer and hands the
//! operator's own keys on.

use std::fs::File;
use std::io::{ErrorKind, Read as _};
use std::time::Duration;

use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use crate::theme::contrast::Rgb;

/// The longest a silent terminal keeps the first frame waiting.
pub const FIRST_PAINT_BOUND: Duration = Duration::from_millis(150);
/// The longest a terminal's late answer is waited for before input is read.
pub const TAIL_BOUND: Duration = Duration::from_millis(1500);

/// What the terminal said.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Answers {
    /// Its ground, from OSC 11.
    pub background: Option<Rgb>,
    /// Cells its cursor moved over one box-drawing character.
    pub box_cells: Option<u16>,
    /// It reports kitty keyboard flags.
    pub kitty: bool,
    /// It answered the device attributes, so nothing more is coming.
    pub settled: bool,
}

impl Answers {
    /// Read everything the terminal has sent. The questions were asked with
    /// the cursor in column one, so a position report's column is how far the
    /// one character carried it. Anything else on the line is not an answer.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Self {
        let mut answers = Self::default();
        let mut rest = bytes;
        while let Some(start) = rest.iter().position(|&byte| byte == 0x1B) {
            rest = &rest[start + 1..];
            match rest.first() {
                Some(b']') => answers.background = answers.background.or(background(rest)),
                Some(b'[') => answers.read_csi(&rest[1..]),
                _ => {}
            }
        }
        answers
    }

    fn read_csi(&mut self, body: &[u8]) {
        let end = body.iter().position(|byte| (0x40..=0x7E).contains(byte));
        let Some((&last, params)) = end.map(|end| (&body[end], &body[..end])) else {
            return;
        };
        match (params.first(), last) {
            (Some(b'?'), b'u') => self.kitty = true,
            (Some(b'?'), b'c') => self.settled = true,
            (_, b'R') => self.box_cells = self.box_cells.or(moved_cells(params)),
            _ => {}
        }
    }
}

fn moved_cells(params: &[u8]) -> Option<u16> {
    let (_, column) = std::str::from_utf8(params).ok()?.split_once(';')?;
    column.parse::<u16>().ok()?.checked_sub(1)
}

/// `]11;rgb:RRRR/GGGG/BBBB`, each channel one to four hex digits of a scale
/// its own length (xterm's `XParseColor`).
fn background(reply: &[u8]) -> Option<Rgb> {
    let text = std::str::from_utf8(reply.strip_prefix(b"]11;")?).ok()?;
    let colour = text
        .strip_prefix("rgb:")
        .or_else(|| text.strip_prefix("rgba:"))?;
    let end = colour.find(['\x07', '\x1b']).unwrap_or(colour.len());
    let mut channels = colour[..end].split('/').map(channel);
    Some((channels.next()??, channels.next()??, channels.next()??))
}

fn channel(digits: &str) -> Option<u8> {
    let value = u32::from_str_radix(digits, 16).ok()?;
    let scale = 16_u32.checked_pow(u32::try_from(digits.len()).ok()?)? - 1;
    (scale > 0)
        .then(|| value * 255 / scale)
        .and_then(|byte| u8::try_from(byte).ok())
}

/// The read side of a probe a silent terminal has not finished answering:
/// it ends, on the input thread, before anything else reads the line.
#[derive(Debug)]
pub struct Tail {
    line: File,
}

impl Tail {
    /// Take in what the terminal still has to say, until it settles or
    /// [`TAIL_BOUND`] passes, and answer the operator's keys among it.
    #[must_use]
    pub fn drain(self) -> Vec<Event> {
        let mut line = self.line;
        let mut heard = Vec::new();
        read_until_settled(&mut line, &mut heard, TAIL_BOUND);
        typed(&heard)
    }
}

/// What the terminal answered, and the [`Tail`] of one still to be heard out.
#[derive(Debug, Default)]
pub struct Probed {
    /// The answers in time for the first frame.
    pub answers: Answers,
    /// Input waits on this.
    pub tail: Option<Tail>,
}

/// The questions, in the order their answers settle: the character goes down
/// from column one and its width comes back first; device attributes are last.
const QUESTIONS: &str = "\r\u{2500}\x1b[6n\x1b[?u\x1b]11;?\x1b\\\x1b[c";

/// Ask, through `send`, with raw mode up, and wait for the answers on a read
/// end of the probe's own: the line is the only writer, and this is the only
/// time a run reads its terminal for anything but input. No read end is no
/// question and no answers.
pub fn ask(send: impl FnOnce(Vec<u8>)) -> Probed {
    let Ok(mut line) = rmule_os::terminal::open_unblocked() else {
        return Probed::default();
    };
    send(QUESTIONS.as_bytes().to_vec());
    let mut heard = Vec::new();
    read_until_settled(&mut line, &mut heard, FIRST_PAINT_BOUND);
    let answers = Answers::parse(&heard);
    let tail = (!answers.settled).then_some(Tail { line });
    Probed { answers, tail }
}

fn read_until_settled(line: &mut File, heard: &mut Vec<u8>, bound: Duration) {
    /// Between looks at a line with nothing on it.
    const LOOK: Duration = Duration::from_millis(2);

    let deadline = std::time::Instant::now() + bound;
    let mut chunk = [0; 256];
    while std::time::Instant::now() < deadline {
        match line.read(&mut chunk) {
            Ok(0) => return,
            Ok(read) => {
                heard.extend_from_slice(&chunk[..read]);
                if Answers::parse(heard).settled {
                    return;
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => std::thread::sleep(LOOK),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// The keys among bytes read off the line: answers cut out, and what is left
/// read as a legacy keyboard sends it. A CSI sequence is an arrow or nothing.
fn typed(mut bytes: &[u8]) -> Vec<Event> {
    let mut keys = Vec::new();
    while let Some(&first) = bytes.first() {
        let (key, used) = match bytes {
            [0x1B, b'[', body @ ..] => csi_key(body),
            [0x1B, b']', body @ ..] => (None, osc_length(body).saturating_add(2)),
            [0x1B, ..] => (Some(KeyEvent::from(KeyCode::Esc)), 1),
            _ if first < 0x80 => (control_or_char(first), 1),
            _ => utf8_key(bytes),
        };
        keys.extend(key.map(Event::Key));
        bytes = &bytes[used.min(bytes.len())..];
    }
    keys
}

fn csi_key(body: &[u8]) -> (Option<KeyEvent>, usize) {
    let Some(end) = body.iter().position(|byte| (0x40..=0x7E).contains(byte)) else {
        return (None, usize::MAX);
    };
    let code = match (end, body[end]) {
        (0, b'A') => Some(KeyCode::Up),
        (0, b'B') => Some(KeyCode::Down),
        (0, b'C') => Some(KeyCode::Right),
        (0, b'D') => Some(KeyCode::Left),
        _ => None,
    };
    (code.map(KeyEvent::from), 2 + end + 1)
}

fn osc_length(body: &[u8]) -> usize {
    let bell = body.iter().position(|&byte| byte == 0x07).map(|at| at + 1);
    let st = body
        .windows(2)
        .position(|pair| pair == b"\x1b\\")
        .map(|at| at + 2);
    bell.into_iter().chain(st).min().unwrap_or(usize::MAX)
}

fn control_or_char(byte: u8) -> Option<KeyEvent> {
    let control = |letter| KeyEvent::new(KeyCode::Char(letter), KeyModifiers::CONTROL);
    Some(match byte {
        b'\r' | b'\n' => KeyEvent::from(KeyCode::Enter),
        b'\t' => KeyEvent::from(KeyCode::Tab),
        0x7F => KeyEvent::from(KeyCode::Backspace),
        0x01..=0x1A => control(char::from(byte - 1 + b'a')),
        0x20..=0x7E => KeyEvent::from(KeyCode::Char(char::from(byte))),
        _ => return None,
    })
}

fn utf8_key(bytes: &[u8]) -> (Option<KeyEvent>, usize) {
    let Some(chunk) = bytes.utf8_chunks().next() else {
        return (None, 1);
    };
    match chunk.valid().chars().next() {
        Some(character) => (
            Some(KeyEvent::from(KeyCode::Char(character))),
            character.len_utf8(),
        ),
        None => (None, chunk.invalid().len().max(1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_answer_reads_as_each_terminal_sends_it() {
        let xterm = b"\x1b[1;2R\x1b]11;rgb:ffff/ffff/d7d7\x1b\\\x1b[?64;1;2c";
        assert_eq!(
            Answers::parse(xterm),
            Answers {
                background: Some((255, 255, 215)),
                box_cells: Some(1),
                kitty: false,
                settled: true,
            }
        );
        let kitty = b"\x1b[1;2R\x1b[?0u\x1b]11;rgb:10/12/18\x07\x1b[?62;c";
        let answers = Answers::parse(kitty);
        assert!(answers.kitty && answers.settled);
        assert_eq!(answers.background, Some((0x10, 0x12, 0x18)));
    }

    /// A console answers only the two it knows; a KOI8 terminal takes the
    /// character's three bytes for three characters.
    #[test]
    fn what_a_terminal_leaves_unanswered_stays_unknown() {
        let linux = Answers::parse(b"\x1b[1;4R\x1b[?6c");
        assert_eq!(linux.background, None);
        assert_eq!(linux.box_cells, Some(3));
        assert!(linux.settled);
        assert_eq!(Answers::parse(b""), Answers::default());
    }

    /// The first read can end anywhere, and the wait goes on from there.
    #[test]
    fn a_reply_cut_short_does_not_settle() {
        assert!(!Answers::parse(b"\x1b[1;2R\x1b[?64;1").settled);
        assert_eq!(Answers::parse(b"\x1b]11;rgb:ff").background, None);
    }

    /// What a silent terminal's operator typed before input started arrives,
    /// and a terminal's late answer among it does not.
    #[test]
    fn a_tail_keeps_the_keys_and_cuts_the_late_answers() {
        let heard = b"j\x1b[A\x1b]11;rgb:ffff/ffff/ffff\x1b\\\x1b[1;2R\x03\x1b[?62;22c\xD1\x8Fq";
        let keys: Vec<Event> = [
            KeyEvent::from(KeyCode::Char('j')),
            KeyEvent::from(KeyCode::Up),
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            KeyEvent::from(KeyCode::Char('я')),
            KeyEvent::from(KeyCode::Char('q')),
        ]
        .map(Event::Key)
        .to_vec();
        assert_eq!(typed(heard), keys);
    }

    /// A read cut off inside an answer leaves nothing of it to run as keys.
    #[test]
    fn a_tail_ending_inside_an_answer_types_nothing() {
        assert!(typed(b"\x1b]11;rgb:ff").is_empty());
        assert!(typed(b"\x1b[?64;1").is_empty());
    }

    #[test]
    fn a_short_channel_scales_to_a_byte() {
        assert_eq!(background(b"]11;rgb:f/8/0"), Some((255, 136, 0)));
        assert_eq!(
            background(b"]11;rgba:ffff/0000/0000/ffff\x07"),
            Some((255, 0, 0))
        );
    }
}
