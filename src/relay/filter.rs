//! Escape sequences the relay keeps from the user's terminal.
//!
//! Replies are not the concern here — the relay already keeps every reply
//! away from the user's shell. These are sequences the terminal emulator
//! acts on by itself:
//!
//! - **Clipboard (`OSC 52`).** A read hands the clipboard to the agent, and
//!   is dropped. A write is kept, with its text cut down to what can't act
//!   by itself once pasted: line breaks and tabs become a space, every
//!   other control character and bidi override is removed. So a paste
//!   never submits a line or a form, and shows what it is.
//! - **iTerm2's tmux integration (`DCS 1000p`).** Everything up to the
//!   string terminator goes to iTerm2's tmux protocol parser, which has
//!   had remote-code-execution bugs. Dropped whole.
//!
//! Everything else passes through byte for byte. The parser follows how
//! xterm-style terminals delimit these strings — an `ESC` that doesn't
//! start `ESC \`, or `CAN`/`SUB`, aborts the string — so a sequence can't
//! hide inside another one. Where the two could disagree, it drops rather
//! than passes: a `DCS 1000p` ends only at a string terminator.

use base64::Engine;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};

/// The most clipboard data (base64) buffered for one `OSC 52`; a longer one
/// is dropped.
const MAX_CLIPBOARD: usize = 1 << 20;

/// The most of an `OSC`'s number or a `DCS`'s header read before deciding
/// to pass it through.
const MAX_HEAD: usize = 32;

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;
/// First byte of a C1 control in UTF-8 (`U+0080`–`U+009F`): `C2 9D` is
/// `OSC`, `C2 90` is `DCS`, `C2 9C` is the string terminator.
const C2: u8 = 0xc2;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Osc,
    Dcs,
}

enum State {
    Ground,
    /// An `ESC`, or the first byte of a UTF-8 C1 control, held back until
    /// the next byte says whether it starts a string.
    Held(u8),
    /// The start of a string, held back until it says what it is.
    Head {
        kind: Kind,
        intro: &'static [u8],
        head: Vec<u8>,
    },
    /// An `OSC 52`'s `<selection>;<data>`, held back until it ends.
    Clipboard {
        intro: &'static [u8],
        body: Vec<u8>,
    },
    /// A string passed through as it comes.
    Pass {
        kind: Kind,
    },
    /// A string dropped; `strict` ones end only at a string terminator.
    Drop {
        kind: Kind,
        strict: bool,
    },
}

pub struct Filter {
    state: State,
    /// Inside a string: an `ESC` or `C2` waiting for the byte that says
    /// whether it ends the string.
    pending: Option<u8>,
}

impl Filter {
    pub fn new() -> Self {
        Filter {
            state: State::Ground,
            pending: None,
        }
    }

    /// Filters `input`, a chunk of what the agent wrote, onto `out`.
    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) {
        for &b in input {
            self.byte(b, out);
        }
    }

    /// The agent is gone: ends a string it left open, so the terminal isn't
    /// left swallowing what comes next. Anything held back is dropped.
    pub fn close(&mut self, out: &mut Vec<u8>) {
        if let State::Pass { .. } = self.state {
            out.extend_from_slice(b"\x1b\\");
        }
        self.state = State::Ground;
        self.pending = None;
    }

    fn byte(&mut self, b: u8, out: &mut Vec<u8>) {
        match &self.state {
            State::Ground => match b {
                ESC | C2 => self.state = State::Held(b),
                _ => out.push(b),
            },
            State::Held(held) => {
                let held = *held;
                let start = match (held, b) {
                    (ESC, b']') => Some((Kind::Osc, b"\x1b]".as_slice())),
                    (ESC, b'P') => Some((Kind::Dcs, b"\x1bP".as_slice())),
                    (C2, 0x9d) => Some((Kind::Osc, b"\xc2\x9d".as_slice())),
                    (C2, 0x90) => Some((Kind::Dcs, b"\xc2\x90".as_slice())),
                    _ => None,
                };
                match start {
                    Some((kind, intro)) => {
                        self.state = State::Head {
                            kind,
                            intro,
                            head: Vec::new(),
                        }
                    }
                    None => {
                        out.push(held);
                        self.state = State::Ground;
                        self.byte(b, out);
                    }
                }
            }
            _ => self.in_string(b, out),
        }
    }

    fn in_string(&mut self, b: u8, out: &mut Vec<u8>) {
        let (kind, strict) = match &self.state {
            State::Head { kind, .. } | State::Pass { kind } => (*kind, false),
            State::Clipboard { .. } => (Kind::Osc, false),
            State::Drop { kind, strict } => (*kind, *strict),
            State::Ground | State::Held(_) => unreachable!("not in a string"),
        };
        if let Some(p) = self.pending.take() {
            match (p, b) {
                (ESC, b'\\') => return self.end(b"\x1b\\", out),
                (C2, 0x9c) => return self.end(b"\xc2\x9c", out),
                (ESC, _) if !strict => {
                    // The terminal abandons the string here and reads the
                    // `ESC` afresh; so does this.
                    self.abort(out, None);
                    self.byte(ESC, out);
                    return self.byte(b, out);
                }
                // A strict string drops the `ESC` with the rest, then reads
                // `b` as usual: it may start the terminator itself.
                (ESC, _) => {}
                // A `C2` that isn't `C2 9C` is just text.
                _ => self.data(C2, out),
            }
        }
        match b {
            ESC | C2 => self.pending = Some(b),
            BEL if kind == Kind::Osc => self.end(b"\x07", out),
            CAN | SUB if !strict => self.abort(out, Some(b)),
            _ => self.data(b, out),
        }
    }

    fn data(&mut self, b: u8, out: &mut Vec<u8>) {
        match &mut self.state {
            State::Head { kind, intro, head } => {
                head.push(b);
                let next = match kind {
                    Kind::Osc if b == b';' && head == b"52;" => Some(State::Clipboard {
                        intro,
                        body: Vec::new(),
                    }),
                    Kind::Osc if b == b';' || head.len() > MAX_HEAD => {
                        Some(State::Pass { kind: Kind::Osc })
                    }
                    Kind::Dcs if (0x40..=0x7e).contains(&b) && is_tmux_integration(head) => {
                        Some(State::Drop {
                            kind: Kind::Dcs,
                            strict: true,
                        })
                    }
                    Kind::Dcs if (0x40..=0x7e).contains(&b) || head.len() > MAX_HEAD => {
                        Some(State::Pass { kind: Kind::Dcs })
                    }
                    _ => None,
                };
                if let Some(next) = next {
                    if let State::Pass { .. } = next {
                        out.extend_from_slice(intro);
                        out.extend_from_slice(head);
                    }
                    self.state = next;
                }
            }
            State::Clipboard { body, .. } => {
                body.push(b);
                if body.len() > MAX_CLIPBOARD {
                    self.state = State::Drop {
                        kind: Kind::Osc,
                        strict: false,
                    };
                }
            }
            State::Pass { .. } => out.push(b),
            State::Drop { .. } => {}
            State::Ground | State::Held(_) => unreachable!("not in a string"),
        }
    }

    /// The string ended with terminator `term`.
    fn end(&mut self, term: &[u8], out: &mut Vec<u8>) {
        match std::mem::replace(&mut self.state, State::Ground) {
            // Ended before saying what it is: harmless whatever it was, bar
            // an `OSC 52` with no data, which is nothing anyway.
            State::Head { intro, head, .. } => {
                if head != b"52" {
                    out.extend_from_slice(intro);
                    out.extend_from_slice(&head);
                    out.extend_from_slice(term);
                }
            }
            State::Clipboard { intro, body } => {
                if let Some(body) = clipboard_write(&body) {
                    out.extend_from_slice(intro);
                    out.extend_from_slice(b"52;");
                    out.extend_from_slice(&body);
                    out.extend_from_slice(term);
                }
            }
            State::Pass { .. } => out.extend_from_slice(term),
            State::Drop { .. } => {}
            State::Ground | State::Held(_) => unreachable!("not in a string"),
        }
    }

    /// The string was abandoned (by `CAN`/`SUB`, `cancel`, or an `ESC`).
    /// One already passed on gets `cancel` too, so the terminal abandons it
    /// the same way; one held back or dropped simply never happened.
    fn abort(&mut self, out: &mut Vec<u8>, cancel: Option<u8>) {
        if let (State::Pass { .. }, Some(c)) = (&self.state, cancel) {
            out.push(c);
        }
        self.state = State::Ground;
    }
}

/// iTerm2's tmux integration: a `DCS` whose final byte is `p` and whose
/// first parameter is `1000`. `head` ends with the final byte.
fn is_tmux_integration(head: &[u8]) -> bool {
    let Some((&b'p', params)) = head.split_last() else {
        return false;
    };
    params.split(|&c| c == b';').next() == Some(b"1000".as_slice())
}

/// The `<selection>;<data>` of an `OSC 52` to pass on, or `None` to drop
/// it: a read (`?`), anything malformed, or text with nothing left once
/// cut down by [`visible_only`].
fn clipboard_write(body: &[u8]) -> Option<Vec<u8>> {
    let split = body.iter().position(|&c| c == b';')?;
    let (selection, data) = (&body[..split], &body[split + 1..]);
    if !selection.iter().all(u8::is_ascii_alphanumeric) || data == b"?" {
        return None;
    }
    let mut out = selection.to_vec();
    out.push(b';');
    if data.is_empty() {
        // Clears the clipboard; nothing to paste.
        return Some(out);
    }
    let lenient = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let text = String::from_utf8(lenient.decode(data).ok()?).ok()?;
    let visible = visible_only(&text);
    if visible.is_empty() {
        return None;
    }
    out.extend_from_slice(STANDARD.encode(visible).as_bytes());
    Some(out)
}

/// `text` without what can act by itself once pasted: each run of line
/// breaks and tabs becomes one space, and every other control character
/// and bidi control is removed.
fn visible_only(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_break = false;
    for c in text.chars() {
        if matches!(c, '\n' | '\r' | '\t') {
            if !in_break {
                out.push(' ');
            }
            in_break = true;
            continue;
        }
        in_break = false;
        if !c.is_control() && !is_bidi_control(c) {
            out.push(c);
        }
    }
    out
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(input: &[u8]) -> Vec<u8> {
        let mut f = Filter::new();
        let mut out = Vec::new();
        f.push(input, &mut out);
        out
    }

    /// The same input a byte at a time: the result must not depend on how
    /// the agent's output is split into reads.
    fn filter_bytewise(input: &[u8]) -> Vec<u8> {
        let mut f = Filter::new();
        let mut out = Vec::new();
        for b in input {
            f.push(std::slice::from_ref(b), &mut out);
        }
        out
    }

    fn osc52(text: &str, term: &str) -> Vec<u8> {
        format!("\x1b]52;c;{}{term}", STANDARD.encode(text)).into_bytes()
    }

    #[test]
    fn ordinary_output_passes_unchanged() {
        let input = b"hello \x1b[1;31mred\x1b[0m \xc3\xa9 \xc2\xa0 \x1b]0;title\x07 \x1b]8;;https://x\x1b\\link\x1b]8;;\x1b\\ \x1bPq#0;2;0;0;0~\x1b\\ end";
        assert_eq!(filter(input), input);
        assert_eq!(filter_bytewise(input), input);
    }

    #[test]
    fn clipboard_write_keeps_text_and_turns_line_breaks_into_spaces() {
        let input = osc52("rm -rf ~\r\nsudo\tsh\n", "\x07");
        let expected = osc52("rm -rf ~ sudo sh ", "\x07");
        assert_eq!(filter(&input), expected);
        assert_eq!(filter_bytewise(&input), expected);
    }

    #[test]
    fn clipboard_write_loses_control_characters_and_bidi_overrides() {
        let input = osc52("a\x1b[201~b\u{202e}c\u{0085}d\x7f", "\x1b\\");
        assert_eq!(filter(&input), osc52("a[201~bcd", "\x1b\\"));
    }

    #[test]
    fn clipboard_write_of_plain_text_is_unchanged() {
        let input = osc52("echo hello", "\x1b\\");
        assert_eq!(filter(&input), input);
    }

    #[test]
    fn clipboard_clear_passes() {
        assert_eq!(filter(b"\x1b]52;c;\x07"), b"\x1b]52;c;\x07");
    }

    #[test]
    fn clipboard_read_and_malformed_writes_are_dropped() {
        for input in [
            b"\x1b]52;c;?\x07".as_slice(),
            b"\x1b]52;c;!!not base64!!\x07",
            b"\x1b]52;c;/w==\x07", // not UTF-8
            b"\x1b]52;c\x07",
            b"\x1b]52\x07",
            b"\x1b]52;c c;aGk=\x07",
        ] {
            assert_eq!(filter(input), b"", "{input:?}");
        }
        // Nothing but control characters: nothing left to write.
        assert_eq!(filter(&osc52("\x1b\x07", "\x07")), b"");
    }

    #[test]
    fn clipboard_without_padding_is_accepted() {
        assert_eq!(filter(b"\x1b]52;c;aGk\x07"), b"\x1b]52;c;aGk=\x07");
    }

    #[test]
    fn clipboard_in_utf8_c1_form_is_filtered_too() {
        let input = format!("\u{9d}52;c;{}\u{9c}", STANDARD.encode("a\nb")).into_bytes();
        let expected = format!("\u{9d}52;c;{}\u{9c}", STANDARD.encode("a b")).into_bytes();
        assert_eq!(filter(&input), expected);
        assert_eq!(filter_bytewise(&input), expected);
    }

    #[test]
    fn oversized_clipboard_is_dropped_and_what_follows_passes() {
        let mut input = b"\x1b]52;c;".to_vec();
        input.extend(std::iter::repeat_n(b'A', MAX_CLIPBOARD + 8));
        input.extend_from_slice(b"\x07after");
        assert_eq!(filter(&input), b"after");
    }

    #[test]
    fn a_clipboard_hidden_in_another_string_is_still_filtered() {
        // xterm abandons the title at the `ESC` and reads `ESC ] 52` afresh.
        let mut input = b"\x1b]0;title".to_vec();
        input.extend(osc52("x\ny", "\x07"));
        let mut expected = b"\x1b]0;title".to_vec();
        expected.extend(osc52("x y", "\x07"));
        assert_eq!(filter(&input), expected);
        assert_eq!(filter_bytewise(&input), expected);
    }

    #[test]
    fn cancelled_clipboard_is_dropped() {
        assert_eq!(filter(b"\x1b]52;c;aGk=\x18after"), b"after");
    }

    #[test]
    fn tmux_integration_is_dropped_up_to_the_string_terminator() {
        let input = b"before\x1bP1000p%begin 1 2 3\n\x07\x1b[1m\x18%end\x1b\x1b\\after";
        assert_eq!(filter(input), b"beforeafter");
        assert_eq!(filter_bytewise(input), b"beforeafter");
        assert_eq!(filter(b"\x1bP1000;1p%x\xc2\x9cafter"), b"after");
    }

    #[test]
    fn other_dcs_strings_pass() {
        for input in [
            b"\x1bP100p\x1b\\".as_slice(),
            b"\x1bP1000q\x1b\\",
            b"\x1bP$qm\x1b\\",
        ] {
            assert_eq!(filter(input), input);
        }
    }

    #[test]
    fn close_ends_a_string_left_open_and_drops_what_was_held() {
        let mut f = Filter::new();
        let mut out = Vec::new();
        f.push(b"\x1b]0;unterminated", &mut out);
        f.close(&mut out);
        assert_eq!(out, b"\x1b]0;unterminated\x1b\\");

        let mut f = Filter::new();
        let mut out = Vec::new();
        f.push(b"text\x1b]52;c;aGk=", &mut out);
        f.close(&mut out);
        assert_eq!(out, b"text");
    }

    #[test]
    fn visible_only_collapses_each_run_of_breaks() {
        assert_eq!(visible_only("a\r\n\r\nb\tc"), "a b c");
        assert_eq!(visible_only("\u{1b}\u{7}"), "");
    }
}
