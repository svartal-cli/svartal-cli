//! Bare `sv`: a list of your environments, arrow keys, enter connects.
//!
//! Typing `sv` with nothing after it used to print the usage and exit 1. On a
//! terminal it now shows the thing the person came for — the environments they
//! can reach — and connects a shell to the one they pick. Off a terminal
//! (a pipe, a script, CI) it still prints the usage and still exits 1, because
//! a script that runs `sv` by mistake must not start waiting for a keystroke.
//!
//! There is no TUI framework here and there does not need to be one. The
//! terminal work is what `sv shell` already does — `termios` raw mode through
//! `libc`, ANSI bytes to stdout — and the list is a `Vec` with an index. The
//! parts worth getting right are pure functions with tests: which rows exist,
//! what a keystroke means, what one frame looks like. What is left is a loop
//! that reads bytes and writes a frame, and that loop is deliberately thin.
//!
//! Raw mode and a hidden cursor are global terminal state, so both are undone
//! on every way out: the normal return, an error, a panic, and the signals that
//! would otherwise skip both (`terminal::restore_terminal`).

use crate::shortnames::Shortnames;
use crate::view::{self, MachinesView};

/// One line in the picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickerRow {
    pub shortname: Option<String>,
    pub label: String,
    pub environment_id: String,
    pub machine_name: Option<String>,
    /// What connecting would find: the machine's last heartbeat, or the fact
    /// that there is no link to it at all.
    pub state: String,
}

/// The environments, in the order `sv envs` lists them.
///
/// Workspaces that cannot be connected to are listed as well, marked
/// `not linked`. Hiding them would leave a person looking for a workspace they
/// can see in the web app at an empty list; showing it with its reason is the
/// answer they need. Picking one prints the same refusal `sv shell` gives.
pub fn build_picker_rows(view: &MachinesView, shortnames: &Shortnames) -> Vec<PickerRow> {
    view::build_env_rows(view, shortnames)
        .into_iter()
        .map(|row| PickerRow {
            state: if !row.linked {
                "not linked".to_string()
            } else {
                row.machine_presence.clone().unwrap_or_else(|| "unknown".to_string())
            },
            shortname: row.shortname,
            label: row.label,
            environment_id: row.environment_id,
            machine_name: row.machine_name,
        })
        .collect()
}

/// The keys this list answers to. Everything else is ignored rather than
/// guessed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Enter,
    Quit,
    Ignored,
}

/// Bytes from the terminal, as keys.
///
/// One read can carry several keystrokes (a held arrow key, a paste), so this
/// returns all of them in order. An escape sequence that arrives split across
/// two reads decodes as a bare `Esc` and quits — the same thing every
/// hand-rolled reader does, and in practice a terminal sends `Esc [ A` in one
/// write.
pub fn decode_keys(bytes: &[u8]) -> Vec<Key> {
    let mut keys = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == 0x1b {
            // `Esc [ A` and `Esc O A`: the two encodings a terminal uses for
            // the arrow keys, depending on its keypad mode.
            let introducer = bytes.get(index + 1).copied();
            let final_byte = bytes.get(index + 2).copied();
            if matches!(introducer, Some(b'[') | Some(b'O'))
                && let Some(final_byte) = final_byte
            {
                keys.push(match final_byte {
                    b'A' => Key::Up,
                    b'B' => Key::Down,
                    _ => Key::Ignored,
                });
                index += 3;
                continue;
            }
            keys.push(Key::Quit);
            index += 1;
            continue;
        }
        keys.push(match byte {
            b'\r' | b'\n' => Key::Enter,
            b'k' => Key::Up,
            b'j' => Key::Down,
            // `q`, Ctrl-C and Ctrl-D. Raw mode means Ctrl-C is a byte, not a
            // signal, so quitting on it here is what makes the key still work.
            b'q' | 0x03 | 0x04 => Key::Quit,
            _ => Key::Ignored,
        });
        index += 1;
    }
    keys
}

/// What the person did with the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Chosen(usize),
    Cancelled,
}

/// The list and where the highlight is.
#[derive(Debug, Clone)]
pub struct Picker {
    rows: Vec<PickerRow>,
    selected: usize,
}

impl Picker {
    pub fn new(rows: Vec<PickerRow>) -> Self {
        Self { rows, selected: 0 }
    }

    pub fn rows(&self) -> &[PickerRow] {
        &self.rows
    }

    pub fn selected(&self) -> usize {
        self.selected
    }

    pub fn selected_row(&self) -> Option<&PickerRow> {
        self.rows.get(self.selected)
    }

    /// Apply one key. `None` means the list is still open.
    ///
    /// Moving wraps around: with four environments on screen at once, the end
    /// of the list is never far enough away for wrapping to lose anyone, and
    /// it saves holding a key down to get back to the top.
    pub fn press(&mut self, key: Key) -> Option<Choice> {
        if self.rows.is_empty() {
            return Some(Choice::Cancelled);
        }
        match key {
            Key::Up => {
                self.selected = (self.selected + self.rows.len() - 1) % self.rows.len();
                None
            }
            Key::Down => {
                self.selected = (self.selected + 1) % self.rows.len();
                None
            }
            Key::Enter => Some(Choice::Chosen(self.selected)),
            Key::Quit => Some(Choice::Cancelled),
            Key::Ignored => None,
        }
    }
}

pub const PICKER_HINT: &str = "up/down to move, enter to connect, q to quit";

/// The frame as plain text, one string per line, already fitted to the
/// terminal's width.
///
/// Plain text first and colour afterwards, so the layout can be asserted on and
/// so a line can never be wider than the terminal: a wrapped line would make
/// the redraw move the cursor up by the wrong number of lines and leave the
/// list smeared down the screen.
pub fn frame_lines(rows: &[PickerRow], selected: usize, cols: u16) -> Vec<String> {
    let table = view::render_table(
        &["SHORTNAME", "WORKSPACE", "MACHINE", "STATE"],
        &rows
            .iter()
            .map(|row| {
                vec![
                    row.shortname.clone().unwrap_or_else(|| "-".to_string()),
                    row.label.clone(),
                    row.machine_name.clone().unwrap_or_else(|| "-".to_string()),
                    row.state.clone(),
                ]
            })
            .collect::<Vec<_>>(),
    );
    let table: Vec<&str> = table.lines().collect();
    let width = table.iter().map(|line| line.chars().count()).max().unwrap_or(0);
    let mut lines: Vec<String> = table
        .iter()
        .enumerate()
        .map(|(index, line)| {
            // Row 0 of the table is the header, so a row's index is one less.
            let marker = if index > 0 && index - 1 == selected { "> " } else { "  " };
            let padding = width.saturating_sub(line.chars().count());
            format!("{marker}{line}{}", " ".repeat(padding))
        })
        .collect();
    lines.push(String::new());
    lines.push(format!("  {PICKER_HINT}"));
    let limit = usize::from(cols.max(1));
    lines
        .into_iter()
        .map(|line| line.chars().take(limit).collect::<String>())
        .collect()
}

const CLEAR_LINE: &str = "\x1b[2K";
const REVERSE: &str = "\x1b[7m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

/// One frame, ready to write to a raw terminal.
///
/// Every line clears itself first, so a shorter frame cannot leave the tail of
/// a longer one behind, and every line ends `\r\n`, because raw mode does not
/// add the carriage return.
pub fn render_frame(rows: &[PickerRow], selected: usize, cols: u16) -> String {
    let lines = frame_lines(rows, selected, cols);
    let hint_index = lines.len().saturating_sub(1);
    let mut frame = String::new();
    for (index, line) in lines.iter().enumerate() {
        frame.push_str(CLEAR_LINE);
        if index > 0 && index - 1 == selected {
            frame.push_str(REVERSE);
            frame.push_str(line);
            frame.push_str(RESET);
        } else if index == hint_index {
            frame.push_str(DIM);
            frame.push_str(line);
            frame.push_str(RESET);
        } else {
            frame.push_str(line);
        }
        frame.push_str("\r\n");
    }
    frame
}

/// Move the cursor back to the top of a frame of `lines` lines.
pub fn cursor_up(lines: usize) -> String {
    if lines == 0 { String::new() } else { format!("\x1b[{lines}A\r") }
}

// -- the loop --------------------------------------------------------------
//
// Everything below is the untestable half: raw bytes in, raw bytes out. It
// holds no rules of its own — every decision it makes comes from the functions
// above.

/// Show the list and wait for an answer. `None` means the person quit.
///
/// Blocking reads on the main thread, not the shell's reader thread: the shell
/// this may hand over to spawns that thread itself, and two readers on one
/// stdin would race for the person's keystrokes.
pub fn pick(rows: Vec<PickerRow>) -> Option<PickerRow> {
    if rows.is_empty() {
        return None;
    }
    let raw = crate::terminal::RawMode::enter();
    if !raw.interactive() {
        return None;
    }
    crate::terminal::hide_cursor();

    let mut picker = Picker::new(rows);
    let mut painted = 0usize;
    let mut buffer = [0u8; 64];
    let choice = loop {
        let cols = crate::terminal::terminal_size().cols;
        let frame = render_frame(picker.rows(), picker.selected(), cols);
        crate::terminal::write_output(&format!("{}{frame}", cursor_up(painted)));
        painted = frame_lines(picker.rows(), picker.selected(), cols).len();

        let Some(read) = crate::terminal::read_stdin(&mut buffer) else {
            // Local input ended; there is nobody left to choose.
            break Choice::Cancelled;
        };
        let mut outcome = None;
        for key in decode_keys(&buffer[..read]) {
            outcome = picker.press(key);
            if outcome.is_some() {
                break;
            }
        }
        if let Some(outcome) = outcome {
            break outcome;
        }
    };

    // Take the list back off the screen before anything else prints: what
    // follows is either a shell banner or nothing at all.
    crate::terminal::write_output(&format!("{}\x1b[J", cursor_up(painted)));
    crate::terminal::show_cursor();
    drop(raw);

    match choice {
        Choice::Chosen(index) => picker.rows().get(index).cloned(),
        Choice::Cancelled => None,
    }
}
