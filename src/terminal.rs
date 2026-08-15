//! The local end of `sv shell`: this terminal, in raw mode.
//!
//! Port of `src/localTerminal.ts`, which is the same four platform calls Node
//! makes underneath: `tcgetattr`/`tcsetattr` for raw mode, `TIOCGWINSZ` for the
//! size, `SIGWINCH` for resizes, `isatty` to know whether any of it applies.
//!
//! Raw mode is the one piece of global state this CLI mutates, so restoring it
//! is defended four ways: the guard's `Drop` (normal return and error return),
//! a panic hook (the release build aborts rather than unwinds, so `Drop` would
//! not run), and handlers for `SIGTERM`, `SIGHUP` and `SIGINT` that restore
//! before re-raising. A terminal left raw is a terminal the person has to close.

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

/// The size a non-TTY gets, so a piped run still opens a usable PTY.
pub const FALLBACK_COLS: u16 = 80;
pub const FALLBACK_ROWS: u16 = 24;

/// Sizes the workspace accepts (`TerminalOpenInput`). A window wider than this
/// is clamped rather than refused: a rejected resize would leave the remote PTY
/// at the wrong size with no way for the person to tell.
pub const MAX_COLS: u16 = 1_000;
pub const MAX_ROWS: u16 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    pub cols: u16,
    pub rows: u16,
}

pub fn normalize_size(cols: Option<u16>, rows: Option<u16>) -> TerminalSize {
    TerminalSize {
        cols: clamp(cols, FALLBACK_COLS, MAX_COLS),
        rows: clamp(rows, FALLBACK_ROWS, MAX_ROWS),
    }
}

fn clamp(value: Option<u16>, fallback: u16, max: u16) -> u16 {
    match value {
        Some(value) if value >= 1 => value.min(max),
        _ => fallback,
    }
}

/// True when both ends are a terminal. A pipe still runs a shell; there is just
/// nothing to put in raw mode and no resizes to propagate.
pub fn is_interactive() -> bool {
    // SAFETY: `isatty` only reads the descriptor's kind.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 && libc::isatty(libc::STDOUT_FILENO) == 1 }
}

/// The current window size, from the terminal itself.
pub fn terminal_size() -> TerminalSize {
    let mut window: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: `TIOCGWINSZ` writes one `winsize` into the pointer we own.
    let ok = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut window) } == 0;
    if !ok {
        return normalize_size(None, None);
    }
    normalize_size(Some(window.ws_col), Some(window.ws_row))
}

// -- raw mode --------------------------------------------------------------

static RAW_ACTIVE: AtomicBool = AtomicBool::new(false);
static mut SAVED_TERMIOS: Option<libc::termios> = None;

/// Restore the terminal if this process put it in raw mode.
///
/// `tcsetattr` is on POSIX's async-signal-safe list, which is what makes this
/// callable from a signal handler.
fn restore_terminal() {
    if !RAW_ACTIVE.swap(false, Ordering::SeqCst) {
        return;
    }
    // SAFETY: written once before `RAW_ACTIVE` was set, and read only after the
    // swap above has claimed the restore, so there is one reader and no writer.
    let saved = unsafe { SAVED_TERMIOS };
    if let Some(saved) = saved {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &saved);
        }
    }
}

extern "C" fn on_fatal_signal(signal: libc::c_int) {
    restore_terminal();
    // Re-raise with the default disposition so the exit status is honest about
    // having been signalled.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
}

extern "C" fn on_window_change(_signal: libc::c_int) {
    RESIZED.store(true, Ordering::SeqCst);
}

static RESIZED: AtomicBool = AtomicBool::new(false);

/// Raw mode, undone when this value is dropped.
pub struct RawMode {
    interactive: bool,
}

impl RawMode {
    /// Enter raw mode and arm every restore path.
    pub fn enter() -> Self {
        let interactive = is_interactive();
        if !interactive {
            return Self { interactive };
        }
        let mut current: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `tcgetattr` fills the struct we own.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut current) } != 0 {
            return Self { interactive: false };
        }
        let saved = current;
        // SAFETY: single-threaded at this point, before `RAW_ACTIVE` is set.
        unsafe {
            SAVED_TERMIOS = Some(saved);
            libc::cfmakeraw(&mut current);
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &current);
        }
        RAW_ACTIVE.store(true, Ordering::SeqCst);
        install_guards();
        Self { interactive }
    }

    pub fn interactive(&self) -> bool {
        self.interactive
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn install_guards() {
    // SAFETY: installing handlers for signals that would otherwise leave the
    // terminal raw. The handlers touch one atomic and `tcsetattr`.
    unsafe {
        for signal in [libc::SIGTERM, libc::SIGHUP, libc::SIGINT, libc::SIGQUIT] {
            libc::signal(signal, on_fatal_signal as *const () as libc::sighandler_t);
        }
        libc::signal(libc::SIGWINCH, on_window_change as *const () as libc::sighandler_t);
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        previous(info);
    }));
}

/// True once per local resize. The handler only sets a flag; reading the new
/// size happens on the main thread, where an `ioctl` is allowed.
pub fn take_resize() -> bool {
    RESIZED.swap(false, Ordering::SeqCst)
}

// -- input -----------------------------------------------------------------

/// What the reader thread saw.
pub enum Input {
    /// Bytes typed here, already whole UTF-8.
    Data(String),
    /// Local input ended: a closed pipe, or Ctrl-D with nothing buffered.
    Ended,
}

/// Read stdin on its own thread and hand complete UTF-8 to the main loop.
///
/// `libc::read` rather than `std::io::stdin`, because the shell needs each
/// keystroke as it lands and not whatever a `BufReader` decides to hold.
pub fn spawn_input_reader() -> Receiver<Input> {
    let (sender, receiver): (Sender<Input>, Receiver<Input>) = channel();
    std::thread::spawn(move || {
        let mut chunker = Utf8Chunker::default();
        let mut buffer = [0u8; 4096];
        loop {
            // SAFETY: reading into a buffer we own, on the descriptor this
            // thread is the only reader of.
            let read = unsafe {
                libc::read(libc::STDIN_FILENO, buffer.as_mut_ptr().cast(), buffer.len())
            };
            if read > 0 {
                let text = chunker.push(&buffer[..read as usize]);
                if !text.is_empty() && sender.send(Input::Data(text)).is_err() {
                    return;
                }
                continue;
            }
            if read < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
            }
            let _ = sender.send(Input::Ended);
            return;
        }
    });
    receiver
}

/// Holds back a trailing partial UTF-8 sequence, the way Node's
/// `StringDecoder` does, so a multi-byte character split across two reads is
/// not turned into replacement characters.
#[derive(Default)]
pub struct Utf8Chunker {
    carry: Vec<u8>,
}

impl Utf8Chunker {
    pub fn push(&mut self, bytes: &[u8]) -> String {
        self.carry.extend_from_slice(bytes);
        match std::str::from_utf8(&self.carry) {
            Ok(text) => {
                let text = text.to_string();
                self.carry.clear();
                text
            }
            Err(error) => {
                let valid = error.valid_up_to();
                // An invalid sequence is not a partial one; pass it through as
                // replacement characters rather than stalling the shell.
                let complete = match error.error_len() {
                    None => valid,
                    Some(length) => valid + length,
                };
                let text = String::from_utf8_lossy(&self.carry[..complete]).to_string();
                self.carry.drain(..complete);
                text
            }
        }
    }
}

/// Remote output, straight through.
pub fn write_output(data: &str) {
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(data.as_bytes());
    let _ = stdout.flush();
}

/// This process's stdin, stdout and window as the shell's local half.
///
/// Thin wrapper by design: everything with logic lives in `shell.rs` behind
/// `LocalTerminal`, so it can be tested without a tty.
pub struct ProcessTerminal {
    interactive: bool,
    input: Receiver<Input>,
    ended: bool,
}

impl ProcessTerminal {
    pub fn new(interactive: bool) -> Self {
        Self { interactive, input: spawn_input_reader(), ended: false }
    }
}

impl crate::shell::LocalTerminal for ProcessTerminal {
    fn size(&self) -> TerminalSize {
        terminal_size()
    }

    fn write(&mut self, data: &str) {
        write_output(data);
    }

    fn take_input(&mut self) -> crate::shell::InputPoll {
        if self.ended {
            return crate::shell::InputPoll::Ended;
        }
        match self.input.try_recv() {
            Ok(Input::Data(data)) => crate::shell::InputPoll::Data(data),
            Ok(Input::Ended) => {
                self.ended = true;
                crate::shell::InputPoll::Ended
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => crate::shell::InputPoll::None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.ended = true;
                crate::shell::InputPoll::Ended
            }
        }
    }

    fn take_resize(&mut self) -> bool {
        self.interactive && take_resize()
    }
}
