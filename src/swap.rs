//! What `sv host up` asks about this computer's swap.
//!
//! A Svartal machine runs workspace containers, and a workspace container
//! runs coding agents that each want a few hundred MiB. A machine with no
//! swap has no soft failure mode: the kernel cannot page anything out, so it
//! answers a spike by killing a process — usually the largest one, which is
//! the machine container itself rather than the workspace that caused it.
//! That is a machine that looks healthy right up until it isn't.
//!
//! Whose question this is depends on the computer, and only here:
//!
//! - On Linux, `sv host up` runs on the kernel that would do the swapping.
//!   Swap is this computer's to have, so a machine without it is asked about.
//! - On macOS and Windows, containers run on the engine's Linux VM. Docker
//!   Desktop and OrbStack size that VM's swap, `sv` cannot change it, and
//!   asking would offer something that cannot be delivered. So it says
//!   nothing.
//!
//! brok answers the same question from the machine's side once it is running
//! (`brok::swap`); this is the half that happens before there is a machine.

use std::io::Write;

/// The swapfile `sv` offers to create, and where it puts it.
pub const DEFAULT_SWAPFILE: &str = "/var/lib/svartal/swapfile";
pub const DEFAULT_SWAP_MIB: u64 = 2_048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    pub total_bytes: u64,
    pub free_bytes: u64,
}

/// What this computer's swap situation is, as far as `sv host up` cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// macOS or Windows: the engine's Linux VM owns the answer.
    EngineOwnsIt,
    /// Linux, and `/proc/meminfo` could not be read.
    Unreadable,
    Present { total_bytes: u64 },
    Missing,
}

/// What to tell the person, and whether there is anything to offer them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advice {
    /// `None` when there is nothing worth saying, which is the common case.
    pub message: Option<String>,
    /// Whether to ask about creating a swapfile.
    pub offer: bool,
}

/// `SwapTotal` and `SwapFree` out of a `/proc/meminfo` document. A document
/// without `SwapTotal` is `None`: a machine that cannot be read, not one
/// without swap, which reports `SwapTotal: 0 kB` like any other line.
pub fn parse_swap(text: &str) -> Option<Reading> {
    let field = |name: &str| -> Option<u64> {
        for line in text.lines() {
            let Some(rest) = line.strip_prefix(name) else { continue };
            let mut fields = rest.split_whitespace();
            let value: u64 = fields.next()?.parse().ok()?;
            return match fields.next() {
                Some("kB") | Some("KB") | None => Some(value * 1024),
                Some(_) => None,
            };
        }
        None
    };
    let total = field("SwapTotal:")?;
    Some(Reading { total_bytes: total, free_bytes: field("SwapFree:").unwrap_or(0) })
}

/// This computer's swap, as `sv host up` sees it.
pub fn verdict() -> Verdict {
    if !cfg!(target_os = "linux") {
        return Verdict::EngineOwnsIt;
    }
    let Ok(text) = std::fs::read_to_string("/proc/meminfo") else {
        return Verdict::Unreadable;
    };
    match parse_swap(&text) {
        Some(reading) if reading.total_bytes > 0 => {
            Verdict::Present { total_bytes: reading.total_bytes }
        }
        Some(_) => Verdict::Missing,
        None => Verdict::Unreadable,
    }
}

/// The sentence for a verdict, and whether it comes with an offer. Split from
/// the asking so the wording is testable without a terminal.
pub fn advice(verdict: &Verdict, want_mib: u64) -> Advice {
    match verdict {
        // Nothing to say: the common, healthy cases.
        Verdict::EngineOwnsIt | Verdict::Present { .. } => Advice { message: None, offer: false },
        Verdict::Unreadable => Advice {
            message: Some(
                "This computer's swap could not be read, so Svartal cannot tell whether it has a safety net when memory runs short.".to_string(),
            ),
            offer: false,
        },
        Verdict::Missing => Advice {
            message: Some(format!(
                "This computer has no swap. Workspaces run coding agents that each want a few hundred MiB, and without swap the kernel answers a spike by killing a process instead of paging one out — often this machine's own container. A {want_mib} MiB swapfile at {DEFAULT_SWAPFILE} would give it somewhere to go."
            )),
            offer: true,
        },
    }
}

/// How big a swapfile to offer. `SVARTAL_SWAPFILE_MIB` overrides it.
pub fn want_mib() -> u64 {
    std::env::var("SVARTAL_SWAPFILE_MIB")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value >= 128 && *value <= 1_048_576)
        .unwrap_or(DEFAULT_SWAP_MIB)
}

/// The commands that turn an empty path into live, persistent swap. Returned
/// rather than run so the person can be shown exactly what is about to
/// happen, and so a refusal leaves them something to run by hand.
pub fn creation_commands(path: &str, mib: u64) -> Vec<Vec<String>> {
    let owned = |parts: &[&str]| parts.iter().map(|part| part.to_string()).collect::<Vec<_>>();
    vec![
        owned(&["install", "-d", "-m", "0755", parent_of(path)]),
        owned(&["fallocate", "-l", &format!("{mib}M"), path]),
        owned(&["chmod", "600", path]),
        owned(&["mkswap", path]),
        owned(&["swapon", path]),
    ]
}

fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(index) => &path[..index],
    }
}

/// Run the creation commands, with `sudo` in front of each when this is not
/// already root. Stops at the first failure and says which step it was.
pub fn create(out: &mut dyn Write, path: &str, mib: u64) -> Result<(), String> {
    // SAFETY: geteuid takes nothing and cannot fail.
    let root = unsafe { libc::geteuid() == 0 };
    for command in creation_commands(path, mib) {
        let (program, args) = if root {
            (command[0].clone(), command[1..].to_vec())
        } else {
            ("sudo".to_string(), command.clone())
        };
        writeln!(out, "  {} {}", program, args.join(" ")).ok();
        let status = std::process::Command::new(&program)
            .args(&args)
            .status()
            .map_err(|error| format!("Could not run {program}: {error}"))?;
        if !status.success() {
            return Err(format!("`{} {}` failed.", program, args.join(" ")));
        }
    }
    // Swap that does not survive a reboot is missing exactly when nobody is
    // watching. This is the one step that is only advice: appending to
    // /etc/fstab through sudo is awkward to do safely from here, and a live
    // swapfile is already the win.
    writeln!(
        out,
        "\nSwap is on now. To keep it after a reboot, add this line to /etc/fstab:\n  {path} none swap sw 0 0"
    )
    .ok();
    Ok(())
}

/// The creation commands as something a person can paste into a shell.
pub fn creation_script(path: &str, mib: u64) -> String {
    creation_commands(path, mib)
        .into_iter()
        .map(|command| format!("  sudo {}", command.join(" ")))
        .collect::<Vec<_>>()
        .join("\n")
}

fn confirm(out: &mut dyn Write, question: &str) -> bool {
    write!(out, "{question} [y/N] ").ok();
    out.flush().ok();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// The swap half of `sv host up`'s preflight.
///
/// This never refuses. A machine with no swap is a worse machine, not an
/// impossible one, and someone who says no to the offer still gets their
/// machine — with the reason written down once, where they saw it.
pub fn preflight(out: &mut dyn Write, interactive: bool) {
    let mib = want_mib();
    let advice = advice(&verdict(), mib);
    let Some(message) = advice.message else { return };
    writeln!(out, "{message}").ok();
    if !advice.offer {
        return;
    }
    if !interactive {
        writeln!(out, "Create it with:\n{}", creation_script(DEFAULT_SWAPFILE, mib)).ok();
        return;
    }
    if !confirm(out, &format!("Create a {mib} MiB swapfile now?")) {
        writeln!(
            out,
            "Continuing without swap. You can create it later with:\n{}",
            creation_script(DEFAULT_SWAPFILE, mib)
        )
        .ok();
        return;
    }
    if let Err(reason) = create(out, DEFAULT_SWAPFILE, mib) {
        writeln!(out, "{reason}\nContinuing without swap.").ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn a_machine_with_no_swap_is_offered_one_and_a_healthy_one_is_left_alone() {
        let missing = advice(&Verdict::Missing, 2_048);
        assert!(missing.offer);
        let message = missing.message.expect("a machine with no swap is told");
        assert!(message.contains("no swap"), "message: {message}");
        assert!(message.contains("2048 MiB"), "message: {message}");

        // The quiet cases say nothing at all.
        assert_eq!(
            advice(&Verdict::Present { total_bytes: 4 * 1024 * MIB }, 2_048),
            Advice { message: None, offer: false }
        );
        assert_eq!(
            advice(&Verdict::EngineOwnsIt, 2_048),
            Advice { message: None, offer: false }
        );
    }

    #[test]
    fn an_unreadable_machine_is_reported_but_never_offered_a_swapfile() {
        let advice = advice(&Verdict::Unreadable, 2_048);
        assert!(!advice.offer, "nothing is offered for a machine that cannot be read");
        assert!(advice.message.is_some());
    }

    #[test]
    fn swap_is_read_from_meminfo_and_zero_is_an_answer() {
        let present = parse_swap("SwapCached: 0 kB\nSwapTotal: 2097148 kB\nSwapFree: 2000000 kB\n")
            .expect("reads");
        assert_eq!(present.total_bytes, 2_097_148 * 1024);
        assert_eq!(present.free_bytes, 2_000_000 * 1024);
        // The Hetzner shape.
        assert_eq!(parse_swap("SwapTotal: 0 kB\nSwapFree: 0 kB\n").unwrap().total_bytes, 0);
        // Unreadable is not the same as none.
        assert_eq!(parse_swap("MemTotal: 3911560 kB\n"), None);
    }

    #[test]
    fn the_commands_make_the_file_private_before_it_holds_anything() {
        let commands = creation_commands("/var/lib/svartal/swapfile", 2_048);
        let names: Vec<&str> = commands.iter().map(|command| command[0].as_str()).collect();
        assert_eq!(names, vec!["install", "fallocate", "chmod", "mkswap", "swapon"]);
        // Whatever gets paged out is readable by anyone who can read the
        // file, so 600 has to land before mkswap, not after swapon.
        let chmod = names.iter().position(|name| *name == "chmod").unwrap();
        let mkswap = names.iter().position(|name| *name == "mkswap").unwrap();
        assert!(chmod < mkswap);
        assert!(commands[1].contains(&"2048M".to_string()));
    }

    #[test]
    fn the_parent_directory_is_the_one_the_swapfile_lives_in() {
        assert_eq!(parent_of("/var/lib/svartal/swapfile"), "/var/lib/svartal");
        assert_eq!(parent_of("/swapfile"), "/");
        assert_eq!(parent_of("swapfile"), "/");
    }

    #[test]
    fn the_offered_size_is_bounded() {
        // The variable is process-global; this test only reads the default.
        if std::env::var_os("SVARTAL_SWAPFILE_MIB").is_none() {
            assert_eq!(want_mib(), DEFAULT_SWAP_MIB);
        }
    }
}
