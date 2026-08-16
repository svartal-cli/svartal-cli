//! The list bare `sv` shows, and one rule about what this CLI calls itself.
//!
//! The picker's loop cannot be tested — it reads a terminal — so everything
//! that decides anything lives outside it: which rows exist, what a keystroke
//! means, and what one frame looks like. Those are what is tested here.

mod common;

use serde_json::json;

use svartal::api::{LinkRecord, Machine};
use svartal::picker::{
    Choice, Key, PICKER_HINT, Picker, PickerRow, build_picker_rows, cursor_up, decode_keys,
    frame_lines, render_frame,
};
use svartal::shortnames::Shortnames;
use svartal::view::{MachinesView, build_machines_view};

fn view(presence: &str) -> MachinesView {
    let machines: Vec<Machine> = vec![
        serde_json::from_value(json!({
            "id": "machine-1",
            "name": "workbench",
            "origin": "donated",
            "lifecycleState": "open",
            "presence": presence,
            "lastSeenAt": null,
            "environments": [
                { "id": "row-1", "environmentId": "env-primary", "label": "Primary", "kind": "personal", "lifecycleState": "active" },
                { "id": "row-2", "environmentId": "env-second", "label": "Second", "kind": "workspace", "lifecycleState": "active" },
            ],
        }))
        .unwrap(),
    ];
    let links: Vec<LinkRecord> = vec![
        serde_json::from_value(json!({
            "environmentId": "env-primary",
            "label": "Primary",
            "endpoint": {
                "httpBaseUrl": "https://workspace.example.test",
                "wsBaseUrl": "wss://workspace.example.test",
                "providerKind": "cloudflare_tunnel",
            },
            "linkedAt": "2026-08-01T10:00:00Z",
        }))
        .unwrap(),
    ];
    build_machines_view(&machines, &links)
}

fn rows() -> Vec<PickerRow> {
    let mut names = Shortnames::new();
    names.assign("web", "env-primary").unwrap();
    build_picker_rows(&view("online"), &names)
}

// -- the rows --------------------------------------------------------------

#[test]
fn every_environment_is_listed_with_its_name_and_what_connecting_would_find() {
    let listed = rows();
    assert_eq!(
        listed
            .iter()
            .map(|row| (row.environment_id.as_str(), row.shortname.as_deref(), row.state.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("env-primary", Some("web"), "online"),
            // Listed, with the reason it cannot be picked, rather than hidden.
            ("env-second", None, "not linked"),
        ]
    );
    assert_eq!(listed[0].machine_name.as_deref(), Some("workbench"));

    // A machine that never checked in says so rather than claiming offline.
    let quiet = build_picker_rows(&view("unknown"), &Shortnames::new());
    assert_eq!(quiet[0].state, "unknown");
}

// -- the keys --------------------------------------------------------------

#[test]
fn the_keys_are_the_arrows_j_k_enter_and_a_way_out() {
    assert_eq!(decode_keys(b"\x1b[A"), vec![Key::Up]);
    assert_eq!(decode_keys(b"\x1b[B"), vec![Key::Down]);
    // Application keypad mode sends `Esc O A` for the same key.
    assert_eq!(decode_keys(b"\x1bOA"), vec![Key::Up]);
    assert_eq!(decode_keys(b"k"), vec![Key::Up]);
    assert_eq!(decode_keys(b"j"), vec![Key::Down]);
    assert_eq!(decode_keys(b"\r"), vec![Key::Enter]);
    assert_eq!(decode_keys(b"\n"), vec![Key::Enter]);
    for quit in [&b"q"[..], &b"\x1b"[..], &[0x03][..], &[0x04][..]] {
        assert_eq!(decode_keys(quit), vec![Key::Quit], "{quit:?} should quit");
    }
    // Left and right mean nothing in a list, and are not guessed at.
    assert_eq!(decode_keys(b"\x1b[C"), vec![Key::Ignored]);
    assert_eq!(decode_keys(b"x"), vec![Key::Ignored]);
    // One read can carry several keystrokes, and they all count.
    assert_eq!(
        decode_keys(b"\x1b[B\x1b[Bj\r"),
        vec![Key::Down, Key::Down, Key::Down, Key::Enter]
    );
    assert!(decode_keys(b"").is_empty());
}

#[test]
fn moving_wraps_and_enter_answers_with_the_highlighted_row() {
    let mut picker = Picker::new(rows());
    assert_eq!(picker.selected(), 0);
    assert_eq!(picker.press(Key::Down), None);
    assert_eq!(picker.selected(), 1);
    // Past the end is back to the top, and past the top is back to the end.
    assert_eq!(picker.press(Key::Down), None);
    assert_eq!(picker.selected(), 0);
    assert_eq!(picker.press(Key::Up), None);
    assert_eq!(picker.selected(), 1);
    // A key with no meaning here moves nothing.
    assert_eq!(picker.press(Key::Ignored), None);
    assert_eq!(picker.selected(), 1);
    assert_eq!(picker.selected_row().unwrap().environment_id, "env-second");
    assert_eq!(picker.press(Key::Enter), Some(Choice::Chosen(1)));
}

#[test]
fn quitting_is_an_answer_too_and_an_empty_list_has_nothing_to_pick() {
    let mut picker = Picker::new(rows());
    assert_eq!(picker.press(Key::Quit), Some(Choice::Cancelled));

    let mut empty = Picker::new(Vec::new());
    assert_eq!(empty.press(Key::Enter), Some(Choice::Cancelled));
    assert_eq!(empty.press(Key::Down), Some(Choice::Cancelled));
    assert!(empty.selected_row().is_none());
}

// -- the frame -------------------------------------------------------------

#[test]
fn the_frame_is_a_table_a_marker_and_one_line_of_help() {
    let listed = rows();
    let lines = frame_lines(&listed, 0, 80);
    assert_eq!(lines.len(), listed.len() + 3, "a header, the rows, a blank line, the hint");
    assert!(lines[0].starts_with("  SHORTNAME"));
    assert!(lines[1].starts_with("> web"), "the highlighted row is marked without colour too");
    assert!(lines[1].contains("Primary") && lines[1].contains("workbench") && lines[1].contains("online"));
    assert!(lines[2].starts_with("  -"));
    assert_eq!(lines[lines.len() - 2], "");
    assert_eq!(lines[lines.len() - 1], format!("  {PICKER_HINT}"));

    // The marker follows the selection, and only one row carries it.
    let moved = frame_lines(&listed, 1, 80);
    assert!(moved[1].starts_with("  web"));
    assert!(moved[2].starts_with("> -"));
    assert_eq!(moved.iter().filter(|line| line.starts_with("> ")).count(), 1);
}

#[test]
fn every_line_is_padded_to_one_width_and_never_wider_than_the_terminal() {
    let listed = rows();
    let lines = frame_lines(&listed, 0, 80);
    let table_widths: Vec<usize> =
        lines[..=listed.len()].iter().map(|line| line.chars().count()).collect();
    assert!(
        table_widths.windows(2).all(|pair| pair[0] == pair[1]),
        "the highlight bar is even: {table_widths:?}"
    );

    // A narrow terminal truncates. A line wider than the window would wrap,
    // and a wrapped line would make the redraw move up by the wrong count.
    for line in frame_lines(&listed, 0, 12) {
        assert!(line.chars().count() <= 12, "{line:?}");
    }
    for line in frame_lines(&listed, 0, 1) {
        assert!(line.chars().count() <= 1, "{line:?}");
    }
}

#[test]
fn a_frame_clears_what_it_overwrites_and_ends_its_lines_for_a_raw_terminal() {
    let frame = render_frame(&rows(), 0, 80);
    let lines: Vec<&str> = frame.split("\r\n").collect();
    // Every line but the trailing empty one after the last `\r\n`.
    assert_eq!(lines.len(), frame_lines(&rows(), 0, 80).len() + 1);
    assert_eq!(lines.last().copied(), Some(""));
    assert!(lines[..lines.len() - 1].iter().all(|line| line.starts_with("\x1b[2K")));
    // Raw mode does not add the carriage return, so a bare newline would leave
    // the next line indented where the last one ended.
    assert!(
        frame.match_indices('\n').all(|(index, _)| frame.as_bytes()[index - 1] == b'\r'),
        "each line break is a carriage return too"
    );
    // The selected row is reversed, and every sequence that opens is closed.
    assert!(frame.contains("\x1b[7m"));
    assert_eq!(
        frame.matches("\x1b[0m").count(),
        frame.matches("\x1b[7m").count() + frame.matches("\x1b[2m").count()
    );

    assert_eq!(cursor_up(0), "");
    assert_eq!(cursor_up(5), "\x1b[5A\r");
}

// -- what this CLI calls itself --------------------------------------------

/// The command is `sv`. `Svartal` is the product, and the code keeps
/// `svartal-cli`, `svartal-shell:` and `~/.config/svartal` as identifiers, but
/// no sentence this program prints may tell a person to run `svartal`.
///
/// This is a regression test for a real bug: the rename from `svartal` to `sv`
/// left the unknown-command error saying "Run `svartal --help`", which is
/// advice that does not work on any machine.
#[test]
fn no_source_line_tells_anyone_to_run_a_command_called_svartal() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offences: Vec<String> = Vec::new();
    for directory in ["src", "tests"] {
        for entry in std::fs::read_dir(root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }
            // This file quotes the mistake it is looking for.
            if path.file_name().and_then(|name| name.to_str()) == Some("picker_and_strings.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for (number, line) in text.lines().enumerate() {
                for (column, _) in line.match_indices("svartal") {
                    // A path (`~/.config/svartal`), a crate path
                    // (`svartal::view`) or a hyphenated identifier
                    // (`svartal-cli`) is not a command.
                    let before = line[..column].chars().next_back();
                    if matches!(before, Some('/' | '-' | '@' | '.')) {
                        continue;
                    }
                    let rest = &line[column + "svartal".len()..];
                    let mut characters = rest.chars();
                    let next = characters.next();
                    let after = characters.next();
                    // `` `svartal` `` on its own, or `svartal ` followed by a
                    // word or a flag: both read as a command to run.
                    let looks_like_a_command = next == Some('`')
                        || (next == Some(' ')
                            && matches!(after, Some(character) if character.is_ascii_lowercase() || character == '-'));
                    if looks_like_a_command {
                        offences.push(format!(
                            "{}:{}: {}",
                            path.file_name().unwrap().to_string_lossy(),
                            number + 1,
                            line.trim()
                        ));
                    }
                }
            }
        }
    }
    assert!(offences.is_empty(), "the command is `sv`:\n{}", offences.join("\n"));
}

/// The other half of the same rule: the usage text, which is the first thing a
/// new person reads, says `sv` and spells the product with a capital S.
#[test]
fn the_help_text_names_the_command_sv_and_the_product_svartal() {
    let usage = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"),
    )
    .unwrap();
    assert!(usage.contains("Usage: sv [command] [options]"));
    assert!(usage.contains("Work with your Svartal machines from the terminal."));
    assert!(usage.contains("is not an sv command. Run `sv --help` to see what is."));
    for command in ["envs", "name", "shell <target>", "claude [target]"] {
        assert!(usage.contains(command), "{command} is missing from the usage");
    }
}
