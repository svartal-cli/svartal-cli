//! Turning the two listings into what a person sees.
//!
//! Port of `src/view.ts`, including the exact table shape and the exact
//! sentences. The wording is not incidental: `REACHABLE` is a link record and
//! `MACHINE` is the box's own heartbeat, and the note under the table exists so
//! the CLI never implies it probed anything.

use serde::Serialize;
use serde_json::json;

use crate::api::{LinkRecord, Machine};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceRow {
    pub machine_id: String,
    pub machine_name: String,
    /// The word the machine's owner gave it in Svartal, when there is one.
    pub machine_short_name: Option<String>,
    pub machine_presence: String,
    pub environment_id: String,
    pub label: String,
    /// The word the machine's owner gave this workspace in Svartal. `label` is
    /// generated, so this is the only one of the two anybody chose.
    pub short_name: Option<String>,
    pub kind: String,
    pub lifecycle_state: String,
    /// The username whose personal workspace this is, when Svartal said so.
    pub owner: Option<String>,
    /// True when this identity holds a relay link to the workspace.
    pub linked: bool,
    pub linked_at: Option<String>,
    /// What Svartal intends this workspace to be, when it said so. It is the
    /// difference between a link that is gone and a link that is coming back;
    /// see `reachable_cell`.
    pub intent_state: Option<String>,
    /// A personal workspace owned by somebody else. Not printed and not
    /// serialised: it is a judgement about the person reading the listing,
    /// not a fact about the workspace, so it is recomputed every time a view
    /// is built and never travels anywhere.
    #[serde(skip)]
    pub belongs_to_another: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachinesView {
    pub rows: Vec<WorkspaceRow>,
    /// Relay links whose workspace is not on any machine this person can list.
    /// They are real and reachable, so hiding them would be a lie; they usually
    /// mean a box was linked directly without being registered.
    pub unregistered_links: Vec<LinkRecord>,
}

impl MachinesView {
    /// The same view with other people's personal workspaces left out.
    ///
    /// This is what a listing shows by default. A second person's personal
    /// workspace on a machine you own is on your machine, but it is not yours
    /// to open, and a list of things you cannot open is not your list. The
    /// same goes for an unclaimed one: nobody owns it and nobody can open it
    /// (`--all` still shows it, marked `unclaimed`).
    pub fn yours(&self) -> Self {
        Self {
            rows: self
                .rows
                .iter()
                .filter(|row| {
                    !row.belongs_to_another
                        && !unclaimed(&row.kind, row.linked, row.intent_state.as_deref())
                })
                .cloned()
                .collect(),
            unregistered_links: self.unregistered_links.clone(),
        }
    }
}

/// Said once, everywhere the CLI would otherwise imply it knows more than it
/// does.
pub const MACHINE_STATE_NOTE: &str = "REACHABLE is your relay link, not a live check: relinking means Svartal is restoring your link, so run `sv host up` on that machine; unclaimed means nobody owns that workspace. HEARTBEAT is the box's last heartbeat: unknown means it has never reported.";

/// A machine as one cell: the word its owner chose, with the name the host
/// derived from its own hostname kept in brackets so nothing a person already
/// recognised disappears.
pub fn machine_cell(name: &str, short_name: Option<&str>) -> String {
    match short_name.map(str::trim).filter(|value| !value.is_empty()) {
        Some(short) if short != name => format!("{short} ({name})"),
        Some(short) => short.to_string(),
        None => name.to_string(),
    }
}

pub const SESSIONS_NOT_EXPOSED_NOTE: &str = "Live agent sessions are not readable with a terminal sign-in yet. They live on the workspace itself and need a connected session, which this CLI cannot open yet. See NOTES.md in the svartal-cli package.";

/// Whether a workspace belongs to somebody other than the person reading the
/// listing.
///
/// All three facts have to be there: the workspace is a personal one, Svartal
/// named its owner, and this terminal knows the name it is signed in under. An
/// answer missing any of them is not evidence that a workspace is somebody
/// else's, and hiding a row on a guess would lose a person their own
/// workspace. Older servers send no owner at all, and that is exactly the case
/// this keeps unchanged.
fn belongs_to_another(kind: Option<&str>, owner: Option<&str>, viewer: Option<&str>) -> bool {
    let (Some(owner), Some(viewer)) = (owner, viewer) else {
        return false;
    };
    let same = |left: &str, right: &str| left.trim().eq_ignore_ascii_case(right.trim());
    kind.map(str::trim) == Some("personal") && !same(owner, viewer)
}

fn present(value: Option<&str>, fallback: &str) -> String {
    match value.map(str::trim) {
        Some(text) if !text.is_empty() => text.to_string(),
        _ => fallback.to_string(),
    }
}

/// The joined listing, as seen by one person.
///
/// `viewer` is the username this terminal is signed in as, when the session
/// carries one. It decides nothing about what Svartal returned; it only marks
/// which rows are somebody else's personal workspace, which the listings and
/// target resolution then leave out.
pub fn build_machines_view(
    machines: &[Machine],
    links: &[LinkRecord],
    viewer: Option<&str>,
) -> MachinesView {
    let mut rows = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for machine in machines {
        for workspace in &machine.environments {
            let link = links
                .iter()
                .find(|link| link.environment_id == workspace.environment_id);
            seen.push(workspace.environment_id.as_str());
            rows.push(WorkspaceRow {
                machine_id: machine.id.clone(),
                machine_name: machine.name.clone(),
                machine_short_name: machine.short_name.clone(),
                machine_presence: present(Some(machine.presence.as_str()), "unknown"),
                environment_id: workspace.environment_id.clone(),
                label: present(workspace.label.as_deref(), &workspace.environment_id),
                short_name: workspace.short_name.clone(),
                kind: present(workspace.kind.as_deref(), "-"),
                lifecycle_state: present(workspace.lifecycle_state.as_deref(), "-"),
                owner: workspace.owner.clone(),
                linked: link.is_some(),
                linked_at: link.map(|link| link.linked_at.clone()),
                intent_state: workspace.intent_state.clone(),
                belongs_to_another: belongs_to_another(
                    workspace.kind.as_deref(),
                    workspace.owner.as_deref(),
                    viewer,
                ),
            });
        }
    }
    let unregistered_links = links
        .iter()
        .filter(|link| !seen.contains(&link.environment_id.as_str()))
        .cloned()
        .collect();
    MachinesView { rows, unregistered_links }
}

/// Every column padded to its widest cell, two spaces between them, no
/// trailing whitespace.
pub fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(column, header)| {
            rows.iter()
                .map(|row| row.get(column).map(|cell| cell.chars().count()).unwrap_or(0))
                .fold(header.chars().count(), usize::max)
        })
        .collect();
    let line = |cells: &[String]| -> String {
        let rendered: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(column, cell)| {
                if column + 1 == cells.len() {
                    cell.clone()
                } else {
                    let width = widths.get(column).copied().unwrap_or_else(|| cell.chars().count());
                    let padding = width.saturating_sub(cell.chars().count());
                    format!("{cell}{}", " ".repeat(padding))
                }
            })
            .collect();
        rendered.join("  ").trim_end().to_string()
    };
    let header_cells: Vec<String> = headers.iter().map(|header| (*header).to_string()).collect();
    let mut lines = vec![line(&header_cells)];
    for row in rows {
        lines.push(line(row));
    }
    lines.join("\n")
}

/// The username column's cell: the owner Svartal named, or a dash when it
/// named none.
fn owner_cell(owner: Option<&String>) -> String {
    owner.cloned().unwrap_or_else(|| "-".to_string())
}

/// The `REACHABLE` cell: whether this identity can open the workspace, and
/// when it cannot, the one word that says why.
///
/// A link is either there or it is not, but `not linked` was three different
/// situations wearing one word. Svartal's intent tells them apart: `relinking`
/// is a link it is putting back, and `unclaimed` is a personal workspace
/// nobody owns. Every other answer, including a server old enough to send no
/// intent at all, keeps reading `not linked` exactly as before.
///
/// Said in one place because three listings print this cell — `sv machines`,
/// `sv envs`, and the picker — and a person comparing them must not find three
/// different words for one workspace.
pub fn reachable_cell(linked: bool, intent_state: Option<&str>) -> String {
    if linked {
        return "linked".to_string();
    }
    match intent_state.map(str::trim) {
        Some("relinking") => "relinking".to_string(),
        Some("unclaimed") => "unclaimed".to_string(),
        _ => "not linked".to_string(),
    }
}

/// `show_owner` is `--all`: the column exists only in the listing that shows
/// other people's workspaces, because that is the only listing where the
/// answer is ever anything but yourself.
pub fn format_machines_view(view: &MachinesView, show_owner: bool) -> String {
    if view.rows.is_empty() && view.unregistered_links.is_empty() {
        return "No machines yet. Register one in the Svartal web app, then link it from the box."
            .to_string();
    }
    let mut sections: Vec<String> = Vec::new();
    if !view.rows.is_empty() {
        let mut headers = vec!["MACHINE", "WORKSPACE", "WORKSPACE ID", "KIND"];
        if show_owner {
            headers.push("OWNER");
        }
        headers.extend(["STATE", "REACHABLE", "HEARTBEAT"]);
        sections.push(render_table(
            &headers,
            &view
                .rows
                .iter()
                .map(|row| {
                    let mut cells = vec![
                        machine_cell(&row.machine_name, row.machine_short_name.as_deref()),
                        row.short_name.clone().unwrap_or_else(|| row.label.clone()),
                        row.environment_id.clone(),
                        row.kind.clone(),
                    ];
                    if show_owner {
                        cells.push(owner_cell(row.owner.as_ref()));
                    }
                    cells.extend([
                        row.lifecycle_state.clone(),
                        reachable_cell(row.linked, row.intent_state.as_deref()),
                        row.machine_presence.clone(),
                    ]);
                    cells
                })
                .collect::<Vec<_>>(),
        ));
    }
    if !view.unregistered_links.is_empty() {
        sections.push(format!(
            "Linked workspaces that are not registered on any machine you can see:\n{}",
            render_table(
                &["WORKSPACE", "WORKSPACE ID"],
                &view
                    .unregistered_links
                    .iter()
                    .map(|link| vec![link.label.clone(), link.environment_id.clone()])
                    .collect::<Vec<_>>(),
            )
        ));
    }
    sections.join("\n\n")
}

// -- environments ----------------------------------------------------------

/// One row of `sv envs`: the same data `sv machines` prints, with the
/// workspace rather than the machine as the subject, and the short name in
/// front of it.
///
/// A workspace that is linked but sits on no machine this person can list is a
/// row here too. `sv machines` puts those in a second table because that table
/// is about machines and they have none; an environment listing has no reason
/// to separate them.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvRow {
    pub shortname: Option<String>,
    pub label: String,
    pub environment_id: String,
    pub machine_name: Option<String>,
    pub kind: String,
    pub lifecycle_state: String,
    /// The username whose personal workspace this is, when Svartal said so.
    pub owner: Option<String>,
    pub linked: bool,
    /// What Svartal intends this workspace to be; see `reachable_cell`.
    pub intent_state: Option<String>,
    pub machine_presence: Option<String>,
    /// A personal workspace owned by somebody else; see `WorkspaceRow`.
    #[serde(skip)]
    pub belongs_to_another: bool,
}

pub fn build_env_rows(
    view: &MachinesView,
    shortnames: &crate::shortnames::Shortnames,
) -> Vec<EnvRow> {
    let mut rows: Vec<EnvRow> = view
        .rows
        .iter()
        .map(|row| EnvRow {
            // Svartal's answer first: it is what everyone else reading this
            // workspace sees. A local name is a leftover from before names
            // were stored, and still resolves.
            shortname: row
                .short_name
                .clone()
                .or_else(|| shortnames.shortname_of(&row.environment_id).map(str::to_string)),
            label: row.label.clone(),
            environment_id: row.environment_id.clone(),
            machine_name: Some(machine_cell(&row.machine_name, row.machine_short_name.as_deref())),
            kind: row.kind.clone(),
            lifecycle_state: row.lifecycle_state.clone(),
            owner: row.owner.clone(),
            linked: row.linked,
            intent_state: row.intent_state.clone(),
            machine_presence: Some(row.machine_presence.clone()),
            belongs_to_another: row.belongs_to_another,
        })
        .collect();
    for link in &view.unregistered_links {
        rows.push(EnvRow {
            shortname: shortnames.shortname_of(&link.environment_id).map(str::to_string),
            label: link.label.clone(),
            environment_id: link.environment_id.clone(),
            machine_name: None,
            kind: "-".to_string(),
            lifecycle_state: "-".to_string(),
            owner: None,
            // A link record is the proof of reachability, so these are linked
            // by definition.
            linked: true,
            // A link record carries no intent, and a linked row never needs
            // one: the cell reads `linked` either way.
            intent_state: None,
            machine_presence: None,
            // A link this identity holds is never somebody else's workspace.
            belongs_to_another: false,
        });
    }
    rows
}

pub const NO_ENVIRONMENTS: &str =
    "No workspaces yet. Register a machine in the Svartal web app, then link it from the box.";

/// The rows of your own listing: everything except a personal workspace that
/// belongs to somebody else, or one that belongs to nobody at all.
///
/// An unclaimed personal workspace has nobody's intent behind it and no link
/// to it: nobody owns it and nobody can open it, so it is a leftover, not a
/// row in this person's list. `--all` still shows it, marked `unclaimed`,
/// because something that exists has to be findable somewhere. A row from a
/// server that sends no intent is untouched by this: not knowing is not a
/// reason to drop somebody's workspace.
pub fn own_env_rows(rows: &[EnvRow]) -> Vec<EnvRow> {
    rows.iter().filter(|row| !row.belongs_to_another && !is_unclaimed(row)).cloned().collect()
}

/// A personal workspace with nobody's intent behind it and no link to it.
/// One rule for `sv machines` (`MachinesView::yours`) and `sv envs`
/// (`own_env_rows`), so the two default listings never disagree about a row.
fn unclaimed(kind: &str, linked: bool, intent_state: Option<&str>) -> bool {
    kind.trim() == "personal" && !linked && intent_state.map(str::trim) == Some("unclaimed")
}

fn is_unclaimed(row: &EnvRow) -> bool {
    unclaimed(&row.kind, row.linked, row.intent_state.as_deref())
}

/// `show_owner` is `--all`, exactly as in `format_machines_view`.
pub fn format_envs_view(rows: &[EnvRow], show_owner: bool) -> String {
    if rows.is_empty() {
        return NO_ENVIRONMENTS.to_string();
    }
    let mut headers = vec!["SHORTNAME", "WORKSPACE", "WORKSPACE ID", "MACHINE", "KIND"];
    if show_owner {
        headers.push("OWNER");
    }
    headers.extend(["STATE", "REACHABLE", "HEARTBEAT"]);
    render_table(
        &headers,
        &rows
            .iter()
            .map(|row| {
                let mut cells = vec![
                    row.shortname.clone().unwrap_or_else(|| "-".to_string()),
                    row.label.clone(),
                    row.environment_id.clone(),
                    row.machine_name.clone().unwrap_or_else(|| "-".to_string()),
                    row.kind.clone(),
                ];
                if show_owner {
                    cells.push(owner_cell(row.owner.as_ref()));
                }
                cells.extend([
                    row.lifecycle_state.clone(),
                    reachable_cell(row.linked, row.intent_state.as_deref()),
                    row.machine_presence.clone().unwrap_or_else(|| "-".to_string()),
                ]);
                cells
            })
            .collect::<Vec<_>>(),
    )
}

pub fn format_envs_json(rows: &[EnvRow]) -> String {
    pretty(&json!({ "environments": rows }))
}

pub fn format_sessions_view(view: &MachinesView) -> String {
    let reachable: Vec<&WorkspaceRow> = view.rows.iter().filter(|row| row.linked).collect();
    if reachable.is_empty() {
        return format!("No workspace you can reach.\n\n{SESSIONS_NOT_EXPOSED_NOTE}");
    }
    let table = render_table(
        &["MACHINE", "WORKSPACE", "WORKSPACE ID", "LINKED SINCE"],
        &reachable
            .iter()
            .map(|row| {
                vec![
                    machine_cell(&row.machine_name, row.machine_short_name.as_deref()),
                    row.short_name.clone().unwrap_or_else(|| row.label.clone()),
                    row.environment_id.clone(),
                    row.linked_at.clone().unwrap_or_else(|| "-".to_string()),
                ]
            })
            .collect::<Vec<_>>(),
    );
    format!("{table}\n\n{SESSIONS_NOT_EXPOSED_NOTE}")
}

/// `--json` output. These are presentation shapes built here and never parsed
/// back, so they are plain serialisation, not a decode boundary.
pub fn format_machines_json(view: &MachinesView) -> String {
    pretty(&json!({
        "workspaces": view.rows,
        "unregisteredLinks": view.unregistered_links,
    }))
}

pub fn format_sessions_json(view: &MachinesView) -> String {
    let workspaces: Vec<&WorkspaceRow> = view.rows.iter().filter(|row| row.linked).collect();
    pretty(&json!({
        // Explicitly null, not an empty list: the CLI does not know of zero
        // sessions, it cannot see sessions at all yet.
        "sessions": serde_json::Value::Null,
        "sessionsAvailable": false,
        "note": SESSIONS_NOT_EXPOSED_NOTE,
        "workspaces": workspaces,
    }))
}

pub fn format_user_json(user: &crate::store::StoredUser) -> String {
    pretty(&json!({
        "subject": user.sub,
        "username": user.preferred_username,
        "name": user.name,
        "email": user.email,
    }))
}

pub fn describe_user(user: &crate::store::StoredUser) -> Vec<String> {
    let mut lines = vec![format!("Subject: {}", user.sub)];
    if let Some(username) = &user.preferred_username {
        lines.push(format!("Username: {username}"));
    }
    if let Some(name) = &user.name {
        lines.push(format!("Name: {name}"));
    }
    if let Some(email) = &user.email {
        lines.push(format!("Email: {email}"));
    }
    lines
}

pub fn filter_view_by_machine(view: &MachinesView, machine: &str) -> MachinesView {
    let needle = machine.trim().to_lowercase();
    MachinesView {
        rows: view
            .rows
            .iter()
            .filter(|row| {
                row.machine_name.to_lowercase() == needle
                    || row.machine_short_name.as_deref().map(str::to_lowercase).as_deref()
                        == Some(needle.as_str())
                    || row.machine_id.to_lowercase() == needle
                    || row.environment_id.to_lowercase() == needle
                    || row.short_name.as_deref().map(str::to_lowercase).as_deref()
                        == Some(needle.as_str())
            })
            .cloned()
            .collect(),
        unregistered_links: view
            .unregistered_links
            .iter()
            .filter(|link| {
                link.environment_id.to_lowercase() == needle
                    || link.label.to_lowercase() == needle
            })
            .cloned()
            .collect(),
    }
}

/// `JSON.stringify(value, null, 2)`.
fn pretty(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}
