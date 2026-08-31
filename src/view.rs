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
    pub machine_presence: String,
    /// Whether a server exists for the machine right now. None from an older
    /// Svartal that does not report it.
    pub machine_runtime_state: Option<String>,
    pub environment_id: String,
    pub label: String,
    pub kind: String,
    pub lifecycle_state: String,
    /// True when this identity holds a relay link to the workspace.
    pub linked: bool,
    pub linked_at: Option<String>,
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

/// Said once, everywhere the CLI would otherwise imply it knows more than it
/// does.
pub const MACHINE_STATE_NOTE: &str = "REACHABLE is your relay link, not a live check. MACHINE is the box's last heartbeat: unknown means it has never reported.";

pub const SESSIONS_NOT_EXPOSED_NOTE: &str = "Live agent sessions are not readable with a terminal sign-in yet. They live on the workspace itself and need a connected session, which this CLI cannot open yet. See NOTES.md in the svartal-cli package.";

fn present(value: Option<&str>, fallback: &str) -> String {
    match value.map(str::trim) {
        Some(text) if !text.is_empty() => text.to_string(),
        _ => fallback.to_string(),
    }
}

pub fn build_machines_view(machines: &[Machine], links: &[LinkRecord]) -> MachinesView {
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
                machine_presence: present(Some(machine.presence.as_str()), "unknown"),
                machine_runtime_state: machine.runtime_state.clone(),
                environment_id: workspace.environment_id.clone(),
                label: present(workspace.label.as_deref(), &workspace.environment_id),
                kind: present(workspace.kind.as_deref(), "-"),
                lifecycle_state: present(workspace.lifecycle_state.as_deref(), "-"),
                linked: link.is_some(),
                linked_at: link.map(|link| link.linked_at.clone()),
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

pub fn format_machines_view(view: &MachinesView) -> String {
    if view.rows.is_empty() && view.unregistered_links.is_empty() {
        return "No machines yet. Register one in the Svartal web app, then link it from the box."
            .to_string();
    }
    let mut sections: Vec<String> = Vec::new();
    if !view.rows.is_empty() {
        sections.push(render_table(
            &["MACHINE", "WORKSPACE", "WORKSPACE ID", "KIND", "STATE", "REACHABLE", "MACHINE"],
            &view
                .rows
                .iter()
                .map(|row| {
                    vec![
                        row.machine_name.clone(),
                        row.label.clone(),
                        row.environment_id.clone(),
                        row.kind.clone(),
                        row.lifecycle_state.clone(),
                        if row.linked { "linked".to_string() } else { "not linked".to_string() },
                        row.machine_presence.clone(),
                    ]
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
    pub linked: bool,
    pub machine_presence: Option<String>,
}

pub fn build_env_rows(
    view: &MachinesView,
    shortnames: &crate::shortnames::Shortnames,
) -> Vec<EnvRow> {
    let mut rows: Vec<EnvRow> = view
        .rows
        .iter()
        .map(|row| EnvRow {
            shortname: shortnames.shortname_of(&row.environment_id).map(str::to_string),
            label: row.label.clone(),
            environment_id: row.environment_id.clone(),
            machine_name: Some(row.machine_name.clone()),
            kind: row.kind.clone(),
            lifecycle_state: row.lifecycle_state.clone(),
            linked: row.linked,
            machine_presence: Some(row.machine_presence.clone()),
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
            // A link record is the proof of reachability, so these are linked
            // by definition.
            linked: true,
            machine_presence: None,
        });
    }
    rows
}

pub const NO_ENVIRONMENTS: &str =
    "No workspaces yet. Register a machine in the Svartal web app, then link it from the box.";

pub fn format_envs_view(rows: &[EnvRow]) -> String {
    if rows.is_empty() {
        return NO_ENVIRONMENTS.to_string();
    }
    render_table(
        &["SHORTNAME", "WORKSPACE", "WORKSPACE ID", "MACHINE", "KIND", "STATE", "REACHABLE", "MACHINE"],
        &rows
            .iter()
            .map(|row| {
                vec![
                    row.shortname.clone().unwrap_or_else(|| "-".to_string()),
                    row.label.clone(),
                    row.environment_id.clone(),
                    row.machine_name.clone().unwrap_or_else(|| "-".to_string()),
                    row.kind.clone(),
                    row.lifecycle_state.clone(),
                    if row.linked { "linked".to_string() } else { "not linked".to_string() },
                    row.machine_presence.clone().unwrap_or_else(|| "-".to_string()),
                ]
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
                    row.machine_name.clone(),
                    row.label.clone(),
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
                    || row.machine_id.to_lowercase() == needle
                    || row.environment_id.to_lowercase() == needle
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
