//! Turning what a person typed into one workspace to connect to.
//!
//! Port of `src/target.ts`. `sv shell <target>` takes whatever the person
//! has in front of them — a machine name, a workspace label, or a workspace id
//! — and has to end at exactly one environment id. Anything else is a question,
//! not a guess: two matches are listed back, and no match says so.
//!
//! The input is the same joined view `sv machines` prints, so the CLI
//! never resolves against data the person could not have seen.

use crate::view::{MachinesView, WorkspaceRow, render_table};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellTarget {
    pub environment_id: String,
    pub label: String,
    /// None for a workspace that is linked but not on a machine this person can
    /// list.
    pub machine_name: Option<String>,
    /// True when this identity holds a relay link, which is what connecting
    /// needs.
    pub linked: bool,
    /// The machine's own heartbeat: `online`, `offline`, or `unknown`.
    pub machine_presence: Option<String>,
}

#[derive(Debug)]
pub enum TargetError {
    Ambiguous { argument: String, candidates: String },
    Unknown { argument: String, reachable: String },
    /// No target was given and more than one workspace could have been meant.
    Unspecified { reachable: String },
    NotLinked { label: String },
    MachineOffline { label: String },
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ambiguous { argument, candidates } => write!(
                f,
                "{argument} matches more than one workspace. Say which one, by its workspace id:\n\n{candidates}"
            ),
            Self::Unknown { argument, reachable } if reachable.is_empty() => write!(
                f,
                "No workspace called {argument}. You cannot reach any workspace yet; run `sv machines` to see what exists."
            ),
            Self::Unknown { argument, reachable } => write!(
                f,
                "No workspace called {argument}. These are the ones you can reach:\n\n{reachable}"
            ),
            Self::Unspecified { reachable } if reachable.is_empty() => write!(
                f,
                "You cannot reach any workspace yet; run `sv machines` to see what exists."
            ),
            Self::Unspecified { reachable } => write!(
                f,
                "Say which workspace, by name or workspace id:\n\n{reachable}"
            ),
            Self::NotLinked { label } => write!(
                f,
                "You are not linked to {label}, so there is nothing to connect to. Link the machine from the Svartal web app first."
            ),
            Self::MachineOffline { label } => write!(
                f,
                "The machine hosting {label} last reported that it is offline, so a shell would not reach it. Start the machine and try again."
            ),
        }
    }
}

impl std::error::Error for TargetError {}

fn target_of_row(row: &WorkspaceRow) -> ShellTarget {
    ShellTarget {
        environment_id: row.environment_id.clone(),
        label: row.label.clone(),
        machine_name: Some(row.machine_name.clone()),
        linked: row.linked,
        machine_presence: Some(row.machine_presence.clone()),
    }
}

/// Every workspace the person could mean, machine-listed ones first.
pub fn shell_targets(view: &MachinesView) -> Vec<ShellTarget> {
    let mut targets: Vec<ShellTarget> = view.rows.iter().map(target_of_row).collect();
    for link in &view.unregistered_links {
        targets.push(ShellTarget {
            environment_id: link.environment_id.clone(),
            label: link.label.clone(),
            machine_name: None,
            linked: true,
            machine_presence: None,
        });
    }
    targets
}

fn normalize(value: &str) -> String {
    value.trim().to_lowercase()
}

#[derive(Debug)]
pub enum Resolution {
    Resolved(ShellTarget),
    Ambiguous(Vec<ShellTarget>),
    Missing(Vec<ShellTarget>),
}

/// Resolve one argument against the view.
///
/// A workspace id wins outright, because ids are unique and a person who typed
/// one has already been specific. Everything else is matched on equal footing:
/// if a machine name and a workspace label both answer to the same word, that
/// is genuinely ambiguous and the person has to say which.
pub fn resolve_shell_target(view: &MachinesView, argument: &str) -> Resolution {
    let needle = normalize(argument);
    let candidates = shell_targets(view);
    let reachable = |candidates: &[ShellTarget]| -> Vec<ShellTarget> {
        candidates.iter().filter(|target| target.linked).cloned().collect()
    };
    if needle.is_empty() {
        return Resolution::Missing(reachable(&candidates));
    }

    let by_id: Vec<&ShellTarget> = candidates
        .iter()
        .filter(|target| normalize(&target.environment_id) == needle)
        .collect();
    if by_id.len() == 1 {
        return Resolution::Resolved(by_id[0].clone());
    }

    let matches: Vec<ShellTarget> = candidates
        .iter()
        .filter(|target| {
            normalize(&target.environment_id) == needle
                || normalize(&target.label) == needle
                || target.machine_name.as_deref().map(normalize).as_deref() == Some(needle.as_str())
        })
        .cloned()
        .collect();
    match matches.len() {
        1 => Resolution::Resolved(matches.into_iter().next().expect("one match")),
        0 => Resolution::Missing(reachable(&candidates)),
        _ => Resolution::Ambiguous(matches),
    }
}

/// The candidate table printed when one word means more than one workspace.
pub fn format_target_candidates(candidates: &[ShellTarget]) -> String {
    render_table(
        &["MACHINE", "WORKSPACE", "WORKSPACE ID"],
        &candidates
            .iter()
            .map(|target| {
                vec![
                    target.machine_name.clone().unwrap_or_else(|| "-".to_string()),
                    target.label.clone(),
                    target.environment_id.clone(),
                ]
            })
            .collect::<Vec<_>>(),
    )
}

/// The one workspace to connect to when the person named none.
///
/// One reachable workspace is not a guess — it is the only thing the words
/// could have meant. Two are a question, and the answer is the same table
/// every other refusal prints.
pub fn select_target(
    view: &MachinesView,
    argument: Option<&str>,
) -> Result<ShellTarget, TargetError> {
    match argument.map(str::trim).filter(|argument| !argument.is_empty()) {
        Some(argument) => select_shell_target(view, argument),
        None => {
            let reachable: Vec<ShellTarget> =
                shell_targets(view).into_iter().filter(|target| target.linked).collect();
            match reachable.len() {
                1 => select_shell_target(
                    view,
                    &reachable.into_iter().next().expect("one target").environment_id,
                ),
                _ => Err(TargetError::Unspecified {
                    reachable: if reachable.is_empty() {
                        String::new()
                    } else {
                        format_target_candidates(&reachable)
                    },
                }),
            }
        }
    }
}

/// The one workspace to connect to, or a refusal that says why.
///
/// A machine whose heartbeat says `offline` is refused; `unknown` is not. Most
/// machines never report at all, so treating silence as "offline" would refuse
/// almost every real connection.
pub fn select_shell_target(view: &MachinesView, argument: &str) -> Result<ShellTarget, TargetError> {
    let target = match resolve_shell_target(view, argument) {
        Resolution::Ambiguous(candidates) => {
            return Err(TargetError::Ambiguous {
                argument: argument.to_string(),
                candidates: format_target_candidates(&candidates),
            });
        }
        Resolution::Missing(reachable) => {
            return Err(TargetError::Unknown {
                argument: argument.to_string(),
                reachable: if reachable.is_empty() {
                    String::new()
                } else {
                    format_target_candidates(&reachable)
                },
            });
        }
        Resolution::Resolved(target) => target,
    };
    if !target.linked {
        return Err(TargetError::NotLinked { label: target.label });
    }
    if target.machine_presence.as_deref() == Some("offline") {
        return Err(TargetError::MachineOffline { label: target.label });
    }
    Ok(target)
}
