//! Turning what a person typed into one workspace to connect to.
//!
//! Port of `src/target.ts`. `sv shell <target>` takes whatever the person
//! has in front of them — a machine name, a workspace label, or a workspace id
//! — and has to end at exactly one environment id. Anything else is a question,
//! not a guess: two matches are listed back, and no match says so.
//!
//! The input is the same joined view `sv machines` prints, so the CLI
//! never resolves against data the person could not have seen.
//!
//! A short name is the fourth thing an argument can be, and it sits in the
//! middle of the order on purpose: below workspace ids, which are unique and
//! cannot be argued with, and above labels and machine names, which the person
//! did not choose and which the workspace can rename underneath them.
//!
//! Short names now come from Svartal, where the machine's owner assigned them,
//! so everybody reading a workspace reads the same word. The local
//! `shortnames.json` is still consulted after them: names given before they
//! were stored keep working on the laptop that gave them.

use crate::shortnames::Shortnames;
use crate::view::{MachinesView, WorkspaceRow, render_table};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellTarget {
    pub environment_id: String,
    pub label: String,
    /// The word this workspace's owner gave it in Svartal, when there is one.
    pub short_name: Option<String>,
    /// None for a workspace that is linked but not on a machine this person can
    /// list.
    pub machine_name: Option<String>,
    /// The word the machine's owner gave the machine in Svartal.
    pub machine_short_name: Option<String>,
    /// True when this identity holds a relay link, which is what connecting
    /// needs.
    pub linked: bool,
    /// The machine's own heartbeat: `online`, `offline`, or `unknown`.
    pub machine_presence: Option<String>,
    /// What Svartal intends this workspace to be, when it said so. It is what
    /// turns "you are not linked" into "the link is coming back"; see
    /// `select_shell_target`. None for a workspace known only from a link
    /// record, which is linked anyway.
    pub intent_state: Option<String>,
    /// A personal workspace belonging to somebody else. It stays a candidate
    /// for its own workspace id and for nothing else: an id is unambiguous and
    /// a person who typed one meant it, while a machine name means "my
    /// workspace on that machine".
    pub belongs_to_another: bool,
}

#[derive(Debug)]
pub enum TargetError {
    Ambiguous { argument: String, candidates: String },
    Unknown { argument: String, reachable: String },
    /// No target was given and more than one workspace could have been meant.
    Unspecified { reachable: String },
    NotLinked { label: String },
    /// Not linked, but Svartal is putting the link back. The person has
    /// something to do about that, so this says what.
    Relinking { label: String, machine_name: Option<String> },
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
            Self::Relinking { label, machine_name: Some(machine_name) } => write!(
                f,
                "Svartal is relinking {label}, so the link is not back yet. Run `sv host up` on {machine_name} to finish it. Then `sv shell` will work."
            ),
            Self::Relinking { label, machine_name: None } => write!(
                f,
                "Svartal is relinking {label}, so the link is not back yet. Run `sv host up` on that machine to finish it. Then `sv shell` will work."
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
        short_name: row.short_name.clone(),
        machine_name: Some(row.machine_name.clone()),
        machine_short_name: row.machine_short_name.clone(),
        linked: row.linked,
        machine_presence: Some(row.machine_presence.clone()),
        intent_state: row.intent_state.clone(),
        belongs_to_another: row.belongs_to_another,
    }
}

/// Every workspace the person could mean, machine-listed ones first.
pub fn shell_targets(view: &MachinesView) -> Vec<ShellTarget> {
    let mut targets: Vec<ShellTarget> = view.rows.iter().map(target_of_row).collect();
    for link in &view.unregistered_links {
        targets.push(ShellTarget {
            environment_id: link.environment_id.clone(),
            label: link.label.clone(),
            short_name: None,
            machine_name: None,
            machine_short_name: None,
            linked: true,
            machine_presence: None,
            // A link record carries no intent, and a linked workspace needs
            // none: nothing below asks about it.
            intent_state: None,
            // A link this identity holds is its own proof of whose it is.
            belongs_to_another: false,
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
/// The order is workspace id, then the short name Svartal holds, then a local
/// short name, then label or machine name.
///
/// A workspace id wins outright, because ids are unique and a person who typed
/// one has already been specific. Short names come next: they are the only
/// words here anybody chose. Labels and machine names are matched last and on
/// equal footing: if a machine name and a workspace label both answer to the
/// same word, that is genuinely ambiguous and the person has to say which.
///
/// A short name is unique to its machine, not globally, so the same word can
/// name a workspace on two machines. That is listed back as the ambiguity it
/// is rather than resolved to whichever came first.
///
/// A short name pointing at a workspace that is no longer in the view falls
/// through to the ordinary matching rather than failing on its own, so a stale
/// entry reads as "no workspace called web" with the usual list under it.
///
/// A second person's personal workspace on a machine you own is not a
/// candidate for any of those words. `sv shell m3` means "my workspace on m3",
/// so the machine name resolves to yours rather than asking you which of two
/// you meant — and the one you would have had to name is one you cannot open.
/// Its workspace id still resolves, because an id names one workspace and
/// nothing else.
pub fn resolve_shell_target(
    view: &MachinesView,
    shortnames: &Shortnames,
    argument: &str,
) -> Resolution {
    let needle = normalize(argument);
    let candidates = shell_targets(view);
    let yours: Vec<&ShellTarget> =
        candidates.iter().filter(|target| !target.belongs_to_another).collect();
    let reachable = || -> Vec<ShellTarget> {
        yours.iter().filter(|target| target.linked).map(|target| (*target).clone()).collect()
    };
    if needle.is_empty() {
        return Resolution::Missing(reachable());
    }

    let by_id: Vec<&ShellTarget> = candidates
        .iter()
        .filter(|target| normalize(&target.environment_id) == needle)
        .collect();
    if by_id.len() == 1 {
        return Resolution::Resolved(by_id[0].clone());
    }

    let by_short_name: Vec<ShellTarget> = candidates
        .iter()
        .filter(|target| target.short_name.as_deref().map(normalize).as_deref() == Some(needle.as_str()))
        .cloned()
        .collect();
    match by_short_name.len() {
        1 => return Resolution::Resolved(by_short_name.into_iter().next().expect("one match")),
        0 => {}
        _ => return Resolution::Ambiguous(by_short_name),
    }

    if let Some(environment_id) = shortnames.environment_of(&needle) {
        let named = normalize(environment_id);
        if let Some(target) =
            yours.iter().find(|target| normalize(&target.environment_id) == named)
        {
            return Resolution::Resolved((*target).clone());
        }
    }

    let matches: Vec<ShellTarget> = yours
        .iter()
        .filter(|target| {
            normalize(&target.environment_id) == needle
                || normalize(&target.label) == needle
                || target.machine_name.as_deref().map(normalize).as_deref() == Some(needle.as_str())
                || target.machine_short_name.as_deref().map(normalize).as_deref()
                    == Some(needle.as_str())
        })
        .map(|target| (*target).clone())
        .collect();
    match matches.len() {
        1 => Resolution::Resolved(matches.into_iter().next().expect("one match")),
        0 => Resolution::Missing(reachable()),
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
                    target
                        .machine_name
                        .as_deref()
                        .map(|name| {
                            crate::view::machine_cell(name, target.machine_short_name.as_deref())
                        })
                        .unwrap_or_else(|| "-".to_string()),
                    target.short_name.clone().unwrap_or_else(|| target.label.clone()),
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
    shortnames: &Shortnames,
    argument: Option<&str>,
) -> Result<ShellTarget, TargetError> {
    match argument.map(str::trim).filter(|argument| !argument.is_empty()) {
        Some(argument) => select_shell_target(view, shortnames, argument),
        None => {
            let reachable: Vec<ShellTarget> = shell_targets(view)
                .into_iter()
                .filter(|target| target.linked && !target.belongs_to_another)
                .collect();
            match reachable.len() {
                1 => select_shell_target(
                    view,
                    shortnames,
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
///
/// A workspace Svartal is relinking is refused too, but with its own sentence:
/// the link is not gone, it is coming back, and there is one command to run on
/// the machine to finish it. Telling that person to link the machine in the web
/// app would send them somewhere that cannot help them.
pub fn select_shell_target(
    view: &MachinesView,
    shortnames: &Shortnames,
    argument: &str,
) -> Result<ShellTarget, TargetError> {
    let target = match resolve_shell_target(view, shortnames, argument) {
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
        if target.intent_state.as_deref().map(str::trim) == Some("relinking") {
            return Err(TargetError::Relinking {
                label: target.label,
                machine_name: target.machine_name,
            });
        }
        return Err(TargetError::NotLinked { label: target.label });
    }
    if target.machine_presence.as_deref() == Some("offline") {
        return Err(TargetError::MachineOffline { label: target.label });
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Machine, Workspace};
    use crate::view::build_machines_view;

    /// One machine called `m3` with two personal workspaces on it: the
    /// caller's, and a second person's. This is the laptop the rule was
    /// written for.
    fn two_personal_workspaces(other_owner: Option<&str>) -> MachinesView {
        let workspace = |environment_id: &str, label: &str, owner: Option<&str>| Workspace {
            id: format!("row-{environment_id}"),
            environment_id: environment_id.to_string(),
            label: Some(label.to_string()),
            short_name: None,
            kind: Some("personal".to_string()),
            lifecycle_state: Some("active".to_string()),
            owner: owner.map(str::to_string),
            intent_state: None,
        };
        let machines = vec![Machine {
            id: "machine-1".to_string(),
            name: "m3".to_string(),
            short_name: None,
            origin: Some("donated".to_string()),
            lifecycle_state: Some("open".to_string()),
            presence: "online".to_string(),
            last_seen_at: None,
            environments: vec![
                workspace("env-mine", "Marc", Some("marc")),
                workspace("env-theirs", "Someone", other_owner),
            ],
        }];
        build_machines_view(&machines, &[], Some("marc"))
    }

    fn resolve(view: &MachinesView, argument: &str) -> Resolution {
        resolve_shell_target(view, &Shortnames::new(), argument)
    }

    #[test]
    fn a_machine_name_means_your_own_workspace_on_that_machine() {
        let view = two_personal_workspaces(Some("someone"));
        let Resolution::Resolved(target) = resolve(&view, "m3") else {
            panic!("m3 did not resolve to one workspace");
        };
        assert_eq!(target.environment_id, "env-mine");
        // And so does the label of your own workspace, as it always did.
        let Resolution::Resolved(target) = resolve(&view, "Marc") else {
            panic!("Marc did not resolve");
        };
        assert_eq!(target.environment_id, "env-mine");
    }

    #[test]
    fn the_other_persons_workspace_answers_to_its_workspace_id_and_nothing_else() {
        let view = two_personal_workspaces(Some("someone"));
        // An id names one workspace, so it still resolves; what happens next
        // is the ordinary "you are not linked to it" refusal.
        let Resolution::Resolved(target) = resolve(&view, "env-theirs") else {
            panic!("the workspace id did not resolve");
        };
        assert_eq!(target.environment_id, "env-theirs");
        assert!(target.belongs_to_another);
        // Its label is not a word you can reach it by.
        assert!(matches!(resolve(&view, "Someone"), Resolution::Missing(_)));
    }

    #[test]
    fn a_workspace_with_no_owner_is_as_ambiguous_as_it_ever_was() {
        // An older server sends no owner. Nothing is known to be somebody
        // else's, so `m3` is two workspaces and the person is asked which.
        let view = two_personal_workspaces(None);
        let Resolution::Ambiguous(candidates) = resolve(&view, "m3") else {
            panic!("m3 should still be ambiguous when no owner is known");
        };
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn the_lists_a_refusal_prints_leave_other_peoples_workspaces_out() {
        let mut view = two_personal_workspaces(Some("someone"));
        // Linked to both, which is the only way a row reaches those lists.
        for row in &mut view.rows {
            row.linked = true;
        }
        let Resolution::Missing(reachable) = resolve(&view, "nowhere") else {
            panic!("nowhere should not resolve");
        };
        assert_eq!(
            reachable.iter().map(|target| target.environment_id.as_str()).collect::<Vec<_>>(),
            vec!["env-mine"]
        );
        // With one workspace of your own left, no argument at all is not a
        // question any more.
        let target = select_target(&view, &Shortnames::new(), None).unwrap();
        assert_eq!(target.environment_id, "env-mine");
    }

    /// The person's own workspace, unlinked, with Svartal putting the link
    /// back. This is the machine whose link was revoked.
    fn relinking_workspace() -> MachinesView {
        let machines = vec![Machine {
            id: "machine-1".to_string(),
            name: "m3".to_string(),
            short_name: None,
            origin: Some("donated".to_string()),
            lifecycle_state: Some("open".to_string()),
            presence: "online".to_string(),
            last_seen_at: None,
            environments: vec![Workspace {
                id: "row-mine".to_string(),
                environment_id: "env-mine".to_string(),
                label: Some("Marc".to_string()),
                short_name: None,
                kind: Some("personal".to_string()),
                lifecycle_state: Some("active".to_string()),
                owner: Some("marc".to_string()),
                intent_state: Some("relinking".to_string()),
            }],
        }];
        build_machines_view(&machines, &[], Some("marc"))
    }

    #[test]
    fn a_workspace_being_relinked_is_refused_with_the_command_that_finishes_it() {
        let view = relinking_workspace();
        // It is still this person's own workspace, so it resolves the way it
        // always did; what changes is the sentence it is refused with.
        let Resolution::Resolved(target) = resolve(&view, "m3") else {
            panic!("m3 did not resolve");
        };
        assert_eq!(target.intent_state.as_deref(), Some("relinking"));

        let error = select_shell_target(&view, &Shortnames::new(), "m3").unwrap_err();
        let TargetError::Relinking { label, machine_name } = &error else {
            panic!("expected a relinking refusal, got {error:?}");
        };
        assert_eq!(label, "Marc");
        assert_eq!(machine_name.as_deref(), Some("m3"));
        let said = error.to_string();
        assert!(said.contains("`sv host up`"), "{said}");
        assert!(said.contains("m3"), "{said}");
    }

    #[test]
    fn every_other_unlinked_workspace_is_refused_the_way_it_always_was() {
        // No intent at all, which is what an older server sends: the old
        // sentence, unchanged.
        let view = two_personal_workspaces(Some("someone"));
        let error = select_shell_target(&view, &Shortnames::new(), "m3").unwrap_err();
        assert!(matches!(error, TargetError::NotLinked { .. }), "{error:?}");
        assert!(error.to_string().contains("Link the machine from the Svartal web app"));
    }

    #[test]
    fn a_short_name_cannot_point_at_somebody_elses_workspace_either() {
        let view = two_personal_workspaces(Some("someone"));
        let mut names = Shortnames::new();
        names.assign("theirs", "env-theirs").unwrap();
        assert!(matches!(
            resolve_shell_target(&view, &names, "theirs"),
            Resolution::Missing(_)
        ));
    }
}
