//! Starting a machine that went to sleep.
//!
//! The platform stops machines nobody is working on and keeps their disk. The
//! CLI's job is to notice, start the machine, and wait — never to refuse a
//! connection because a box it can start is not running.

mod common;

use serde_json::json;

use svartal::api::MachineTicket;
use svartal::target::{ShellTarget, select_shell_target};
use svartal::shortnames::Shortnames;
use svartal::view::build_machines_view;

fn machine(runtime_state: Option<&str>, presence: &str) -> svartal::api::Machine {
    serde_json::from_value(json!({
        "id": "machine-1",
        "name": "workbench",
        "origin": "managed",
        "lifecycleState": "open",
        "presence": presence,
        "runtimeState": runtime_state,
        "lastSeenAt": null,
        "environments": [{
            "id": "row-1",
            "environmentId": "env-1",
            "label": "Workspace",
            "kind": "personal",
            "lifecycleState": "active",
        }],
    }))
    .unwrap()
}

fn link() -> svartal::api::LinkRecord {
    serde_json::from_value(json!({
        "environmentId": "env-1",
        "label": "Workspace",
        "endpoint": {
            "httpBaseUrl": "https://workspace.example",
            "wsBaseUrl": "wss://workspace.example",
            "providerKind": "cloudflare_tunnel",
        },
        "linkedAt": "2026-08-31T09:00:00Z",
    }))
    .unwrap()
}

fn target_for(runtime_state: Option<&str>, presence: &str) -> Result<ShellTarget, String> {
    let view = build_machines_view(&[machine(runtime_state, presence)], &[link()]);
    select_shell_target(&view, &Shortnames::default(), "env-1").map_err(|error| error.to_string())
}

#[test]
fn a_sleeping_machine_is_something_to_start_not_something_to_refuse() {
    // A stopped machine reads as offline five minutes after its last beat. If
    // the heartbeat were checked first, the one machine the CLI knows how to
    // start would be the one it refuses.
    let target = target_for(Some("hibernated"), "offline").expect("a sleeping machine is usable");

    assert!(target.needs_waking());
    assert_eq!(target.machine_id.as_deref(), Some("machine-1"));
}

#[test]
fn a_machine_on_its_way_somewhere_is_waited_for() {
    for state in ["waking", "hibernating", "failed"] {
        let target = target_for(Some(state), "offline").expect("still usable");
        assert!(target.needs_waking(), "{state} should be waited for");
    }
}

#[test]
fn a_running_machine_that_stopped_reporting_is_still_refused() {
    // Nothing here is asleep: this box is supposed to be up and is not
    // answering, which is a real problem and must not be dressed up as a
    // machine that is merely resting.
    let error = target_for(Some("running"), "offline").expect_err("refused");
    assert!(error.contains("offline"), "{error}");
}

#[test]
fn an_older_svartal_that_says_nothing_about_runtime_state_behaves_as_before() {
    assert!(!target_for(None, "online").expect("usable").needs_waking());
    assert!(target_for(None, "offline").is_err());
}

#[test]
fn a_workspace_with_no_machine_is_never_woken() {
    // A link to a box this person cannot list: real and reachable, but there is
    // no machine record to ask about, so there is nothing to start.
    let view = build_machines_view(&[], &[link()]);
    let target = select_shell_target(&view, &Shortnames::default(), "env-1").expect("usable");

    assert!(!target.needs_waking());
    assert_eq!(target.machine_id, None);
}

fn ticket(state: &str, position: Option<u32>, eta: Option<u64>) -> MachineTicket {
    serde_json::from_value(json!({
        "state": state,
        "machineId": "machine-1",
        "machineName": "workbench",
        "position": position,
        "etaSeconds": eta,
        "reason": null,
    }))
    .unwrap()
}

#[test]
fn what_is_printed_while_waiting_is_true_for_each_state() {
    assert_eq!(ticket("active", None, None).sentence("workbench"), "workbench is ready.");
    assert!(ticket("always_on", None, None).ready());

    assert_eq!(
        ticket("waking", None, Some(210)).sentence("workbench"),
        "Starting workbench. This takes about 4 minutes."
    );
    // No estimate is better than an invented one.
    assert_eq!(ticket("waking", None, None).sentence("workbench"), "Starting workbench.");

    assert_eq!(
        ticket("queued", Some(3), None).sentence("workbench"),
        "Every machine in the pool is in use. 2 people are ahead of you."
    );
    assert_eq!(
        ticket("queued", Some(1), None).sentence("workbench"),
        "Every machine in the pool is in use. You are next."
    );
}

#[test]
fn waiting_only_continues_while_waiting_can_get_somewhere() {
    assert!(ticket("waking", None, None).settling());
    assert!(ticket("queued", Some(2), None).settling());

    // Nothing is going to change on its own for either of these, so the CLI
    // must stop rather than poll until it times out.
    assert!(!ticket("failed", None, None).settling());
    assert!(!ticket("asleep", None, None).settling());
    assert!(!ticket("active", None, None).settling());
}
