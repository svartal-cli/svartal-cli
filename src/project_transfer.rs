//! `sv project transfer`: hand a personal project to another person, or move
//! it into an organization you administer. The project keeps its id, slug,
//! bundles and history, and the former owner keeps push access.

use std::io::Write;

use serde_json::{Value, json};

use crate::api::api_request;
use crate::commands::{CliError, Context};
use crate::issue::encode_segment;

const USAGE: &str =
    "Usage: sv project transfer <project> --to-user <username> | --to-org <organization>.";

#[derive(Debug, PartialEq, Eq)]
pub enum Recipient<'a> {
    User(&'a str),
    Organization(&'a str),
}

pub fn parse_transfer_args<'a>(
    args: &[&'a str],
    to_user: Option<&'a str>,
    to_org: Option<&'a str>,
) -> Result<(&'a str, Recipient<'a>), String> {
    let ["transfer", project] = args else {
        return Err(USAGE.to_string());
    };
    if project.trim().is_empty() {
        return Err(USAGE.to_string());
    }
    let recipient = match (to_user, to_org) {
        (Some(user), None) if !user.trim().is_empty() => Recipient::User(user.trim()),
        (None, Some(org)) if !org.trim().is_empty() => Recipient::Organization(org.trim()),
        (Some(_), Some(_)) => {
            return Err("Name one new owner: --to-user or --to-org, not both.".to_string());
        }
        _ => return Err(USAGE.to_string()),
    };
    Ok((project, recipient))
}

/// `project` is a slug or a UUID, as the server resolves it.
pub fn transfer(
    context: &Context<'_>,
    out: &mut dyn Write,
    project: &str,
    recipient: Recipient<'_>,
) -> Result<(), CliError> {
    let (body, named) = match recipient {
        Recipient::User(user) => (json!({ "user": user }), user),
        Recipient::Organization(org) => (json!({ "organization": org }), org),
    };
    let reply = api_request(
        context,
        "POST",
        &format!("/projects/{}/transfer", encode_segment(project)),
        Some(body),
        "transfer the project",
    )?;
    let data = reply.body.get("data").ok_or_else(|| {
        CliError("Svartal answered with something this client cannot read.".to_string())
    })?;
    let owner = data
        .pointer("/organization/slug")
        .or_else(|| data.pointer("/owner/slug"))
        .and_then(Value::as_str)
        .unwrap_or(named);
    writeln!(
        out,
        "{project}: now owned by {owner}. You keep push access."
    )
    .map_err(CliError::of)?;
    if let Some(id) = data.get("id").and_then(Value::as_str) {
        writeln!(
            out,
            "{}/app/projects/{}",
            context.config.web_url.trim_end_matches('/'),
            encode_segment(id)
        )
        .map_err(CliError::of)?;
    }
    Ok(())
}
