//! `sv project visibility`: show or change who can see a Svartal project.

use std::io::Write;

use serde_json::{Value, json};

use crate::api::{ApiRequestError, api_request_structured};
use crate::commands::{CliError, Context};
use crate::issue::encode_segment;

const USAGE: &str = "Usage: sv project visibility <project> [public|private].";

pub fn parse_visibility_args<'a>(args: &[&'a str]) -> Result<(&'a str, Option<&'a str>), String> {
    let (project, value) = match args {
        ["visibility", project] => (*project, None),
        ["visibility", project, value] => (*project, Some(*value)),
        _ => return Err(USAGE.to_string()),
    };
    if project.trim().is_empty() {
        return Err(USAGE.to_string());
    }
    if let Some(value) = value
        && !matches!(value, "public" | "private")
    {
        return Err(format!(
            "`{value}` is not a visibility. Use one of: public, private."
        ));
    }
    Ok((project, value))
}

fn request(
    context: &Context<'_>,
    method: &'static str,
    project: &str,
    body: Option<Value>,
) -> Result<Value, CliError> {
    let action = match method {
        "PATCH" => "change project visibility",
        _ => "read the project",
    };
    let path = format!("/projects/{}", encode_segment(project));
    let reply =
        api_request_structured(context, method, &path, body, action).map_err(
            |error| match error {
                ApiRequestError::Http { status: 403, .. } => {
                    CliError("Only the project's owner can change its visibility.".to_string())
                }
                ApiRequestError::Http { status: 404, .. } => {
                    CliError(format!("No project named {project}."))
                }
                other => other.into_cli_error(),
            },
        )?;
    reply.body.get("data").cloned().ok_or_else(|| {
        CliError("Svartal answered with something this client cannot read.".to_string())
    })
}

/// `project` is a slug or a UUID, as the server resolves it.
pub fn visibility(
    context: &Context<'_>,
    out: &mut dyn Write,
    project: &str,
    value: Option<&str>,
) -> Result<(), CliError> {
    let data = match value {
        None => request(context, "GET", project, None)?,
        Some(value) => request(
            context,
            "PATCH",
            project,
            Some(json!({ "visibility": value })),
        )?,
    };
    let visibility = data
        .get("visibility")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let now = if value.is_some() { "now " } else { "" };
    writeln!(out, "{project}: {now}{visibility}").map_err(CliError::of)?;
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
