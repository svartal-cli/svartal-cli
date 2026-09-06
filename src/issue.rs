//! `sv issue`: turn a conversation into Svartal project objects.
//!
//! Post an issue (or a bug, a plan, an idea) from a file or a pipe, link or
//! unlink a bundle to an issue, and save a conversation transcript for audit.
//! Every write goes through the Svartal API with a minted API token
//! (`api::api_request`), and every post is authored as the signed-in person
//! with a `postedVia` note saying which agent — if any — did the typing.
//!
//! This module never touches a Knit bundle or its ledger: it links by name and
//! leaves the bundle itself alone.

use std::io::Read as _;
use std::path::Path;

use serde_json::{Value, json};

use crate::api::{ApiReply, api_request};
use crate::commands::{CliError, Context};

/// The kinds a person may name. `issue` is the everyday word for what Svartal
/// stores as `feature`; the rest are Svartal's own names.
pub const KINDS: [&str; 6] = ["issue", "bug", "chore", "investigation", "idea", "plan"];

/// The `kind` Svartal stores for the word typed after `--kind`.
pub fn work_item_kind(input: &str) -> Result<&'static str, String> {
    match input.trim().to_ascii_lowercase().as_str() {
        "issue" | "feature" => Ok("feature"),
        "bug" => Ok("bug"),
        "chore" => Ok("chore"),
        "investigation" => Ok("investigation"),
        "idea" => Ok("idea"),
        "plan" => Ok("plan"),
        other => Err(format!(
            "`{other}` is not a kind of issue. Use one of: {}.",
            KINDS.join(", ")
        )),
    }
}

/// `#12` or `12`. Issues are numbered per project, so the number alone names
/// one once the project is known.
pub fn parse_number(input: &str) -> Result<u64, String> {
    let digits = input.trim().trim_start_matches('#');
    match digits.parse::<u64>() {
        Ok(number) if number > 0 => Ok(number),
        _ => Err(format!(
            "`{input}` is not an issue number. Issues are named like `#12`."
        )),
    }
}

/// A project or bundle identifier as one URL path segment. A project is
/// `owner/slug`, and the slash inside it must not read as a path separator.
pub fn encode_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// The `postedVia` note every post carries. Absent values are left out rather
/// than sent as null, so Svartal's allow-list sees only what is known.
pub fn posted_via(agent: Option<&str>, thread: Option<&str>, machine: Option<&str>) -> Value {
    let mut note = json!({ "client": "sv" });
    let agent = agent.map(str::trim).filter(|value| !value.is_empty());
    if let Some(agent) = agent {
        note["agent"] = json!(agent);
    }
    if let Some(thread) = thread.map(str::trim).filter(|value| !value.is_empty()) {
        note["threadId"] = json!(thread);
    }
    if let Some(machine) = machine.map(str::trim).filter(|value| !value.is_empty()) {
        note["machine"] = json!(machine);
    }
    note["note"] = json!(match agent {
        Some(agent) => format!("Posted by {agent} via the sv CLI"),
        None => "Posted via the sv CLI".to_string(),
    });
    note
}

pub fn issue_url(web_url: &str, project_id: &str, number: u64) -> String {
    format!("{web_url}/app/projects/{project_id}/issues/{number}")
}

pub fn transcript_url(web_url: &str, project_id: &str, transcript_id: &str) -> String {
    format!("{web_url}/app/projects/{project_id}/transcripts/{transcript_id}")
}

/// The issue body: a file, or `-` for whatever is piped in.
pub fn read_body_file(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut body = String::new();
        std::io::stdin()
            .read_to_string(&mut body)
            .map_err(|error| format!("Could not read the issue body from stdin: {error}"))?;
        return Ok(body);
    }
    std::fs::read_to_string(path)
        .map_err(|error| format!("Could not read the issue body from {path}: {error}"))
}

/// A transcript document, as ivaldi writes it: one JSON object.
pub fn read_transcript_file(path: &Path) -> Result<Value, String> {
    let raw = std::fs::read(path).map_err(|error| {
        format!(
            "Could not read the transcript from {}: {error}",
            path.display()
        )
    })?;
    let document: Value = serde_json::from_slice(&raw)
        .map_err(|error| format!("{} is not a JSON transcript: {error}", path.display()))?;
    if !document.is_object() {
        return Err(format!(
            "{} is not a JSON transcript: expected one object.",
            path.display()
        ));
    }
    Ok(document)
}

/// The three things a command needs back from a work item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkItem {
    pub id: String,
    pub number: u64,
    pub project_id: String,
}

fn work_item_from(value: &Value) -> Option<WorkItem> {
    Some(WorkItem {
        id: value.get("id")?.as_str()?.to_string(),
        number: value.get("number")?.as_u64()?,
        project_id: value.get("projectId")?.as_str()?.to_string(),
    })
}

fn unreadable(action: &str) -> CliError {
    CliError(format!(
        "Could not {action}: Svartal answered with something this client cannot read."
    ))
}

/// What `sv issue post` sends.
#[derive(Debug, Clone)]
pub struct NewWorkItem<'a> {
    pub project: &'a str,
    /// Already mapped through `work_item_kind`.
    pub kind: &'a str,
    pub title: &'a str,
    pub description: Option<&'a str>,
    pub bundles: &'a [String],
    pub posted_via: Value,
}

/// `POST /projects/:project/work-items`.
pub fn create_work_item(
    context: &Context<'_>,
    item: &NewWorkItem<'_>,
) -> Result<WorkItem, CliError> {
    let action = "post the issue";
    let mut body = json!({
        "title": item.title,
        "kind": item.kind,
        "postedVia": item.posted_via,
    });
    if let Some(description) = item.description {
        body["description"] = json!(description);
    }
    if !item.bundles.is_empty() {
        body["bundles"] = json!(item.bundles);
    }
    let reply = api_request(
        context,
        "POST",
        &format!("/projects/{}/work-items", encode_segment(item.project)),
        Some(body),
        action,
    )?;
    reply
        .body
        .get("data")
        .and_then(work_item_from)
        .ok_or_else(|| unreadable(action))
}

/// `GET /projects/:project/work-items?number=N`: the one issue with that
/// number, or a sentence saying there is none.
pub fn find_work_item(
    context: &Context<'_>,
    project: &str,
    number: u64,
) -> Result<WorkItem, CliError> {
    let action = format!("look up issue #{number}");
    let reply = api_request(
        context,
        "GET",
        &format!(
            "/projects/{}/work-items?number={number}",
            encode_segment(project)
        ),
        None,
        &action,
    )?;
    let items = reply
        .body
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| unreadable(&action))?;
    items
        .iter()
        .filter_map(work_item_from)
        .find(|item| item.number == number)
        .ok_or_else(|| CliError(format!("Project {project} has no issue #{number}.")))
}

/// `POST /work-items/:id/bundles/:bundle`.
pub fn link_bundle(
    context: &Context<'_>,
    work_item_id: &str,
    bundle: &str,
) -> Result<(), CliError> {
    api_request(
        context,
        "POST",
        &format!(
            "/work-items/{}/bundles/{}",
            encode_segment(work_item_id),
            encode_segment(bundle)
        ),
        None,
        &format!("link bundle {bundle}"),
    )
    .map(|_| ())
}

/// `DELETE /work-items/:id/bundles/:bundle`.
pub fn unlink_bundle(
    context: &Context<'_>,
    work_item_id: &str,
    bundle: &str,
) -> Result<(), CliError> {
    api_request(
        context,
        "DELETE",
        &format!(
            "/work-items/{}/bundles/{}",
            encode_segment(work_item_id),
            encode_segment(bundle)
        ),
        None,
        &format!("unlink bundle {bundle}"),
    )
    .map(|_| ())
}

/// What `sv issue transcript` sends.
#[derive(Debug, Clone)]
pub struct NewTranscript<'a> {
    pub project: &'a str,
    /// The whole document, stored as it is.
    pub document: &'a Value,
    /// Defaults to the document's `title`.
    pub title: Option<&'a str>,
    /// `--thread`; the document's `threadId` wins when it has one.
    pub thread: Option<&'a str>,
    pub work_item_id: Option<&'a str>,
    pub bundles: &'a [String],
    pub posted_via: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedTranscript {
    pub id: String,
    pub project_id: String,
    /// Svartal already had this exact content and answered 200 with the
    /// existing record instead of 201 with a new one.
    pub duplicate: bool,
}

/// The document's own title, or a sentence when it has none.
pub fn transcript_title<'a>(
    document: &'a Value,
    explicit: Option<&'a str>,
) -> Result<&'a str, CliError> {
    explicit
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .or_else(|| {
            document
                .get("title")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|title| !title.is_empty())
        })
        .ok_or_else(|| CliError("The transcript has no title. Pass `--title <title>`.".to_string()))
}

/// The transcript's detail level: `summary` (messages and one-line tool
/// summaries) or `full`. Read from the document when it says, `summary`
/// otherwise — the document's `format` field names the schema, not the
/// level, so it only counts when it is one of the two words.
pub fn transcript_format(document: &Value) -> &'static str {
    let level = document
        .get("detail")
        .and_then(Value::as_str)
        .or_else(|| document.get("format").and_then(Value::as_str));
    match level {
        Some("full") => "full",
        _ => "summary",
    }
}

/// `POST /projects/:project/transcripts`.
pub fn create_transcript(
    context: &Context<'_>,
    transcript: &NewTranscript<'_>,
) -> Result<SavedTranscript, CliError> {
    let action = "save the transcript";
    let title = transcript_title(transcript.document, transcript.title)?;
    let mut body = json!({
        "title": title,
        "source": "sv",
        "format": transcript_format(transcript.document),
        "transcript": transcript.document,
        "postedVia": transcript.posted_via,
    });
    let thread = transcript
        .document
        .get("threadId")
        .and_then(Value::as_str)
        .or(transcript.thread)
        .map(str::trim)
        .filter(|thread| !thread.is_empty());
    if let Some(thread) = thread {
        body["threadId"] = json!(thread);
    }
    if let Some(work_item_id) = transcript.work_item_id {
        body["workItemId"] = json!(work_item_id);
    }
    if !transcript.bundles.is_empty() {
        body["bundles"] = json!(transcript.bundles);
    }
    let ApiReply {
        status,
        body: reply,
    } = api_request(
        context,
        "POST",
        &format!(
            "/projects/{}/transcripts",
            encode_segment(transcript.project)
        ),
        Some(body),
        action,
    )?;
    let data = reply.get("data").ok_or_else(|| unreadable(action))?;
    let text = |field: &str| data.get(field).and_then(Value::as_str).map(str::to_string);
    let (Some(id), Some(project_id)) = (text("id"), text("projectId")) else {
        return Err(unreadable(action));
    };
    Ok(SavedTranscript {
        id,
        project_id,
        duplicate: status == 200,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_is_svartals_feature_and_the_rest_keep_their_names() {
        assert_eq!(work_item_kind("issue").unwrap(), "feature");
        assert_eq!(work_item_kind("Plan").unwrap(), "plan");
        assert_eq!(work_item_kind("idea").unwrap(), "idea");
        assert!(
            work_item_kind("epic")
                .unwrap_err()
                .contains("issue, bug, chore, investigation, idea, plan")
        );
    }

    #[test]
    fn numbers_take_the_hash_or_not() {
        assert_eq!(parse_number("#12").unwrap(), 12);
        assert_eq!(parse_number("12").unwrap(), 12);
        assert!(parse_number("#0").is_err());
        assert!(parse_number("twelve").is_err());
    }

    #[test]
    fn the_project_slash_is_one_segment() {
        assert_eq!(encode_segment("marc/demo"), "marc%2Fdemo");
        assert_eq!(encode_segment("feature-a_1.0"), "feature-a_1.0");
    }

    #[test]
    fn posted_via_leaves_out_what_is_not_known() {
        let note = posted_via(None, None, Some("laptop"));
        assert_eq!(
            note,
            json!({ "client": "sv", "machine": "laptop", "note": "Posted via the sv CLI" })
        );
        let note = posted_via(Some("claude-code"), Some("t-1"), None);
        assert_eq!(note["agent"], "claude-code");
        assert_eq!(note["threadId"], "t-1");
        assert_eq!(note["note"], "Posted by claude-code via the sv CLI");
        assert!(note.get("machine").is_none());
    }

    #[test]
    fn transcript_format_reads_the_level_not_the_schema_name() {
        assert_eq!(
            transcript_format(&json!({ "format": "ivaldi-transcript/v1" })),
            "summary"
        );
        assert_eq!(
            transcript_format(&json!({ "format": "ivaldi-transcript/v1", "detail": "full" })),
            "full"
        );
        assert_eq!(transcript_format(&json!({ "format": "full" })), "full");
    }
}
