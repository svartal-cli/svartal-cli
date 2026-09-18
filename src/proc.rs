//! Running the system's own tools, behind a trait so a test can answer them.
//!
//! The sv:// half of this CLI talks to three programs that belong to the
//! operating system — `/usr/bin/open`, `/usr/bin/osacompile` and LaunchServices'
//! `lsregister` — and none of them may be run from a test. Every call goes
//! through [`ProcessRunner`]; the product passes [`SystemRunner`], and a test
//! passes a script.

/// What a finished program said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    /// Its exit status succeeded.
    pub success: bool,
    /// Its stderr, trimmed. The one channel a tool like `osacompile` explains
    /// itself on, and the sentence a failure should carry.
    pub stderr: String,
}

impl ProcessOutput {
    pub fn succeeded() -> Self {
        Self {
            success: true,
            stderr: String::new(),
        }
    }

    pub fn failed(detail: &str) -> Self {
        Self {
            success: false,
            stderr: detail.to_string(),
        }
    }
}

/// Run a program to completion.
pub trait ProcessRunner {
    /// `Err` means the program could not be run at all; `Ok` carries its
    /// status and stderr however it ended.
    fn run(&self, program: &str, args: &[&str]) -> Result<ProcessOutput, String>;
}

/// The real thing: `std::process::Command`, output captured.
pub struct SystemRunner;

impl ProcessRunner for SystemRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<ProcessOutput, String> {
        let output = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|error| format!("could not run {program}: {error}"))?;
        Ok(ProcessOutput {
            success: output.status.success(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}
