// What a command fails with, and the exit code it leaves behind.

use std::fmt;

/// How serious a configuration problem is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    /// The configuration cannot be used.
    Error,
    /// The configuration works, but not the way the operator probably meant.
    Warning,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error => f.write_str("error"),
            Self::Warning => f.write_str("warning"),
        }
    }
}

/// One thing wrong with the configuration.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Problem {
    /// The configuration path the problem is about.
    pub field: String,
    /// How serious it is.
    pub severity: Severity,
    /// What is wrong.
    pub message: String,
}

impl Problem {
    /// A problem that stops the command.
    pub fn error(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            severity: Severity::Error,
            message: message.into(),
        }
    }

    /// A problem worth printing but not worth stopping for.
    pub fn warning(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            severity: Severity::Warning,
            message: message.into(),
        }
    }

    /// The one line this problem prints as.
    pub fn line(&self) -> String {
        format!("{}: {}: {}", self.severity, self.field, self.message)
    }
}

/// What a `wgmesh` command failed with.
#[derive(Debug)]
pub enum CliError {
    /// The configuration does not validate. Every problem is reported, not just the first.
    Configuration(Vec<Problem>),
    /// The command line is wrong.
    Usage(String),
    /// Anything else that went wrong at runtime.
    Runtime(String),
}

impl CliError {
    /// The exit code this failure leaves behind.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Configuration(_) => 3,
            Self::Usage(_) => 2,
            Self::Runtime(_) => 1,
        }
    }

    /// A runtime failure.
    pub fn runtime(message: impl Into<String>) -> Self {
        Self::Runtime(message.into())
    }

    /// A command line that asks for something the binary will not do.
    pub fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }

    /// A configuration that did not validate.
    pub fn configuration(problems: Vec<Problem>) -> Self {
        Self::Configuration(problems)
    }

    /// Whether any of the problems is an error.
    pub fn has_errors(&self) -> bool {
        match self {
            Self::Configuration(problems) => problems
                .iter()
                .any(|problem| problem.severity == Severity::Error),
            _ => true,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(problems) => {
                for problem in problems {
                    writeln!(f, "{}", problem.line())?;
                }
                let errors = problems
                    .iter()
                    .filter(|problem| problem.severity == Severity::Error)
                    .count();
                let warnings = problems.len() - errors;
                write!(
                    f,
                    "{} problem{} ({errors} error{}, {warnings} warning{})",
                    problems.len(),
                    if problems.len() == 1 { "" } else { "s" },
                    if errors == 1 { "" } else { "s" },
                    if warnings == 1 { "" } else { "s" }
                )
            }
            Self::Usage(message) | Self::Runtime(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CliError {}
