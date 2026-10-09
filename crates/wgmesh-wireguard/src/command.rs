use std::process::Command;

use wgmesh_ports::RouteError;

/// What a command answered, kept together with the argv that produced it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CommandOutput {
    pub program: String,
    pub args: Vec<String>,
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(self.args.len() + 1);
        argv.push(self.program.clone());
        argv.extend(self.args.iter().cloned());
        argv
    }

    /// The command as an operator would retype it.
    pub fn line(&self) -> String {
        self.argv().join(" ")
    }

    pub fn succeeded(&self) -> bool {
        self.status == 0
    }

    /// Turn a refusal into the error the ports speak, with the argv attached.
    ///
    /// A kernel that refuses is not a world that was briefly unavailable: the same command
    /// will be refused again, so the class is fatal and the message carries what to retype.
    pub fn into_error(self) -> RouteError {
        RouteError::fatal(format!(
            "`{}` exited with {}: {}",
            self.line(),
            self.status,
            self.stderr.trim()
        ))
    }
}

/// Every kernel-side effect in this crate goes through here, so a test can read the exact
/// argv a configuration produces without a kernel, a capability or root.
pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, RouteError>;
}

impl<T: CommandRunner + ?Sized> CommandRunner for std::sync::Arc<T> {
    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, RouteError> {
        (**self).run(program, args)
    }
}

/// The real thing: `ip` and `nft`, started without a shell so no argument is ever re-split
/// and no quoting mistake can turn a prefix into an option.
pub struct ProcessRunner;

impl CommandRunner for ProcessRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, RouteError> {
        let output = Command::new(program).args(args).output().map_err(|error| {
            RouteError::fatal(format!("{program} could not be started: {error}"))
        })?;
        Ok(CommandOutput {
            program: program.to_owned(),
            args: args.to_vec(),
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

pub fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}
