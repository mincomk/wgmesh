use std::collections::BTreeMap;
use std::sync::Mutex;

use wgmesh_ports::{RouteError, Sysctl};

use crate::command::{CommandOutput, CommandRunner};

/// A `CommandRunner` that runs nothing. It records every argv and answers from a script the
/// test writes, so an adapter test reads like the commands the host would see.
#[derive(Default)]
pub struct RecordingRunner {
    seen: Mutex<Vec<Vec<String>>>,
    answers: Mutex<Vec<(String, String, CommandOutput)>>,
}

impl RecordingRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer every call to `program` with this stdout and a zero status.
    pub fn answer(&self, program: &str, stdout: &str) {
        self.answer_containing(program, "", 0, stdout, "");
    }

    /// Answer the calls to `program` whose joined argv contains `needle`, and let every
    /// other call succeed with no output. The first matching answer wins, so specific
    /// answers are added before general ones.
    pub fn answer_containing(
        &self,
        program: &str,
        needle: &str,
        status: i32,
        stdout: &str,
        stderr: &str,
    ) {
        let mut answers = match self.answers.lock() {
            Ok(answers) => answers,
            Err(poisoned) => poisoned.into_inner(),
        };
        answers.push((
            program.to_owned(),
            needle.to_owned(),
            CommandOutput {
                program: program.to_owned(),
                args: Vec::new(),
                status,
                stdout: stdout.to_owned(),
                stderr: stderr.to_owned(),
            },
        ));
    }

    pub fn seen(&self) -> Vec<Vec<String>> {
        match self.seen.lock() {
            Ok(seen) => seen.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Every command as an operator would retype it.
    pub fn lines(&self) -> Vec<String> {
        self.seen().into_iter().map(|argv| argv.join(" ")).collect()
    }

    /// The distinct programs that were started, to prove nothing else is invoked.
    pub fn programs(&self) -> Vec<String> {
        let mut programs: Vec<String> = self
            .seen()
            .into_iter()
            .map(|argv| argv.first().cloned().unwrap_or_default())
            .collect();
        programs.sort();
        programs.dedup();
        programs
    }

    pub fn clear(&self) {
        match self.seen.lock() {
            Ok(mut seen) => seen.clear(),
            Err(poisoned) => poisoned.into_inner().clear(),
        }
    }
}

impl CommandRunner for RecordingRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, RouteError> {
        let mut argv = Vec::with_capacity(args.len() + 1);
        argv.push(program.to_owned());
        argv.extend(args.iter().cloned());
        let joined = argv.join(" ");
        match self.seen.lock() {
            Ok(mut seen) => seen.push(argv),
            Err(poisoned) => poisoned.into_inner().push(argv),
        }

        let answers = match self.answers.lock() {
            Ok(answers) => answers,
            Err(poisoned) => poisoned.into_inner(),
        };
        let found = answers
            .iter()
            .find(|(name, needle, _)| name == program && joined.contains(needle.as_str()));
        match found {
            Some((_, _, answer)) => Ok(CommandOutput {
                program: program.to_owned(),
                args: args.to_vec(),
                status: answer.status,
                stdout: answer.stdout.clone(),
                stderr: answer.stderr.clone(),
            }),
            None => Ok(CommandOutput {
                program: program.to_owned(),
                args: args.to_vec(),
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            }),
        }
    }
}

/// A `Sysctl` in front of a map. Reads and writes are recorded separately, because
/// "`sysctl = false` must not touch anything" is a claim about calls, not about values.
#[derive(Default)]
pub struct RecordingSysctl {
    values: Mutex<BTreeMap<String, String>>,
    reads: Mutex<Vec<String>>,
    writes: Mutex<Vec<(String, String)>>,
}

impl RecordingSysctl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed(&self, key: &str, value: &str) {
        match self.values.lock() {
            Ok(mut values) => values.insert(key.to_owned(), value.to_owned()),
            Err(poisoned) => poisoned
                .into_inner()
                .insert(key.to_owned(), value.to_owned()),
        };
    }

    pub fn value(&self, key: &str) -> Option<String> {
        match self.values.lock() {
            Ok(values) => values.get(key).cloned(),
            Err(poisoned) => poisoned.into_inner().get(key).cloned(),
        }
    }

    pub fn reads(&self) -> Vec<String> {
        match self.reads.lock() {
            Ok(reads) => reads.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn writes(&self) -> Vec<(String, String)> {
        match self.writes.lock() {
            Ok(writes) => writes.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl Sysctl for RecordingSysctl {
    fn read(&self, key: &str) -> Result<String, RouteError> {
        match self.reads.lock() {
            Ok(mut reads) => reads.push(key.to_owned()),
            Err(poisoned) => poisoned.into_inner().push(key.to_owned()),
        }
        match self.values.lock() {
            Ok(values) => values.get(key).cloned(),
            Err(poisoned) => poisoned.into_inner().get(key).cloned(),
        }
        .ok_or_else(|| RouteError::fatal(format!("{key} is not a known sysctl")))
    }

    fn write(&self, key: &str, value: &str) -> Result<(), RouteError> {
        match self.writes.lock() {
            Ok(mut writes) => writes.push((key.to_owned(), value.to_owned())),
            Err(poisoned) => poisoned
                .into_inner()
                .push((key.to_owned(), value.to_owned())),
        }
        match self.values.lock() {
            Ok(mut values) => values.insert(key.to_owned(), value.to_owned()),
            Err(poisoned) => poisoned
                .into_inner()
                .insert(key.to_owned(), value.to_owned()),
        };
        Ok(())
    }
}
