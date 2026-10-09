use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::CliError;

/// The flag surface of the routing commands: small enough to parse by hand, which keeps the
/// binary's dependency list short and the parsing testable without a terminal.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Args {
    pub command: Command,
    pub config: PathBuf,
    pub state: PathBuf,
    pub json: bool,
    pub interface: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Command {
    Peers,
    RoutesPlan,
    RoutesReset,
    /// Print the pin the configuration names and the pin the state holds.
    TrustShow,
    /// Move the state's pin onto the pin the configuration names.
    TrustRotate,
    Doctor,
}

/// Where a configuration file and a state file live when nothing says otherwise.
pub const DEFAULT_CONFIG: &str = "/etc/wgmesh/agent.toml";
pub const DEFAULT_STATE: &str = "/var/lib/wgmesh/state.json";
pub const DEFAULT_INTERFACE: &str = "wg0";

impl Args {
    pub fn parse<I: IntoIterator<Item = String>>(arguments: I) -> Result<Self, CliError> {
        let mut args = arguments.into_iter();
        let program = args.next().unwrap_or_else(|| String::from("wgmesh"));
        let mut command: Option<Command> = None;
        let mut config = PathBuf::from(DEFAULT_CONFIG);
        let mut state = PathBuf::from(DEFAULT_STATE);
        let mut json = false;
        let mut interface = String::from(DEFAULT_INTERFACE);

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "peers" => command = Some(Command::Peers),
                "routes" => {
                    let subcommand = args.next().ok_or_else(|| {
                        CliError::Usage(format!("`{program} routes` needs one of plan, reset"))
                    })?;
                    command = Some(match subcommand.as_str() {
                        "plan" => Command::RoutesPlan,
                        "reset" => Command::RoutesReset,
                        other => {
                            return Err(CliError::Usage(format!(
                                "`{program} routes {other}` is not a command; try plan or reset"
                            )));
                        }
                    });
                }
                "doctor" => command = Some(Command::Doctor),
                "trust" => {
                    let subcommand = args.next().ok_or_else(|| {
                        CliError::Usage(format!("`{program} trust` needs one of show, rotate"))
                    })?;
                    command = Some(match subcommand.as_str() {
                        "show" => Command::TrustShow,
                        "rotate" => Command::TrustRotate,
                        other => {
                            return Err(CliError::Usage(format!(
                                "`{program} trust {other}` is not a command; try show or rotate"
                            )));
                        }
                    });
                }
                "--config" => config = PathBuf::from(next_value(&mut args, "--config")?),
                "--state" => state = PathBuf::from(next_value(&mut args, "--state")?),
                "--interface" => interface = next_value(&mut args, "--interface")?,
                "--json" => json = true,
                "--help" | "-h" => return Err(CliError::Usage(usage(&program))),
                other => {
                    return Err(CliError::Usage(format!(
                        "`{other}` is not an argument this command takes\n{}",
                        usage(&program)
                    )));
                }
            }
        }

        Ok(Self {
            command: command.ok_or_else(|| CliError::Usage(usage(&program)))?,
            config,
            state,
            json,
            interface,
        })
    }

    /// The options that were given, for the plan's own report.
    pub fn as_fields(&self) -> BTreeMap<&'static str, String> {
        let mut fields = BTreeMap::new();
        fields.insert("config", self.config.display().to_string());
        fields.insert("state", self.state.display().to_string());
        fields.insert("interface", self.interface.clone());
        fields
    }
}

fn next_value<I: Iterator<Item = String>>(args: &mut I, flag: &str) -> Result<String, CliError> {
    args.next()
        .ok_or_else(|| CliError::Usage(format!("`{flag}` needs a value")))
}

fn usage(program: &str) -> String {
    format!(
        "usage:\n  \
         {program} peers        [--config PATH] [--state PATH] [--json]\n  \
         {program} routes plan  [--config PATH] [--state PATH] [--interface NAME] [--json]\n  \
         {program} routes reset [--config PATH] [--interface NAME] [--json]\n  \
         {program} trust show   [--config PATH] [--state PATH] [--json]\n  \
         {program} trust rotate [--config PATH] [--state PATH]\n  \
         {program} doctor       [--config PATH] [--json]"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(words: &[&str]) -> Result<Args, CliError> {
        let mut arguments = vec![String::from("wgmesh")];
        arguments.extend(words.iter().map(|word| (*word).to_owned()));
        Args::parse(arguments)
    }

    #[test]
    fn the_routing_commands_parse_with_their_options() {
        let args = parse(&["peers", "--json"]).expect("parses");
        assert_eq!(args.command, Command::Peers);
        assert!(args.json);
        assert_eq!(args.config, PathBuf::from(DEFAULT_CONFIG));

        let args = parse(&[
            "routes",
            "plan",
            "--config",
            "/tmp/agent.toml",
            "--state",
            "/tmp/state.json",
            "--interface",
            "wg7",
        ])
        .expect("parses");
        assert_eq!(args.command, Command::RoutesPlan);
        assert_eq!(args.config, PathBuf::from("/tmp/agent.toml"));
        assert_eq!(args.state, PathBuf::from("/tmp/state.json"));
        assert_eq!(args.interface, "wg7");

        assert_eq!(
            parse(&["routes", "reset"]).expect("parses").command,
            Command::RoutesReset
        );
        assert_eq!(parse(&["doctor"]).expect("parses").command, Command::Doctor);
        assert_eq!(
            parse(&["--config", "/tmp/c", "peers"])
                .expect("flags may come first")
                .command,
            Command::Peers
        );
    }

    #[test]
    fn an_unknown_command_is_refused_with_the_usage_line() {
        let error = parse(&["routes", "apply"]).unwrap_err();
        assert!(error.to_string().contains("try plan or reset"));
        assert!(parse(&[]).unwrap_err().to_string().contains("usage:"));
        assert!(
            parse(&["--config"])
                .unwrap_err()
                .to_string()
                .contains("needs a value")
        );
        assert!(matches!(parse(&["--help"]), Err(CliError::Usage(_))));
    }
}
