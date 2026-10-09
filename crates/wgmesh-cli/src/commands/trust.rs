use std::io::Write;
use std::path::Path;

use crate::CliError;
use crate::args::Args;
use crate::commands::write_line;
use crate::json::Json;

/// `wgmesh trust show|rotate`: the key this device pins for its coordinator.
///
/// The design makes the pin something that moves only as a deliberate act, and never as the
/// consequence of a failed connection: a peer that can answer on the coordinator's address does
/// not become the coordinator because this device was willing to listen. So the surface is two
/// commands. `show` reads the pin the configuration names and the pin the state recorded, and
/// says whether they agree; `rotate` moves the state's pin onto the configuration's.
///
/// Where a *new* pin comes from is not this command's business. The operator learns it from the
/// certificate — `openssl x509 -in leaf.pem -pubkey -noout | openssl pkey -pubin -outform DER |
/// sha256sum` — and puts it in the configuration, which is what makes a coordinator that changed
/// its key without being asked to refuse rather than be believed.
pub fn show(args: &Args, out: &mut dyn Write) -> Result<(), CliError> {
    let configured = configured_pin(args)?;
    let pinned = pinned_pin(&args.state)?;
    let matches = pinned.as_deref() == Some(configured.as_str());

    if args.json {
        let document = Json::Object(vec![
            ("configured", Json::from(configured.as_str())),
            (
                "pinned",
                pinned
                    .as_deref()
                    .map(|value| Json::from(value))
                    .unwrap_or(Json::Null),
            ),
            ("matches", Json::from(matches)),
        ]);
        write_line(out, document.render_pretty().trim_end())?;
    } else {
        write_line(out, &format!("configured {configured}"))?;
        match &pinned {
            Some(pinned) => write_line(out, &format!("pinned     {pinned}"))?,
            None => write_line(out, "pinned     (none: this device has not enrolled)")?,
        }
    }

    match &pinned {
        None => Ok(()),
        Some(_) if matches => {
            if !args.json {
                write_line(
                    out,
                    "the pin matches, so this device will talk to the coordinator",
                )?;
            }
            Ok(())
        }
        Some(_) => Err(CliError::State(
            "the state pins another coordinator key, so this device refuses to talk to it; run \
             `wgmesh trust rotate` if the coordinator's key really did change"
                .to_string(),
        )),
    }
}

/// `wgmesh trust rotate`: accept the pin the configuration names.
pub fn rotate(args: &Args, out: &mut dyn Write) -> Result<(), CliError> {
    let configured = configured_pin(args)?;
    let Some(mut state) = read_state(&args.state)? else {
        return Err(CliError::State(format!(
            "{}: there is no state to re-pin; enrol this device first",
            args.state.display()
        )));
    };

    let previous = pin_of(&state);
    if previous.as_deref() == Some(configured.as_str()) {
        return write_line(
            out,
            &format!("the pin is already {configured}; nothing changed"),
        );
    }

    let coordinator = state
        .get_mut("coordinator")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| {
            CliError::State(format!(
                "{}: the state has no coordinator table to re-pin",
                args.state.display()
            ))
        })?;
    coordinator.insert(
        "spki_sha256".to_string(),
        serde_json::Value::String(configured.clone()),
    );

    let rendered = serde_json::to_string_pretty(&state)
        .map_err(|error| CliError::State(format!("{}: {error}", args.state.display())))?;
    std::fs::write(&args.state, format!("{rendered}\n"))
        .map_err(|error| CliError::State(format!("{}: {error}", args.state.display())))?;

    write_line(out, &format!("the pin is now {configured}"))?;
    write_line(
        out,
        &format!(
            "(it was {})",
            previous.unwrap_or_else(|| "not set".to_string())
        ),
    )?;
    Ok(())
}

/// The pin the configuration names, or a message saying why it cannot be used.
///
/// An empty pin is refused rather than treated as "pin nothing": the coordinator is never
/// trusted by default, and a pin that quietly accepted every certificate would be exactly that.
fn configured_pin(args: &Args) -> Result<String, CliError> {
    let settings = wgmesh_config::load(&args.config)?;
    let pin = settings.coordinator.spki_sha256.trim();
    if pin.is_empty() {
        return Err(CliError::State(format!(
            "{}: the configuration carries no coordinator.spki_sha256, so nothing is pinned",
            args.config.display()
        )));
    }
    if !wgmesh_config::validate::is_sha256_hex(pin) {
        return Err(CliError::State(format!(
            "{}: coordinator.spki_sha256 is not a SHA-256 hex digest: {pin:?}",
            args.config.display()
        )));
    }
    Ok(pin.to_ascii_lowercase())
}

/// The state document, when there is one.
///
/// It is read as a document rather than through a struct because `rotate` writes one field back:
/// a reader that modelled two fields and wrote the file out again would drop the rest of the
/// state, and the state is the device's memory of what it converged to.
fn read_state(path: &Path) -> Result<Option<serde_json::Value>, CliError> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|error| CliError::State(format!("{}: {error}", path.display()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::State(format!(
            "{}: {error}; pass --state to point at the state file",
            path.display()
        ))),
    }
}

fn pinned_pin(path: &Path) -> Result<Option<String>, CliError> {
    Ok(read_state(path)?.and_then(|state| pin_of(&state)))
}

/// The pin a state document records, when it records one.
fn pin_of(state: &serde_json::Value) -> Option<String> {
    let pin = state
        .get("coordinator")?
        .get("spki_sha256")?
        .as_str()?
        .trim()
        .to_ascii_lowercase();
    (!pin.is_empty()).then_some(pin)
}
