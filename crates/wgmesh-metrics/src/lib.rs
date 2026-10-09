use std::collections::BTreeMap;
use std::fmt::Write as _;

/// What a series means to a scraper.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MetricKind {
    Counter,
    Gauge,
}

impl MetricKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            MetricKind::Counter => "counter",
            MetricKind::Gauge => "gauge",
        }
    }
}

/// A sorted label set, which is what makes a series identity stable: two calls
/// that list the same labels in a different order land on the same series.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Labels(Vec<(String, String)>);

impl Labels {
    pub fn new(pairs: &[(&str, &str)]) -> Self {
        let mut owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        owned.sort();
        Self(owned)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Debug)]
struct Series {
    help: String,
    kind: MetricKind,
    value: f64,
}

/// The metrics a process exposes on its scrape endpoint.
///
/// It is a plain value: the server that serves it owns the lock, so nothing in
/// here has to be atomic.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    series: BTreeMap<(String, Labels), Series>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_counter(&mut self, name: &str, help: &str, labels: &[(&str, &str)], by: f64) {
        self.add(name, help, labels, by, MetricKind::Counter);
    }

    pub fn set_gauge(&mut self, name: &str, help: &str, labels: &[(&str, &str)], value: f64) {
        self.add(name, help, labels, value, MetricKind::Gauge);
    }

    pub fn counter_value(&self, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        self.series
            .get(&(name.to_owned(), Labels::new(labels)))
            .map(|series| series.value)
    }

    pub fn gauge_value(&self, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        self.counter_value(name, labels)
    }

    fn add(&mut self, name: &str, help: &str, labels: &[(&str, &str)], by: f64, kind: MetricKind) {
        let key = (sanitize_name(name), Labels::new(labels));
        match self.series.get_mut(&key) {
            Some(series) => {
                if kind == MetricKind::Gauge {
                    series.value = by;
                } else {
                    series.value += by;
                }
            }
            None => {
                self.series.insert(
                    key,
                    Series {
                        help: help.to_owned(),
                        kind,
                        value: by,
                    },
                );
            }
        }
    }

    /// Render the exposition text a Prometheus scraper reads.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let mut last_name: Option<&str> = None;
        for ((name, labels), series) in &self.series {
            if last_name != Some(name.as_str()) {
                let _ = writeln!(out, "# HELP {name} {}", escape_help(&series.help));
                let _ = writeln!(out, "# TYPE {name} {}", series.kind.as_str());
                last_name = Some(name.as_str());
            }
            let _ = write!(out, "{name}");
            if !labels.is_empty() {
                let _ = write!(out, "{{");
                for (index, (label, value)) in labels.0.iter().enumerate() {
                    if index > 0 {
                        let _ = write!(out, ",");
                    }
                    let _ = write!(
                        out,
                        "{}=\"{}\"",
                        sanitize_name(label),
                        escape_label_value(value)
                    );
                }
                let _ = write!(out, "}}");
            }
            let _ = writeln!(out, " {}", format_value(series.value));
        }
        out
    }
}

/// Prometheus names are `[a-zA-Z_:][a-zA-Z0-9_:]*`, labels `[a-zA-Z_][a-zA-Z0-9_]*`.
/// Anything else is replaced rather than dropped so two distinct names cannot
/// collapse onto one.
pub fn sanitize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for (index, ch) in name.chars().enumerate() {
        let valid = if index == 0 {
            ch.is_ascii_alphabetic() || ch == '_' || ch == ':'
        } else {
            ch.is_ascii_alphanumeric() || ch == '_' || ch == ':'
        };
        out.push(if valid { ch } else { '_' });
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

fn escape_help(help: &str) -> String {
    help.replace('\\', "\\\\").replace('\n', "\\n")
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn format_value(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{}", value as i64)
    } else if value.is_finite() {
        let text = format!("{value:.6}");
        let trimmed = text.trim_end_matches('0').trim_end_matches('.');
        trimmed.to_owned()
    } else {
        // Prometheus spells the non-finite values as these words.
        match value {
            v if v.is_nan() => "NaN".to_owned(),
            v if v > 0.0 => "+Inf".to_owned(),
            _ => "-Inf".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// A deliberately small reader for the exposition format. It is not a
    /// general parser: it understands exactly the shape the renderer produces,
    /// which is what makes it a check on that renderer rather than a second
    /// implementation of the same bug.
    fn parse(text: &str) -> BTreeMap<(String, String), f64> {
        let mut out = BTreeMap::new();
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name_and_labels, value) = line
                .rsplit_once(' ')
                .expect("a sample line ends with a value");
            let parsed: f64 = value.parse().expect("the value is a number");
            let name;
            let labels;
            if let Some(open) = name_and_labels.find('{') {
                let close = name_and_labels.rfind('}').expect("a label set is closed");
                name = &name_and_labels[..open];
                labels = &name_and_labels[open + 1..close];
            } else {
                name = name_and_labels;
                labels = "";
            }
            out.insert((name.to_owned(), labels.to_owned()), parsed);
        }
        out
    }

    #[test]
    fn the_exposition_parses_and_carries_the_values_it_was_given() {
        let mut registry = Registry::new();
        registry.add_counter(
            "wgmesh_join_requests_total",
            "Join requests by outcome.",
            &[("outcome", "allowed")],
            12.0,
        );
        registry.add_counter(
            "wgmesh_join_requests_total",
            "Join requests by outcome.",
            &[("outcome", "denied")],
            3.0,
        );
        registry.set_gauge(
            "wgmesh_relay_slots_active",
            "Slots currently assigned.",
            &[],
            4.0,
        );
        registry.set_gauge(
            "wgmesh_relay_slot_pps",
            "Packets per second on a slot.",
            &[("slot", "51901")],
            17.5,
        );

        let text = registry.render();
        assert!(text.contains("# TYPE wgmesh_join_requests_total counter"));
        assert!(text.contains("# TYPE wgmesh_relay_slots_active gauge"));

        let parsed = parse(&text);
        assert_eq!(
            parsed.get(&(
                "wgmesh_join_requests_total".into(),
                "outcome=\"allowed\"".into()
            )),
            Some(&12.0)
        );
        assert_eq!(
            parsed.get(&(
                "wgmesh_join_requests_total".into(),
                "outcome=\"denied\"".into()
            )),
            Some(&3.0)
        );
        assert_eq!(
            parsed.get(&("wgmesh_relay_slots_active".into(), "".into())),
            Some(&4.0)
        );
        assert_eq!(
            parsed.get(&("wgmesh_relay_slot_pps".into(), "slot=\"51901\"".into())),
            Some(&17.5)
        );
    }

    #[test]
    fn help_and_type_are_emitted_once_per_name() {
        let mut registry = Registry::new();
        registry.add_counter("wgmesh_x_total", "X.", &[("a", "1")], 1.0);
        registry.add_counter("wgmesh_x_total", "X.", &[("a", "2")], 1.0);
        let text = registry.render();
        assert_eq!(text.matches("# HELP wgmesh_x_total").count(), 1);
        assert_eq!(text.matches("# TYPE wgmesh_x_total").count(), 1);
        assert_eq!(text.matches("wgmesh_x_total{").count(), 2);
    }

    #[test]
    fn counters_accumulate_and_gauges_replace() {
        let mut registry = Registry::new();
        registry.add_counter("c_total", "C.", &[], 2.0);
        registry.add_counter("c_total", "C.", &[], 3.0);
        registry.set_gauge("g", "G.", &[], 2.0);
        registry.set_gauge("g", "G.", &[], 9.0);
        assert_eq!(registry.counter_value("c_total", &[]), Some(5.0));
        assert_eq!(registry.gauge_value("g", &[]), Some(9.0));
    }

    #[test]
    fn labels_are_order_independent_and_hostile_values_are_escaped() {
        let mut registry = Registry::new();
        registry.add_counter("e_total", "E.", &[("a", "1"), ("b", "2")], 1.0);
        registry.add_counter("e_total", "E.", &[("b", "2"), ("a", "1")], 1.0);
        assert_eq!(
            registry.counter_value("e_total", &[("a", "1"), ("b", "2")]),
            Some(2.0)
        );

        let mut awkward = Registry::new();
        awkward.set_gauge(
            "q",
            "a \"quote\" and a \\ and a \n newline",
            &[("why", "a\"b\nc")],
            1.0,
        );
        let text = awkward.render();
        assert!(
            !text
                .lines()
                .any(|line| line.starts_with("# HELP q a \"quote\" and a \\ and a "))
        );
        let parsed = parse(&text);
        assert!(
            parsed
                .keys()
                .any(|(name, labels)| name == "q" && labels == "why=\"a\\\"b\\nc\"")
        );
    }

    #[test]
    fn a_name_that_is_not_a_prometheus_name_is_repaired_not_dropped() {
        assert_eq!(sanitize_name("wgmesh-relay.slots"), "wgmesh_relay_slots");
        assert_eq!(sanitize_name("9lives"), "_lives");
        assert_eq!(sanitize_name(""), "_");
    }
}
