use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use serde::de::{Deserializer, Error as DeError, SeqAccess, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use wgmesh_core::Allowed;
use wgmesh_core::route::{RoutePrefixes, RouteTable};

/// A CIDR prefix as configuration, state and the command line spell it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Prefix {
    V4([u8; 4], u8),
    V6([u8; 16], u8),
}

impl Prefix {
    /// The prefix length in bits.
    pub fn bits(&self) -> u8 {
        match self {
            Prefix::V4(_, bits) => *bits,
            Prefix::V6(_, bits) => *bits,
        }
    }

    /// Whether this prefix is a default route, which this product never installs.
    pub fn is_catch_all(&self) -> bool {
        match self {
            Prefix::V4(bytes, bits) => *bits == 0 && bytes.iter().all(|byte| *byte == 0),
            Prefix::V6(bytes, bits) => *bits == 0 && bytes.iter().all(|byte| *byte == 0),
        }
    }

    /// The core representation, which carries no serde and no parsing.
    pub fn to_core(self) -> Allowed {
        match self {
            Prefix::V4(bytes, bits) => Allowed::V4(bytes, bits),
            Prefix::V6(bytes, bits) => Allowed::V6(bytes, bits),
        }
    }

    /// Read a core prefix back into the configuration representation.
    pub fn from_core(allowed: Allowed) -> Self {
        match allowed {
            Allowed::V4(bytes, bits) => Prefix::V4(bytes, bits),
            Allowed::V6(bytes, bits) => Prefix::V6(bytes, bits),
        }
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Prefix::V4(bytes, bits) => write!(
                formatter,
                "{}.{}.{}.{}/{}",
                bytes[0], bytes[1], bytes[2], bytes[3], bits
            ),
            Prefix::V6(bytes, bits) => write!(formatter, "{}/{}", Ipv6Addr::from(*bytes), bits),
        }
    }
}

/// A prefix that could not be read, with the reason it could not be read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrefixParseError {
    input: String,
    reason: &'static str,
}

impl PrefixParseError {
    fn new(input: &str, reason: &'static str) -> Self {
        Self {
            input: input.to_string(),
            reason,
        }
    }

    /// The reason the prefix was rejected.
    pub fn reason(&self) -> &'static str {
        self.reason
    }

    /// The prefix as it was written.
    pub fn input(&self) -> &str {
        &self.input
    }
}

impl fmt::Display for PrefixParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "\"{}\" is not a CIDR prefix: {}",
            self.input, self.reason
        )
    }
}

impl std::error::Error for PrefixParseError {}

impl FromStr for Prefix {
    type Err = PrefixParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let trimmed = text.trim();
        let Some((address, bits)) = trimmed.split_once('/') else {
            return Err(PrefixParseError::new(
                text,
                "expected <address>/<prefix length>, for example 10.77.0.0/16",
            ));
        };
        let bits: u8 = bits
            .parse()
            .map_err(|_| PrefixParseError::new(text, "the prefix length is not a number"))?;
        if let Ok(address) = address.parse::<Ipv4Addr>() {
            if bits > 32 {
                return Err(PrefixParseError::new(
                    text,
                    "an IPv4 prefix length is at most 32",
                ));
            }
            return Ok(Prefix::V4(address.octets(), bits));
        }
        if let Ok(address) = address.parse::<Ipv6Addr>() {
            if bits > 128 {
                return Err(PrefixParseError::new(
                    text,
                    "an IPv6 prefix length is at most 128",
                ));
            }
            return Ok(Prefix::V6(address.octets(), bits));
        }
        Err(PrefixParseError::new(
            text,
            "the address is neither IPv4 nor IPv6",
        ))
    }
}

impl Serialize for Prefix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

struct PrefixVisitor;

impl<'de> Visitor<'de> for PrefixVisitor {
    type Value = Prefix;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a CIDR prefix such as \"10.77.0.0/16\" or \"fd00::/64\"")
    }

    fn visit_str<E: DeError>(self, text: &str) -> Result<Self::Value, E> {
        Prefix::from_str(text).map_err(|error| E::custom(error.to_string()))
    }
}

impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(PrefixVisitor)
    }
}

/// What `[route] table` selects: the main table, a numbered table, or no routes at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouteTableSetting {
    Unmanaged,
    Main,
    Number(u32),
}

impl RouteTableSetting {
    /// Whether routes are installed at all.
    pub fn is_managed(self) -> bool {
        !matches!(self, RouteTableSetting::Unmanaged)
    }

    /// The core representation.
    pub fn to_core(self) -> RouteTable {
        match self {
            RouteTableSetting::Unmanaged => RouteTable::Unmanaged,
            RouteTableSetting::Main => RouteTable::Main,
            RouteTableSetting::Number(number) => RouteTable::Number(number),
        }
    }
}

struct RouteTableVisitor;

impl<'de> Visitor<'de> for RouteTableVisitor {
    type Value = RouteTableSetting;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one of \"main\", \"auto\", \"off\", or a routing table number")
    }

    fn visit_str<E: DeError>(self, text: &str) -> Result<Self::Value, E> {
        let lowered = text.trim().to_ascii_lowercase();
        match lowered.as_str() {
            "main" | "auto" => Ok(RouteTableSetting::Main),
            "off" | "none" => Ok(RouteTableSetting::Unmanaged),
            _ => match lowered.parse::<u32>() {
                Ok(number) => Ok(RouteTableSetting::Number(number)),
                Err(_) => Err(E::custom(format!(
                    "expected \"main\", \"auto\", \"off\", or a routing table number, found \"{text}\""
                ))),
            },
        }
    }

    fn visit_u64<E: DeError>(self, value: u64) -> Result<Self::Value, E> {
        u32::try_from(value)
            .map(RouteTableSetting::Number)
            .map_err(|_| {
                E::custom(format!(
                    "routing table number {value} does not fit in 32 bits"
                ))
            })
    }

    fn visit_i64<E: DeError>(self, value: i64) -> Result<Self::Value, E> {
        u32::try_from(value)
            .map(RouteTableSetting::Number)
            .map_err(|_| {
                E::custom(format!(
                    "routing table number {value} is not a positive 32-bit number"
                ))
            })
    }
}

impl Serialize for RouteTableSetting {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            RouteTableSetting::Unmanaged => serializer.serialize_str("off"),
            RouteTableSetting::Main => serializer.serialize_str("main"),
            RouteTableSetting::Number(number) => serializer.serialize_u32(*number),
        }
    }
}

impl<'de> Deserialize<'de> for RouteTableSetting {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(RouteTableVisitor)
    }
}

/// What `[route] prefixes` selects: everything, nothing, or a list somebody chose.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RoutePrefixesSetting {
    Auto,
    None,
    Only(Vec<Prefix>),
}

impl RoutePrefixesSetting {
    /// The core representation.
    pub fn to_core(&self) -> RoutePrefixes {
        match self {
            RoutePrefixesSetting::Auto => RoutePrefixes::Auto,
            RoutePrefixesSetting::None => RoutePrefixes::None,
            RoutePrefixesSetting::Only(prefixes) => {
                RoutePrefixes::Only(prefixes.iter().map(|prefix| prefix.to_core()).collect())
            }
        }
    }
}

struct RoutePrefixesVisitor;

impl<'de> Visitor<'de> for RoutePrefixesVisitor {
    type Value = RoutePrefixesSetting;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("\"auto\", \"none\", or a list of CIDR prefixes")
    }

    fn visit_str<E: DeError>(self, text: &str) -> Result<Self::Value, E> {
        match text.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(RoutePrefixesSetting::Auto),
            "none" | "off" => Ok(RoutePrefixesSetting::None),
            other => Err(E::custom(format!(
                "expected \"auto\", \"none\", or a list of prefixes, found \"{other}\""
            ))),
        }
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut prefixes = Vec::new();
        while let Some(prefix) = sequence.next_element::<Prefix>()? {
            prefixes.push(prefix);
        }
        Ok(RoutePrefixesSetting::Only(prefixes))
    }
}

impl Serialize for RoutePrefixesSetting {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            RoutePrefixesSetting::Auto => serializer.serialize_str("auto"),
            RoutePrefixesSetting::None => serializer.serialize_str("none"),
            RoutePrefixesSetting::Only(prefixes) => prefixes.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for RoutePrefixesSetting {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(RoutePrefixesVisitor)
    }
}

/// What `[route] address` does with the tunnel address: take it, drop it, or fix it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AddressSetting {
    Auto,
    None,
    Only(Prefix),
}

struct AddressVisitor;

impl<'de> Visitor<'de> for AddressVisitor {
    type Value = AddressSetting;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("\"auto\", \"none\", or a CIDR prefix")
    }

    fn visit_str<E: DeError>(self, text: &str) -> Result<Self::Value, E> {
        match text.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(AddressSetting::Auto),
            "none" => Ok(AddressSetting::None),
            other => Prefix::from_str(other)
                .map(AddressSetting::Only)
                .map_err(|error| E::custom(error.to_string())),
        }
    }
}

impl Serialize for AddressSetting {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            AddressSetting::Auto => serializer.serialize_str("auto"),
            AddressSetting::None => serializer.serialize_str("none"),
            AddressSetting::Only(prefix) => prefix.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for AddressSetting {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(AddressVisitor)
    }
}

/// Which peers may carry a catch-all AllowedIPs entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum AllowedIpsSetting {
    #[default]
    Peer,
    Any,
}

/// Whether the daemon manages an nftables table of its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum FirewallSetting {
    #[default]
    Off,
    Manage,
}

/// Which relays the agent is willing to be assigned to.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum RelayPoolSetting {
    #[default]
    Any,
    OperatorOnly,
    Only(Vec<String>),
}

struct RelayPoolVisitor;

impl<'de> Visitor<'de> for RelayPoolVisitor {
    type Value = RelayPoolSetting;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("\"any\", \"operator-only\", or a list of relay names")
    }

    fn visit_str<E: DeError>(self, text: &str) -> Result<Self::Value, E> {
        match text.trim().to_ascii_lowercase().as_str() {
            "any" => Ok(RelayPoolSetting::Any),
            "operator-only" | "operator_only" | "operatoronly" => {
                Ok(RelayPoolSetting::OperatorOnly)
            }
            other => Err(E::custom(format!(
                "expected \"any\", \"operator-only\", or a list of relay names, found \"{other}\""
            ))),
        }
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut names = Vec::new();
        while let Some(name) = sequence.next_element::<String>()? {
            names.push(name);
        }
        Ok(RelayPoolSetting::Only(names))
    }
}

impl Serialize for RelayPoolSetting {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            RelayPoolSetting::Any => serializer.serialize_str("any"),
            RelayPoolSetting::OperatorOnly => serializer.serialize_str("operator-only"),
            RelayPoolSetting::Only(names) => names.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for RelayPoolSetting {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(RelayPoolVisitor)
    }
}

/// The `[route]` table: which prefixes reach the kernel routing table, and in which table.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteSection {
    pub table: RouteTableSetting,
    pub prefixes: RoutePrefixesSetting,
    pub metric: u32,
    pub address: AddressSetting,
}

impl Default for RouteSection {
    fn default() -> Self {
        Self {
            table: RouteTableSetting::Main,
            prefixes: RoutePrefixesSetting::Auto,
            metric: 0,
            address: AddressSetting::Auto,
        }
    }
}

impl RouteSection {
    /// The metric as an option, where zero means "do not set one".
    pub fn metric(&self) -> Option<u32> {
        if self.metric == 0 {
            None
        } else {
            Some(self.metric)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(text: &str) -> Prefix {
        match Prefix::from_str(text) {
            Ok(prefix) => prefix,
            Err(error) => panic!("{text}: {error}"),
        }
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(default, deny_unknown_fields)]
    #[derive(Default)]
    struct Probe {
        route: RouteSection,
    }

    fn probe(document: &str) -> Probe {
        match toml::from_str::<Probe>(document) {
            Ok(probe) => probe,
            Err(error) => panic!("{document}: {error}"),
        }
    }

    #[test]
    fn a_prefix_round_trips_through_its_text_form() {
        for text in [
            "10.77.0.0/16",
            "192.168.5.0/24",
            "0.0.0.0/0",
            "fd00::/64",
            "::/0",
        ] {
            assert_eq!(prefix(text).to_string(), text);
        }
    }

    #[test]
    fn a_prefix_keeps_the_shape_core_uses() {
        assert_eq!(
            prefix("10.77.0.7/32").to_core(),
            Allowed::V4([10, 77, 0, 7], 32)
        );
        assert_eq!(Prefix::from_core(Allowed::V6([0; 16], 0)), prefix("::/0"));
    }

    #[test]
    fn a_prefix_that_is_not_a_cidr_prefix_is_rejected() {
        for text in [
            "10.77.0.0",
            "10.77.0.0/33",
            "fd00::/129",
            "hello/16",
            "10.77.0.0/x",
        ] {
            assert!(
                Prefix::from_str(text).is_err(),
                "{text} was accepted as a prefix"
            );
        }
    }

    #[test]
    fn the_catch_all_prefixes_are_recognized() {
        assert!(prefix("0.0.0.0/0").is_catch_all());
        assert!(prefix("::/0").is_catch_all());
        assert!(!prefix("10.77.0.0/16").is_catch_all());
        assert!(!prefix("0.0.0.0/1").is_catch_all());
    }

    #[test]
    fn the_route_table_accepts_names_and_numbers() {
        assert_eq!(
            probe("[route]\ntable = \"main\"").route.table,
            RouteTableSetting::Main
        );
        assert_eq!(
            probe("[route]\ntable = \"auto\"").route.table,
            RouteTableSetting::Main
        );
        assert_eq!(
            probe("[route]\ntable = \"off\"").route.table,
            RouteTableSetting::Unmanaged
        );
        assert_eq!(
            probe("[route]\ntable = 51820").route.table,
            RouteTableSetting::Number(51820)
        );
        assert_eq!(
            probe("[route]\ntable = \"51821\"").route.table,
            RouteTableSetting::Number(51821)
        );
        assert!(
            toml::from_str::<Probe>("[route]\ntable = \"sideways\"").is_err(),
            "an unknown table name was accepted"
        );
    }

    #[test]
    fn the_prefix_policy_accepts_auto_none_and_a_list() {
        assert_eq!(
            probe("[route]\nprefixes = \"auto\"").route.prefixes,
            RoutePrefixesSetting::Auto
        );
        assert_eq!(
            probe("[route]\nprefixes = \"none\"").route.prefixes,
            RoutePrefixesSetting::None
        );
        assert_eq!(
            probe("[route]\nprefixes = [\"10.77.0.0/16\", \"192.168.5.0/24\"]")
                .route
                .prefixes,
            RoutePrefixesSetting::Only(vec![prefix("10.77.0.0/16"), prefix("192.168.5.0/24")])
        );
        assert!(
            toml::from_str::<Probe>("[route]\nprefixes = \"sometimes\"").is_err(),
            "an unknown prefix policy was accepted"
        );
    }

    #[test]
    fn the_address_policy_accepts_auto_none_and_a_prefix() {
        assert_eq!(
            probe("[route]\naddress = \"auto\"").route.address,
            AddressSetting::Auto
        );
        assert_eq!(
            probe("[route]\naddress = \"none\"").route.address,
            AddressSetting::None
        );
        assert_eq!(
            probe("[route]\naddress = \"10.77.0.7/16\"").route.address,
            AddressSetting::Only(prefix("10.77.0.7/16"))
        );
    }

    #[test]
    fn a_zero_metric_means_no_metric_at_all() {
        assert_eq!(probe("").route.metric(), None);
        assert_eq!(probe("[route]\nmetric = 50").route.metric(), Some(50));
    }

    #[test]
    fn the_route_section_renders_back_to_what_it_was_read_from() {
        let document = r#"
[route]
table = "off"
prefixes = "auto"
metric = 0
address = "none"
"#;
        let rendered = match toml::to_string_pretty(&probe(document)) {
            Ok(text) => text,
            Err(error) => panic!("render: {error}"),
        };
        let again = probe(&rendered);
        assert_eq!(again.route, probe(document).route);
    }

    #[test]
    fn the_relay_pool_accepts_names_and_lists() {
        #[derive(Debug, Deserialize)]
        struct Pool {
            pool: RelayPoolSetting,
        }
        let any = match toml::from_str::<Pool>("pool = \"any\"") {
            Ok(pool) => pool,
            Err(error) => panic!("any: {error}"),
        };
        assert_eq!(any.pool, RelayPoolSetting::Any);
        let operator = match toml::from_str::<Pool>("pool = \"operator-only\"") {
            Ok(pool) => pool,
            Err(error) => panic!("operator-only: {error}"),
        };
        assert_eq!(operator.pool, RelayPoolSetting::OperatorOnly);
        let listed = match toml::from_str::<Pool>("pool = [\"relay-1\", \"relay-3\"]") {
            Ok(pool) => pool,
            Err(error) => panic!("list: {error}"),
        };
        assert_eq!(
            listed.pool,
            RelayPoolSetting::Only(vec!["relay-1".to_string(), "relay-3".to_string()])
        );
    }
}
