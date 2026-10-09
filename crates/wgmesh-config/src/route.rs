use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

use serde::de::{Deserializer, Error as DeError, SeqAccess, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use wgmesh_core::{Allowed, RoutePrefixes, RouteTable};

/// A CIDR band, the way a configuration file spells it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Prefix {
    V4([u8; 4], u8),
    V6([u8; 16], u8),
}

impl Prefix {
    pub fn bits(self) -> u8 {
        match self {
            Prefix::V4(_, bits) => bits,
            Prefix::V6(_, bits) => bits,
        }
    }

    /// Whether this is a default route. This product never puts one in the kernel table.
    pub fn is_catch_all(self) -> bool {
        match self {
            Prefix::V4(bytes, bits) => bits == 0 && bytes.iter().all(|byte| *byte == 0),
            Prefix::V6(bytes, bits) => bits == 0 && bytes.iter().all(|byte| *byte == 0),
        }
    }

    /// The core representation, which carries no serde and no parsing.
    pub fn to_core(self) -> Allowed {
        match self {
            Prefix::V4(bytes, bits) => Allowed::V4(bytes, bits),
            Prefix::V6(bytes, bits) => Allowed::V6(bytes, bits),
        }
    }

    pub fn from_core(allowed: Allowed) -> Self {
        match allowed {
            Allowed::V4(bytes, bits) => Prefix::V4(bytes, bits),
            Allowed::V6(bytes, bits) => Prefix::V6(bytes, bits),
        }
    }

    /// The text form, which is also what `ip` takes on its command line.
    pub fn to_text(self) -> String {
        match self {
            Prefix::V4(bytes, bits) => {
                format!(
                    "{}.{}.{}.{}/{}",
                    bytes[0], bytes[1], bytes[2], bytes[3], bits
                )
            }
            Prefix::V6(bytes, bits) => format!("{}/{}", Ipv6Addr::from(bytes), bits),
        }
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_text())
    }
}

/// A prefix that could not be read, with the reason.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrefixError {
    input: String,
    reason: &'static str,
}

impl PrefixError {
    fn new(input: &str, reason: &'static str) -> Self {
        Self {
            input: input.to_owned(),
            reason,
        }
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for PrefixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "`{}`: {}", self.input, self.reason)
    }
}

impl std::error::Error for PrefixError {}

impl FromStr for Prefix {
    type Err = PrefixError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let trimmed = text.trim();
        let Some((address, bits)) = trimmed.split_once('/') else {
            return Err(PrefixError::new(
                text,
                "expected <address>/<prefix length>, for example 10.77.0.0/16",
            ));
        };
        let bits: u8 = bits
            .trim()
            .parse()
            .map_err(|_| PrefixError::new(text, "the prefix length is not a number"))?;
        match address.trim().parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) if bits <= 32 => Ok(Prefix::V4(v4.octets(), bits)),
            Ok(IpAddr::V4(_)) => Err(PrefixError::new(
                text,
                "an IPv4 prefix length is at most 32",
            )),
            Ok(IpAddr::V6(v6)) if bits <= 128 => Ok(Prefix::V6(v6.octets(), bits)),
            Ok(IpAddr::V6(_)) => Err(PrefixError::new(
                text,
                "an IPv6 prefix length is at most 128",
            )),
            Err(_) => Err(PrefixError::new(
                text,
                "the address is neither IPv4 nor IPv6",
            )),
        }
    }
}

impl Serialize for Prefix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

struct PrefixVisitor;

impl Visitor<'_> for PrefixVisitor {
    type Value = Prefix;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a CIDR band such as \"10.77.0.0/16\"")
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

/// `[route] table`: the main table, a numbered table, or no routes at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouteTableSetting {
    Unmanaged,
    Main,
    Number(u32),
}

impl RouteTableSetting {
    pub fn is_managed(self) -> bool {
        !matches!(self, RouteTableSetting::Unmanaged)
    }

    pub fn to_core(self) -> RouteTable {
        match self {
            RouteTableSetting::Unmanaged => RouteTable::Unmanaged,
            RouteTableSetting::Main => RouteTable::Main,
            RouteTableSetting::Number(number) => RouteTable::Number(number),
        }
    }

    pub fn label(self) -> String {
        match self {
            RouteTableSetting::Unmanaged => String::from("off"),
            RouteTableSetting::Main => String::from("main"),
            RouteTableSetting::Number(number) => number.to_string(),
        }
    }
}

struct RouteTableVisitor;

impl Visitor<'_> for RouteTableVisitor {
    type Value = RouteTableSetting;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one of \"main\", \"auto\", \"off\", or a routing table number")
    }

    fn visit_str<E: DeError>(self, text: &str) -> Result<Self::Value, E> {
        match text.trim().to_ascii_lowercase().as_str() {
            "main" | "auto" => Ok(RouteTableSetting::Main),
            "off" => Ok(RouteTableSetting::Unmanaged),
            other => other
                .parse::<u32>()
                .map(RouteTableSetting::Number)
                .map_err(|_| {
                    E::custom(format!(
                        "expected \"main\", \"auto\", \"off\", or a number, found \"{text}\""
                    ))
                }),
        }
    }

    fn visit_u64<E: DeError>(self, value: u64) -> Result<Self::Value, E> {
        u32::try_from(value)
            .map(RouteTableSetting::Number)
            .map_err(|_| E::custom(format!("table number {value} does not fit in 32 bits")))
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

/// `[route] prefixes`: everything, nothing, or the bands somebody chose.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RoutePrefixesSetting {
    Auto,
    None,
    Only(Vec<Prefix>),
}

impl RoutePrefixesSetting {
    pub fn to_core(&self) -> RoutePrefixes {
        match self {
            RoutePrefixesSetting::Auto => RoutePrefixes::Auto,
            RoutePrefixesSetting::None => RoutePrefixes::None,
            RoutePrefixesSetting::Only(prefixes) => {
                RoutePrefixes::Only(prefixes.iter().map(|prefix| prefix.to_core()).collect())
            }
        }
    }

    pub fn label(&self) -> String {
        match self {
            RoutePrefixesSetting::Auto => String::from("auto"),
            RoutePrefixesSetting::None => String::from("none"),
            RoutePrefixesSetting::Only(prefixes) => prefixes
                .iter()
                .map(|prefix| prefix.to_text())
                .collect::<Vec<String>>()
                .join(","),
        }
    }

    /// The bands this policy names, or nothing when it is not a list.
    pub fn listed(&self) -> &[Prefix] {
        match self {
            RoutePrefixesSetting::Only(prefixes) => prefixes,
            _ => &[],
        }
    }
}

struct RoutePrefixesVisitor;

impl<'de> Visitor<'de> for RoutePrefixesVisitor {
    type Value = RoutePrefixesSetting;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("\"auto\", \"none\", or a list of CIDR bands")
    }

    fn visit_str<E: DeError>(self, text: &str) -> Result<Self::Value, E> {
        match text.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(RoutePrefixesSetting::Auto),
            "none" => Ok(RoutePrefixesSetting::None),
            other => Err(E::custom(format!(
                "expected \"auto\", \"none\", or a list of bands, found \"{other}\""
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

/// `[route] address`: take the tunnel address from the coordinator, or leave the interface
/// alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressSetting {
    #[default]
    Auto,
    None,
}

impl AddressSetting {
    pub fn is_auto(self) -> bool {
        matches!(self, AddressSetting::Auto)
    }
}

/// `[peers] allowed_ips`: every peer on its own prefixes, or one peer on everything.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllowedIpsSetting {
    #[default]
    Peer,
    Any,
}

/// Whether the daemon owns an nftables table of its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallSetting {
    #[default]
    Off,
    Manage,
}

impl FirewallSetting {
    pub fn is_managed(self) -> bool {
        matches!(self, FirewallSetting::Manage)
    }
}

/// `[peers]`: who carries the catch-all.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PeersSection {
    pub allowed_ips: AllowedIpsSetting,
    /// The name of the one peer that also carries `0.0.0.0/0` and `::/0`.
    pub exit_peer: String,
}

impl Default for PeersSection {
    fn default() -> Self {
        Self {
            allowed_ips: AllowedIpsSetting::Peer,
            exit_peer: String::new(),
        }
    }
}

impl PeersSection {
    pub fn exit_peer(&self) -> Option<&str> {
        let name = self.exit_peer.trim();
        (!name.is_empty()).then_some(name)
    }
}

/// `[route]`: which bands reach the kernel table, and where.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteSection {
    pub table: RouteTableSetting,
    pub prefixes: RoutePrefixesSetting,
    /// `0` means "no metric was asked for".
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
    pub fn metric(&self) -> Option<u32> {
        (self.metric != 0).then_some(self.metric)
    }
}

/// `[forwarding]`: whether this device is a gateway, and who sets the host up for it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForwardingSection {
    pub enabled: bool,
    pub sysctl: bool,
    pub firewall: FirewallSetting,
}

impl Default for ForwardingSection {
    fn default() -> Self {
        Self {
            enabled: false,
            sysctl: true,
            firewall: FirewallSetting::Off,
        }
    }
}

/// The three sections the routing commands need, read from one configuration file.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingConfig {
    pub peers: PeersSection,
    pub route: RouteSection,
    pub forwarding: ForwardingSection,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RoutingConfigError {
    Io(String),
    Toml(String),
}

impl fmt::Display for RoutingConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoutingConfigError::Io(text) => write!(formatter, "{text}"),
            RoutingConfigError::Toml(text) => write!(formatter, "{text}"),
        }
    }
}

impl std::error::Error for RoutingConfigError {}

impl RoutingConfig {
    /// Read the routing sections out of a configuration file. Every field has a default, so
    /// a file that says nothing about routing is a valid one.
    pub fn load(path: &Path) -> Result<Self, RoutingConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| RoutingConfigError::Io(format!("{}: {error}", path.display())))?;
        toml::from_str(&text).map_err(|error| RoutingConfigError::Toml(error.to_string()))
    }

    pub fn parse(text: &str) -> Result<Self, RoutingConfigError> {
        toml::from_str(text).map_err(|error| RoutingConfigError::Toml(error.to_string()))
    }
}
