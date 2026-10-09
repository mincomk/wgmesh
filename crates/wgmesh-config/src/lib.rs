pub mod route;

pub use route::{
    AddressSetting, AllowedIpsSetting, FirewallSetting, ForwardingSection, PeersSection, Prefix,
    PrefixError, RoutePrefixesSetting, RouteSection, RouteTableSetting, RoutingConfig,
    RoutingConfigError,
};
