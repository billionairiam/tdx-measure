//! Serde data model for the parsed QEMU command.

use std::collections::BTreeMap;

use serde::Serialize;

/// A flat key-value map representing a single decoded option.
pub type Props = BTreeMap<String, String>;

/// Grouped semantic view of parsed options.
///
/// Each section stores a `BTreeMap<String, String>` (flat k=v).
/// Serialized directly to both JSON and TOML.
#[derive(Debug, Default, Serialize)]
pub struct Grouped {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<Props>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accel: Option<Props>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<Props>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<Props>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smp: Option<Props>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bios: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initrd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub append: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub nodefaults: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<Props>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub numa: Vec<Props>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<Props>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fw_cfg: Vec<Props>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub netdevs: Vec<Props>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub chardevs: Vec<Props>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub acpitables: Vec<Props>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub globals: Vec<Props>,
}
