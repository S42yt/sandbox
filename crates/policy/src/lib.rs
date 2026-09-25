use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("cannot serialize configuration: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, PolicyError>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    pub name: String,
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub devices: DeviceConfig,
    #[serde(default)]
    pub resources: ResourceConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilesystemMode {
    #[default]
    Isolated,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemConfig {
    #[serde(default)]
    pub mode: FilesystemMode,
    #[serde(default, rename = "share", skip_serializing_if = "Vec::is_empty")]
    pub shares: Vec<Share>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    pub host: PathBuf,
    pub path: PathBuf,
    #[serde(default = "yes")]
    pub readonly: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    None,
    Internet,
    Lan,
    Host,
    Full,
}

impl FromStr for NetworkMode {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "none" => Ok(Self::None),
            "internet" => Ok(Self::Internet),
            "lan" => Ok(Self::Lan),
            "host" => Ok(Self::Host),
            "full" => Ok(Self::Full),
            other => Err(PolicyError::Invalid(format!(
                "unknown network mode `{other}` (expected none, internet, lan, host or full)"
            ))),
        }
    }
}

impl fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Internet => "internet",
            Self::Lan => "lan",
            Self::Host => "host",
            Self::Full => "full",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<NetworkMode>,
    #[serde(default)]
    pub internet: bool,
    #[serde(default)]
    pub lan: bool,
    #[serde(default)]
    pub host: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub isolated: bool,
    pub internet: bool,
    pub lan: bool,
    pub host: bool,
}

impl NetworkPolicy {
    pub fn needs_uplink(&self) -> bool {
        self.isolated && (self.internet || self.lan || self.host)
    }
}

impl NetworkConfig {
    pub fn from_mode(mode: NetworkMode) -> Self {
        let (internet, lan, host) = match mode {
            NetworkMode::None => (false, false, false),
            NetworkMode::Internet => (true, false, false),
            NetworkMode::Lan => (true, true, false),
            NetworkMode::Host | NetworkMode::Full => (true, true, true),
        };
        Self {
            mode: (mode == NetworkMode::Full).then_some(mode),
            internet,
            lan,
            host,
        }
    }

    pub fn policy(&self) -> Result<NetworkPolicy> {
        let (isolated, internet, lan, host) = match self.mode {
            Some(NetworkMode::None) => (true, false, false, false),
            Some(NetworkMode::Internet) => (true, true, false, false),
            Some(NetworkMode::Lan) => (true, true, true, false),
            Some(NetworkMode::Host) => (true, true, true, true),
            Some(NetworkMode::Full) => (false, true, true, true),
            None => (true, self.internet, self.lan, self.host),
        };
        if isolated && (lan || host) && !internet {
            return Err(PolicyError::Invalid(
                "network: `lan` or `host` access without `internet` is not supported yet".into(),
            ));
        }
        Ok(NetworkPolicy {
            isolated,
            internet,
            lan,
            host,
        })
    }

    pub fn describe(&self) -> String {
        match self.policy() {
            Ok(p) if !p.isolated => "full (host network namespace)".into(),
            Ok(p) => {
                let mut parts = Vec::new();
                if p.internet {
                    parts.push("internet");
                }
                if p.lan {
                    parts.push("lan");
                }
                if p.host {
                    parts.push("host");
                }
                if parts.is_empty() {
                    "none".into()
                } else {
                    parts.join("+")
                }
            }
            Err(e) => e.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceConfig {
    #[serde(default)]
    pub gpu: bool,
    #[serde(default)]
    pub audio: bool,
    #[serde(default)]
    pub microphone: bool,
    #[serde(default)]
    pub camera: bool,
    #[serde(default)]
    pub usb: bool,
    #[serde(default)]
    pub bluetooth: bool,
    #[serde(default)]
    pub controllers: bool,
    #[serde(default)]
    pub display: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<ByteSize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<f64>,
    #[serde(default = "default_processes")]
    pub processes: u64,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            memory: None,
            cpus: None,
            processes: default_processes(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilitySet {
    None,
    #[default]
    Default,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default)]
    pub capabilities: CapabilitySet,
    #[serde(default)]
    pub nested_namespaces: bool,
    #[serde(default = "default_uid_base")]
    pub uid_base: u32,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            capabilities: CapabilitySet::Default,
            nested_namespaces: false,
            uid_base: default_uid_base(),
        }
    }
}

fn default_uid_base() -> u32 {
    100_000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSize(pub u64);

impl FromStr for ByteSize {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self> {
        let t = s.trim();
        let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
        let (num, unit) = t.split_at(split);
        let n: u64 = num
            .parse()
            .map_err(|_| PolicyError::Invalid(format!("invalid size `{s}`")))?;
        let mult: u64 = match unit.trim().to_ascii_uppercase().as_str() {
            "" | "B" => 1,
            "K" | "KB" | "KIB" => 1 << 10,
            "M" | "MB" | "MIB" => 1 << 20,
            "G" | "GB" | "GIB" => 1 << 30,
            "T" | "TB" | "TIB" => 1 << 40,
            _ => return Err(PolicyError::Invalid(format!("invalid size unit in `{s}`"))),
        };
        n.checked_mul(mult)
            .map(ByteSize)
            .ok_or_else(|| PolicyError::Invalid(format!("size `{s}` is too large")))
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNITS: [(&str, u64); 4] = [("T", 1 << 40), ("G", 1 << 30), ("M", 1 << 20), ("K", 1 << 10)];
        for (u, m) in UNITS {
            if self.0 >= m && self.0.is_multiple_of(m) {
                return write!(f, "{}{u}", self.0 / m);
            }
        }
        write!(f, "{}", self.0)
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u64),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Num(n) => Ok(ByteSize(n)),
            Raw::Str(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }
}

fn yes() -> bool {
    true
}

fn default_processes() -> u64 {
    4096
}

pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
    if ok {
        Ok(())
    } else {
        Err(PolicyError::Invalid(format!(
            "invalid name `{name}`: use 1-63 characters from [A-Za-z0-9._-], starting with a letter or digit"
        )))
    }
}

pub fn normalize_sandbox_path(p: &Path) -> Result<PathBuf> {
    if !p.is_absolute() {
        return Err(PolicyError::Invalid(format!(
            "sandbox path `{}` must be absolute",
            p.display()
        )));
    }
    let mut out = PathBuf::from("/");
    for c in p.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(s) => out.push(s),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(PolicyError::Invalid(format!(
                    "sandbox path `{}` must not contain `..`",
                    p.display()
                )))
            }
        }
    }
    Ok(out)
}

impl SandboxConfig {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            filesystem: FilesystemConfig::default(),
            network: NetworkConfig::default(),
            devices: DeviceConfig::default(),
            resources: ResourceConfig::default(),
            security: SecurityConfig::default(),
            env: BTreeMap::new(),
        }
    }

    pub fn from_toml(s: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn to_toml(&self) -> Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn validate(&self) -> Result<()> {
        validate_name(&self.name)?;
        self.network.policy()?;
        if let Some(c) = self.resources.cpus {
            if !(c > 0.0 && c.is_finite()) {
                return Err(PolicyError::Invalid(
                    "resources.cpus must be a positive number".into(),
                ));
            }
        }
        if let Some(m) = self.resources.memory {
            if m.0 < (16 << 20) {
                return Err(PolicyError::Invalid(
                    "resources.memory must be at least 16M".into(),
                ));
            }
        }
        if self.security.uid_base != 0
            && (self.security.uid_base < 1000 || self.security.uid_base > u32::MAX - 65536)
        {
            return Err(PolicyError::Invalid(
                "security.uid_base must be 0 (identity) or between 1000 and 4294901759".into(),
            ));
        }
        if self.resources.processes == 0 {
            return Err(PolicyError::Invalid(
                "resources.processes must be at least 1".into(),
            ));
        }
        for share in &self.filesystem.shares {
            if !share.host.is_absolute() {
                return Err(PolicyError::Invalid(format!(
                    "share host path `{}` must be absolute",
                    share.host.display()
                )));
            }
            let p = normalize_sandbox_path(&share.path)?;
            if p == Path::new("/") || RESERVED.iter().any(|r| p.starts_with(r)) {
                return Err(PolicyError::Invalid(format!(
                    "share target `{}` overlaps a system directory",
                    share.path.display()
                )));
            }
        }
        for k in self.env.keys() {
            if k.is_empty() || k.contains('=') || k.contains('\0') {
                return Err(PolicyError::Invalid(format!(
                    "invalid environment variable name `{k}`"
                )));
            }
        }
        if self.env.values().any(|v| v.contains('\0')) {
            return Err(PolicyError::Invalid(
                "environment values must not contain NUL".into(),
            ));
        }
        Ok(())
    }
}

pub fn set_value(text: &str, key: &str, value: &str) -> Result<String> {
    let mut table: toml::Table = toml::from_str(text)?;
    let parts: Vec<&str> = key.split('.').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(PolicyError::Invalid(format!("invalid key `{key}`")));
    }
    if parts[0] == "name" {
        return Err(PolicyError::Invalid(
            "the name of a sandbox cannot be changed".into(),
        ));
    }
    let mut cur = &mut table;
    for p in &parts[..parts.len() - 1] {
        cur = cur
            .entry(*p)
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or_else(|| PolicyError::Invalid(format!("`{p}` in `{key}` is not a table")))?;
    }
    cur.insert(parts[parts.len() - 1].to_string(), parse_value(value));
    let out = toml::to_string_pretty(&table)?;
    SandboxConfig::from_toml(&out)?;
    Ok(out)
}

fn parse_value(s: &str) -> toml::Value {
    match s {
        "true" => return toml::Value::Boolean(true),
        "false" => return toml::Value::Boolean(false),
        _ => {}
    }
    if let Ok(i) = s.parse::<i64>() {
        return toml::Value::Integer(i);
    }
    if let Ok(f) = s.parse::<f64>() {
        return toml::Value::Float(f);
    }
    if s.starts_with('[') || s.starts_with('"') || s.starts_with('{') {
        if let Ok(t) = toml::from_str::<toml::Table>(&format!("v = {s}")) {
            if let Some(v) = t.get("v") {
                return v.clone();
            }
        }
    }
    toml::Value::String(s.to_string())
}

const RESERVED: &[&str] = &[
    "/proc", "/sys", "/dev", "/usr", "/etc", "/bin", "/sbin", "/lib", "/lib64", "/run",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spec_example() {
        let cfg = SandboxConfig::from_toml(
            r#"
name = "test"

[filesystem]
mode = "isolated"

[network]
internet = true
lan = false
host = false

[devices]
gpu = true
audio = true
microphone = false
camera = false
usb = false

[resources]
memory = "8G"
cpus = 8
"#,
        )
        .unwrap();
        assert_eq!(cfg.resources.memory, Some(ByteSize(8 << 30)));
        assert_eq!(cfg.resources.cpus, Some(8.0));
        let p = cfg.network.policy().unwrap();
        assert!(p.isolated && p.internet && !p.lan && !p.host);
        assert!(cfg.devices.gpu && !cfg.devices.camera);
    }

    #[test]
    fn roundtrips() {
        let mut cfg = SandboxConfig::new("rt");
        cfg.resources.memory = Some(ByteSize(512 << 20));
        cfg.network = NetworkConfig::from_mode(NetworkMode::Lan);
        cfg.filesystem.shares.push(Share {
            host: "/srv/data".into(),
            path: "/data".into(),
            readonly: true,
        });
        let back = SandboxConfig::from_toml(&cfg.to_toml().unwrap()).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn defaults_are_closed() {
        let cfg = SandboxConfig::from_toml("name = \"x\"").unwrap();
        let p = cfg.network.policy().unwrap();
        assert!(p.isolated && !p.internet && !p.lan && !p.host && !p.needs_uplink());
        assert_eq!(cfg.devices, DeviceConfig::default());
        assert!(!cfg.security.nested_namespaces);
    }

    #[test]
    fn modes() {
        let full = NetworkConfig::from_mode(NetworkMode::Full).policy().unwrap();
        assert!(!full.isolated);
        let host = NetworkConfig::from_mode(NetworkMode::Host).policy().unwrap();
        assert!(host.isolated && host.host && host.lan);
        let lan_only = NetworkConfig {
            lan: true,
            ..Default::default()
        };
        assert!(lan_only.policy().is_err());
    }

    #[test]
    fn sizes() {
        assert_eq!("512M".parse::<ByteSize>().unwrap().0, 512 << 20);
        assert_eq!("1gib".parse::<ByteSize>().unwrap().0, 1 << 30);
        assert_eq!("4096".parse::<ByteSize>().unwrap().0, 4096);
        assert!("12Q".parse::<ByteSize>().is_err());
        assert!("G".parse::<ByteSize>().is_err());
        assert_eq!(ByteSize(3 << 30).to_string(), "3G");
    }

    #[test]
    fn names() {
        assert!(validate_name("malware-test_1.0").is_ok());
        for bad in ["", ".", "..", "-x", "a/b", "a b", &"x".repeat(64)] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn share_paths() {
        assert_eq!(
            normalize_sandbox_path(Path::new("/a/./b/")).unwrap(),
            PathBuf::from("/a/b")
        );
        assert!(normalize_sandbox_path(Path::new("/a/../etc")).is_err());
        assert!(normalize_sandbox_path(Path::new("rel")).is_err());
        let mut cfg = SandboxConfig::new("s");
        cfg.filesystem.shares.push(Share {
            host: "/tmp".into(),
            path: "/etc/x".into(),
            readonly: true,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn set_value_edits_and_validates() {
        let base = SandboxConfig::new("s").to_toml().unwrap();
        let t = set_value(&base, "network.mode", "lan").unwrap();
        let cfg = SandboxConfig::from_toml(&t).unwrap();
        assert_eq!(cfg.network.mode, Some(NetworkMode::Lan));
        let t = set_value(&t, "resources.memory", "8G").unwrap();
        let t = set_value(&t, "resources.cpus", "2").unwrap();
        let t = set_value(&t, "devices.gpu", "true").unwrap();
        let t = set_value(&t, "env.FOO", "bar baz").unwrap();
        let cfg = SandboxConfig::from_toml(&t).unwrap();
        assert_eq!(cfg.resources.memory, Some(ByteSize(8 << 30)));
        assert_eq!(cfg.resources.cpus, Some(2.0));
        assert!(cfg.devices.gpu);
        assert_eq!(cfg.env["FOO"], "bar baz");
        assert!(set_value(&t, "network.mode", "wifi").is_err());
        assert!(set_value(&t, "network.bogus", "1").is_err());
        assert!(set_value(&t, "name", "other").is_err());
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(SandboxConfig::from_toml("name = \"x\"\n[network]\ninternett = true").is_err());
    }
}
