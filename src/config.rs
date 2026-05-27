use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_mysql_port")]
    pub mysql_port: u16,

    #[serde(default = "default_webui_port")]
    pub webui_port: u16,

    #[serde(default = "default_bind")]
    pub bind: String,

    #[serde(default = "default_data_dir")]
    pub data_dir: String,

    #[serde(default)]
    pub tls: TlsConfig,

    #[serde(default)]
    pub auth: AuthConfig,

    #[serde(default)]
    pub xdp: XdpConfig,

    #[serde(default = "default_fw_manage")]
    pub firewall_manage:  bool,
    #[serde(default)]
    pub firewall_backend: Option<String>,
    #[serde(default = "default_fw_tag")]
    pub firewall_tag:     String,
    #[serde(default = "default_icmp_protection")]
    pub icmp_protection: bool,

    #[serde(default = "default_connection_timeout_secs")]
    pub connection_timeout_secs: u64,

    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,

    #[serde(default = "default_checkpoint_interval_secs")]
    pub checkpoint_interval_secs: u64,
    #[serde(default)]
    pub numa_pin: bool,
    #[serde(default)]
    pub worker_threads: usize,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert: Option<String>,
    pub key: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_root_password")]
    pub root_password: String,
    #[serde(default = "default_webui_key")]
    pub webui_api_key: String,
    #[serde(default = "default_webui_admin_user")]
    pub webui_admin_user: String,
    #[serde(default = "default_webui_admin_password")]
    pub webui_admin_password: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            root_password: default_root_password(),
            webui_api_key: default_webui_key(),
            webui_admin_user: default_webui_admin_user(),
            webui_admin_password: default_webui_admin_password(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct XdpConfig {
    pub enabled: bool,
    pub interface: Option<String>,
    pub max_conn_per_sec: Option<u32>,
}

fn default_mysql_port() -> u16 { 3306 }
fn default_webui_port() -> u16 { 8306 }
fn default_bind() -> String { "0.0.0.0".into() }
fn default_data_dir() -> String { "/var/lib/runalexdb".into() }
fn default_root_password() -> String { "changeme".into() }
fn default_webui_admin_user() -> String { "admin".into() }
fn default_webui_admin_password() -> String { "admin".into() }
fn default_webui_key() -> String { "changeme".into() }
fn default_fw_manage() -> bool { true }
fn default_fw_tag() -> String { "runalexdb".into() }

impl Config {
    pub fn load() -> Result<Self> {
        let path = std::env::args()
            .skip(1)
            .find(|a| a.ends_with(".toml"))
            .unwrap_or_else(|| "/etc/runalexdb/runalexdb.toml".into());

        if std::path::Path::new(&path).exists() {
            let s = std::fs::read_to_string(&path)
                .with_context(|| format!("reading config {path}"))?;
            Ok(toml::from_str(&s)?)
        } else {
            Ok(Self::default())
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mysql_port: default_mysql_port(),
            webui_port: default_webui_port(),
            bind: default_bind(),
            data_dir: default_data_dir(),
            tls: TlsConfig::default(),
            auth: AuthConfig::default(),
            xdp:             XdpConfig::default(),
            firewall_manage:  default_fw_manage(),
            firewall_backend: None,
            firewall_tag:     default_fw_tag(),
            icmp_protection: default_icmp_protection(),
            connection_timeout_secs: default_connection_timeout_secs(),
            handshake_timeout_secs: default_handshake_timeout_secs(),
            checkpoint_interval_secs: default_checkpoint_interval_secs(),
            numa_pin: false,
            worker_threads: 0,
        }
    }
}

fn default_icmp_protection() -> bool { true }
fn default_checkpoint_interval_secs() -> u64 { 300 }
fn default_connection_timeout_secs() -> u64 { 300 }
fn default_handshake_timeout_secs() -> u64 { 10 }
