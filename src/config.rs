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
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            root_password: default_root_password(),
            webui_api_key: default_webui_key(),
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
fn default_webui_key() -> String { "changeme".into() }

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
            xdp: XdpConfig::default(),
        }
    }
}
