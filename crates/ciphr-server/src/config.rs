//! Server configuration.
//!
//! One TOML file, loaded strictly: an unknown key is an error rather than a silently
//! ignored line. A typo in the path of an audit device would otherwise start a
//! server that logs nowhere, which is precisely the state this project exists to
//! make impossible.
//!
//! Policies live in a **separate** file, named here. They belong in version control
//! on their own (ADR-3), they change on a different cadence from the listener
//! address, and keeping them apart means a deployment can mount the policy file
//! read-only without doing the same to everything else.
//!
//! ```toml
//! [server]
//! listen = "0.0.0.0:4400"
//!
//! [server.tls]
//! cert = "/etc/ciphr/tls/cert.pem"
//! key  = "/etc/ciphr/tls/key.pem"
//!
//! [storage]
//! backend = "sqlite"
//! path    = "/var/lib/ciphr/store.db"
//!
//! [seal]
//! type = "static_env"
//! env  = "CIPHR_MASTER_KEY"
//!
//! policies = "/etc/ciphr/policies.toml"
//!
//! [[audit]]
//! type = "sqlite"
//!
//! [[audit]]
//! type        = "file"
//! path        = "/var/log/ciphr/audit.jsonl"
//! rotate_size = "64MB"
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::ConfigError;

/// The whole configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Listener and TLS.
    pub server: ServerConfig,
    /// Where secrets are stored.
    pub storage: StorageConfig,
    /// How the root key is protected.
    pub seal: SealConfig,
    /// Path to the policy file.
    pub policies: PathBuf,
    /// Audit devices. At least one is required.
    #[serde(default, rename = "audit")]
    pub audit: Vec<AuditConfig>,
}

/// Listener and TLS settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to listen on. Port 4400 by convention (ADR-10).
    pub listen: SocketAddr,
    /// TLS material. Required: the listener terminates TLS itself (ADR-8).
    pub tls: TlsConfig,
}

/// Where the certificate and key live.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM-encoded certificate chain.
    pub cert: PathBuf,
    /// PEM-encoded private key.
    pub key: PathBuf,
}

/// Storage settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Only `sqlite` in v1 (ADR-7). Named anyway, so that a future backend is a new
    /// value here rather than a new meaning for this one.
    pub backend: StorageBackend,
    /// Path to the database file.
    pub path: PathBuf,
}

/// Which storage backend to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    /// The embedded SQLite database.
    Sqlite,
}

/// Seal settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
pub enum SealConfig {
    /// Master key from an environment variable (ADR-5).
    StaticEnv {
        /// Which variable to read.
        #[serde(default = "default_master_key_variable")]
        env: String,
    },
}

fn default_master_key_variable() -> String {
    ciphr_crypto::StaticEnvSeal::DEFAULT_VARIABLE.to_owned()
}

/// One audit device.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "snake_case")]
pub enum AuditConfig {
    /// The `audit_log` table in the same database as the secrets.
    Sqlite,
    /// A JSON Lines file.
    File {
        /// Where to write.
        path: PathBuf,
        /// Size at which to rotate, as a human-readable size such as `64MB`.
        ///
        /// Absent means the file grows without bound, which is a decision an operator
        /// can make but not one this software makes for them.
        #[serde(default)]
        rotate_size: Option<String>,
    },
}

impl Config {
    /// Load and validate a configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be read, is not valid TOML, has an
    /// unknown key, or configures no audit device.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let config: Self = toml::from_str(&text).map_err(|source| ConfigError::Syntax {
            path: path.display().to_string(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Parse from a string, for tests and for `--check-config`.
    ///
    /// # Errors
    ///
    /// As [`Config::load`], minus the read error.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|source| ConfigError::Syntax {
            path: "<inline>".to_owned(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // The server refuses to start without an audit device. A secret store with no
        // audit trail is a configuration error in this project, not an operating mode
        // — so this is checked here rather than being left to fail later at the first
        // request, when a client is already waiting.
        if self.audit.is_empty() {
            return Err(ConfigError::NoAuditDevice);
        }
        for device in &self.audit {
            if let AuditConfig::File {
                rotate_size: Some(size),
                ..
            } = device
            {
                parse_size(size)?;
            }
        }
        Ok(())
    }

    /// The rotation size of the file device, in bytes, if one is configured.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Size`] if the value cannot be parsed. Validated at load
    /// time, so this is unreachable for a loaded config.
    pub fn file_rotate_bytes(&self) -> Result<Option<u64>, ConfigError> {
        for device in &self.audit {
            if let AuditConfig::File { rotate_size, .. } = device {
                return rotate_size.as_deref().map(parse_size).transpose();
            }
        }
        Ok(None)
    }
}

/// Parse a size such as `64MB`, `512KB`, `2GB`, or a plain byte count.
///
/// Powers of 1024, because that is what a disk quota and a container memory limit
/// mean by the same words. Documented rather than assumed, since the difference
/// between 64 MB and 64 MiB is exactly the sort of detail that makes a rotation
/// threshold miss.
fn parse_size(input: &str) -> Result<u64, ConfigError> {
    let text = input.trim();
    let (digits, multiplier) = if let Some(rest) = text.strip_suffix("GB") {
        (rest, 1024 * 1024 * 1024)
    } else if let Some(rest) = text.strip_suffix("MB") {
        (rest, 1024 * 1024)
    } else if let Some(rest) = text.strip_suffix("KB") {
        (rest, 1024)
    } else {
        (text, 1)
    };

    digits
        .trim()
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_mul(multiplier))
        .filter(|bytes| *bytes > 0)
        .ok_or_else(|| ConfigError::Size {
            found: input.to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::{AuditConfig, Config, SealConfig, StorageBackend, parse_size};
    use crate::error::ConfigError;

    const COMPLETE: &str = r#"
policies = "/etc/ciphr/policies.toml"

[server]
listen = "0.0.0.0:4400"

[server.tls]
cert = "/etc/ciphr/tls/cert.pem"
key  = "/etc/ciphr/tls/key.pem"

[storage]
backend = "sqlite"
path    = "/var/lib/ciphr/store.db"

[seal]
type = "static_env"

[[audit]]
type = "sqlite"

[[audit]]
type        = "file"
path        = "/var/log/ciphr/audit.jsonl"
rotate_size = "64MB"
"#;

    #[test]
    fn loads_the_documented_example() {
        let config = Config::parse(COMPLETE).expect("the example must load");

        assert_eq!(config.server.listen.port(), 4400);
        assert_eq!(config.storage.backend, StorageBackend::Sqlite);
        assert!(config.policies.ends_with("policies.toml"));
        assert_eq!(config.audit.len(), 2);
        assert_eq!(config.file_rotate_bytes().unwrap(), Some(64 * 1024 * 1024));

        // The seal defaults to the documented variable rather than requiring it to be
        // spelled out in every deployment.
        let SealConfig::StaticEnv { env } = &config.seal;
        assert_eq!(env, "CIPHR_MASTER_KEY");
    }

    #[test]
    fn refuses_a_configuration_with_no_audit_device() {
        let text = COMPLETE
            .split("[[audit]]")
            .next()
            .expect("there is a prefix");
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::NoAuditDevice)
        ));
    }

    #[test]
    fn refuses_an_unknown_key() {
        let text = COMPLETE.replace("listen = ", "listen_on = ");
        assert!(matches!(
            Config::parse(&text),
            Err(ConfigError::Syntax { .. })
        ));

        let extra = format!("{COMPLETE}\nunexpected = true\n");
        assert!(matches!(
            Config::parse(&extra),
            Err(ConfigError::Syntax { .. })
        ));
    }

    #[test]
    fn tls_is_not_optional() {
        // ADR-8: the listener terminates TLS itself. A configuration that omits it
        // must fail rather than quietly serving plaintext secrets over a shared
        // network.
        let text = COMPLETE.replace("[server.tls]", "[server.unused]");
        assert!(matches!(
            Config::parse(&text),
            Err(ConfigError::Syntax { .. })
        ));
    }

    #[test]
    fn a_file_device_without_rotation_is_allowed() {
        let text = COMPLETE.replace("rotate_size = \"64MB\"", "");
        let config = Config::parse(&text).expect("rotation is optional");
        assert_eq!(config.file_rotate_bytes().unwrap(), None);
        assert!(matches!(config.audit[1], AuditConfig::File { .. }));
    }

    #[test]
    fn sizes_use_powers_of_1024_and_reject_nonsense() {
        assert_eq!(parse_size("1").unwrap(), 1);
        assert_eq!(parse_size("2KB").unwrap(), 2048);
        assert_eq!(parse_size("64MB").unwrap(), 67_108_864);
        assert_eq!(parse_size("1GB").unwrap(), 1_073_741_824);
        assert_eq!(parse_size(" 8MB ").unwrap(), 8 * 1024 * 1024);

        for bad in [
            "",
            "0",
            "-1",
            "64 megabytes",
            "MB",
            "1.5MB",
            "99999999999GB",
        ] {
            assert!(parse_size(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn an_invalid_rotation_size_fails_at_load_rather_than_at_rotation() {
        let text = COMPLETE.replace("\"64MB\"", "\"sixty-four\"");
        assert!(matches!(
            Config::parse(&text),
            Err(ConfigError::Size { .. })
        ));
    }
}
