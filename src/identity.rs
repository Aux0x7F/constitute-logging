use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoggingServiceIdentity {
    pub service_pk: String,
    pub service_sk_hex: String,
}

impl LoggingServiceIdentity {
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("service-identity.json");
        if let Some(identity) = read_identity(&path)? {
            return Ok(identity);
        }

        fs::create_dir_all(data_dir)
            .with_context(|| format!("create logging data dir {}", data_dir.display()))?;
        let (service_pk, service_sk_hex) = constitute_protocol::generate_keypair();
        let identity = Self {
            service_pk,
            service_sk_hex,
        };
        write_identity(&path, &identity)?;
        Ok(identity)
    }
}

fn read_identity(path: &Path) -> Result<Option<LoggingServiceIdentity>> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    let mut identity: LoggingServiceIdentity =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    identity.service_pk = identity.service_pk.trim().to_string();
    identity.service_sk_hex = identity.service_sk_hex.trim().to_string();
    if identity.service_pk.is_empty() && !identity.service_sk_hex.is_empty() {
        identity.service_pk = constitute_protocol::pubkey_from_sk_hex(&identity.service_sk_hex)
            .context("derive logging service public key")?;
        write_identity(path, &identity)?;
    }
    if identity.service_pk.is_empty() || identity.service_sk_hex.is_empty() {
        anyhow::bail!("logging service identity is incomplete");
    }
    Ok(Some(identity))
}

fn write_identity(path: &Path, identity: &LoggingServiceIdentity) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create logging identity dir {}", parent.display()))?;
    }
    let tmp = tmp_path(path);
    let bytes =
        serde_json::to_vec_pretty(identity).context("serialize logging service identity")?;
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("move {} into place", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    tmp.set_extension("json.tmp");
    tmp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logging_identity_is_stable_after_create() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = LoggingServiceIdentity::load_or_create(dir.path()).expect("create");
        let second = LoggingServiceIdentity::load_or_create(dir.path()).expect("load");
        assert_eq!(first.service_pk, second.service_pk);
        assert_eq!(first.service_sk_hex, second.service_sk_hex);
        assert_eq!(first.service_pk.len(), 64);
    }
}
