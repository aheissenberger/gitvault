use crate::error::GitvaultError;
use std::io::Write;
use std::path::Path;

pub(super) const AGE_ARMOR_HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
/// Prefix used for single-line encrypted values in .env value-only mode.
pub(super) const ENV_ENC_PREFIX: &str = "age:";

pub fn is_age_armor(value: &str) -> bool {
    value.trim_start().starts_with(AGE_ARMOR_HEADER)
}

pub(super) fn is_env_encrypted(value: &str) -> bool {
    value.starts_with(ENV_ENC_PREFIX)
}

/// Write bytes to file atomically using a temp file + rename.
pub(super) fn atomic_write(path: &Path, data: &[u8]) -> Result<(), GitvaultError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(data)?;
    tmp.persist(path).map_err(|e| GitvaultError::Io(e.error))?;
    Ok(())
}
