//! OS keyring integration (REQ-39).
//! Stores the age identity key in the system keyring under service "gitvault".

use crate::error::GitvaultError;

const SERVICE: &str = "gitvault";
const USERNAME: &str = "age-identity";

pub fn keyring_set(key: &str) -> Result<(), GitvaultError> {
    keyring_set_with(key, |service, username, key| {
        let entry = keyring::Entry::new(service, username)
            .map_err(|e| GitvaultError::Keyring(e.to_string()))?;
        entry
            .set_password(key)
            .map_err(|e| GitvaultError::Keyring(e.to_string()))
    })
}

pub fn keyring_get() -> Result<String, GitvaultError> {
    keyring_get_with(|service, username| {
        let entry = keyring::Entry::new(service, username)
            .map_err(|e| GitvaultError::Keyring(e.to_string()))?;
        entry
            .get_password()
            .map_err(|e| GitvaultError::Keyring(e.to_string()))
    })
}

pub fn keyring_delete() -> Result<(), GitvaultError> {
    keyring_delete_with(|service, username| {
        let entry = keyring::Entry::new(service, username)
            .map_err(|e| GitvaultError::Keyring(e.to_string()))?;
        entry
            .delete_credential()
            .map_err(|e| GitvaultError::Keyring(e.to_string()))
    })
}

fn keyring_set_with<F>(key: &str, set_password: F) -> Result<(), GitvaultError>
where
    F: FnOnce(&str, &str, &str) -> Result<(), GitvaultError>,
{
    set_password(SERVICE, USERNAME, key)
}

fn keyring_get_with<F>(get_password: F) -> Result<String, GitvaultError>
where
    F: FnOnce(&str, &str) -> Result<String, GitvaultError>,
{
    get_password(SERVICE, USERNAME)
}

fn keyring_delete_with<F>(delete_credential: F) -> Result<(), GitvaultError>
where
    F: FnOnce(&str, &str) -> Result<(), GitvaultError>,
{
    delete_credential(SERVICE, USERNAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_set_get_delete_are_callable() {
        let key = "AGE-SECRET-KEY-TESTVALUE";

        let _ = keyring_set(key);
        let _ = keyring_get();
        let _ = keyring_delete();
    }

    #[test]
    fn keyring_set_with_passes_expected_metadata() {
        let mut captured: Option<(String, String, String)> = None;
        keyring_set_with("k", |service, username, key| {
            captured = Some((service.to_string(), username.to_string(), key.to_string()));
            Ok(())
        })
        .unwrap();

        assert_eq!(
            captured,
            Some((SERVICE.to_string(), USERNAME.to_string(), "k".to_string()))
        );
    }

    #[test]
    fn keyring_get_with_passes_expected_metadata() {
        let mut captured: Option<(String, String)> = None;
        let value = keyring_get_with(|service, username| {
            captured = Some((service.to_string(), username.to_string()));
            Ok("secret".to_string())
        })
        .unwrap();

        assert_eq!(value, "secret");
        assert_eq!(captured, Some((SERVICE.to_string(), USERNAME.to_string())));
    }

    #[test]
    fn keyring_delete_with_passes_expected_metadata() {
        let mut captured: Option<(String, String)> = None;
        keyring_delete_with(|service, username| {
            captured = Some((service.to_string(), username.to_string()));
            Ok(())
        })
        .unwrap();

        assert_eq!(captured, Some((SERVICE.to_string(), USERNAME.to_string())));
    }

    #[test]
    fn keyring_helpers_propagate_errors() {
        assert!(
            keyring_set_with("k", |_s, _u, _k| Err(GitvaultError::Keyring(
                "set failed".to_string()
            )))
            .is_err()
        );
        assert!(
            keyring_get_with(|_s, _u| Err(GitvaultError::Keyring("get failed".to_string())))
                .is_err()
        );
        assert!(
            keyring_delete_with(|_s, _u| Err(GitvaultError::Keyring("delete failed".to_string())))
                .is_err()
        );
    }
}
