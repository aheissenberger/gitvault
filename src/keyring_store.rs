//! OS keyring integration (REQ-39).
//! Stores the age identity key in the system keyring under service "gitvault".

const SERVICE: &str = "gitvault";
const USERNAME: &str = "age-identity";

pub fn keyring_set(key: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE, USERNAME).map_err(|e| e.to_string())?;
    entry.set_password(key).map_err(|e| e.to_string())
}

pub fn keyring_get() -> Result<String, String> {
    let entry = keyring::Entry::new(SERVICE, USERNAME).map_err(|e| e.to_string())?;
    entry.get_password().map_err(|e| e.to_string())
}

pub fn keyring_delete() -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE, USERNAME).map_err(|e| e.to_string())?;
    entry.delete_credential().map_err(|e| e.to_string())
}
