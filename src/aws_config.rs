//! AWS authentication configuration for the SSM backend (REQ-49).

/// AWS authentication settings resolved from CLI flags or environment variables.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AwsConfig {
    pub profile: Option<String>,
    pub role_arn: Option<String>,
}

impl AwsConfig {
    #[allow(dead_code)]
    pub fn from_cli(profile: Option<String>, role_arn: Option<String>) -> Self {
        Self { profile, role_arn }
    }

    /// Returns true if any AWS auth has been configured.
    #[allow(dead_code)]
    pub fn is_configured(&self) -> bool {
        self.profile.is_some() || self.role_arn.is_some()
    }
}
