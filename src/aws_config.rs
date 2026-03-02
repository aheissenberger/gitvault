//! AWS authentication configuration for the SSM backend (REQ-49).
#![allow(dead_code)]

/// AWS authentication settings resolved from CLI flags or environment variables.
#[derive(Debug, Clone)]
pub struct AwsConfig {
    pub profile: Option<String>,
    pub role_arn: Option<String>,
}

impl AwsConfig {
    pub fn from_cli(profile: Option<String>, role_arn: Option<String>) -> Self {
        Self { profile, role_arn }
    }

    /// Returns true if any AWS auth has been configured.
    pub fn is_configured(&self) -> bool {
        self.profile.is_some() || self.role_arn.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::AwsConfig;

    #[test]
    fn from_cli_keeps_values() {
        let cfg = AwsConfig::from_cli(
            Some("dev-profile".to_string()),
            Some("arn:aws:iam::123456789012:role/demo".to_string()),
        );

        assert_eq!(cfg.profile.as_deref(), Some("dev-profile"));
        assert_eq!(
            cfg.role_arn.as_deref(),
            Some("arn:aws:iam::123456789012:role/demo")
        );
    }

    #[test]
    fn is_configured_false_when_empty() {
        let cfg = AwsConfig::from_cli(None, None);
        assert!(!cfg.is_configured());
    }

    #[test]
    fn is_configured_true_when_profile_or_role_set() {
        let by_profile = AwsConfig::from_cli(Some("dev".to_string()), None);
        let by_role = AwsConfig::from_cli(None, Some("arn:aws:iam::1:role/x".to_string()));

        assert!(by_profile.is_configured());
        assert!(by_role.is_configured());
    }
}
