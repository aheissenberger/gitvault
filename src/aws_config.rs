//! AWS authentication configuration for the SSM backend (REQ-49).

/// AWS authentication settings resolved from CLI flags or environment variables.
#[derive(Debug, Clone)]
pub struct AwsConfig {
    pub profile: Option<String>,
    pub role_arn: Option<String>,
}

impl AwsConfig {
    /// Construct an [`AwsConfig`] from CLI-supplied flags.
    pub const fn from_cli(profile: Option<String>, role_arn: Option<String>) -> Self {
        Self { profile, role_arn }
    }

    /// Returns true if any AWS auth has been configured.
    pub const fn is_configured(&self) -> bool {
        self.profile.is_some() || self.role_arn.is_some()
    }

    /// Build an SSM client using the configured profile and/or role ARN.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::GitvaultError::Other`] if the AWS SDK fails to
    /// create a client or the optional role assumption fails.
    #[cfg(feature = "ssm")]
    pub async fn build_client(&self) -> Result<aws_sdk_ssm::Client, crate::error::GitvaultError> {
        use aws_config::sts::AssumeRoleProvider;

        let mut loader = aws_config::from_env();
        if let Some(p) = &self.profile {
            loader = loader.profile_name(p.as_str());
        }
        let base = loader.load().await;

        let sdk_config = if let Some(arn) = &self.role_arn {
            let provider = AssumeRoleProvider::builder(arn.as_str())
                .session_name("gitvault")
                .configure(&base)
                .build()
                .await;
            aws_config::from_env()
                .credentials_provider(provider)
                .load()
                .await
        } else {
            base
        };

        Ok(aws_sdk_ssm::Client::new(&sdk_config))
    }
}

#[cfg(test)]
mod tests {
    use super::AwsConfig;

    #[cfg(feature = "ssm")]
    #[tokio::test]
    async fn build_client_without_role_returns_ok() {
        let cfg = AwsConfig::from_cli(None, None);
        // build_client creates an SDK client from env — no API call is made here.
        let result = cfg.build_client().await;
        assert!(result.is_ok());
    }

    #[cfg(feature = "ssm")]
    #[tokio::test]
    async fn build_client_with_profile_returns_ok() {
        let cfg = AwsConfig::from_cli(Some("nonexistent-test-profile".to_string()), None);
        // SDK client creation succeeds even with a nonexistent profile name;
        // the error (if any) only surfaces on actual API calls.
        let result = cfg.build_client().await;
        assert!(result.is_ok());
    }

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
