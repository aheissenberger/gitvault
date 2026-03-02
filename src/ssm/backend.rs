//! [`SsmBackend`] trait and production [`RealSsmBackend`] implementation.

use aws_sdk_ssm::types::ParameterType;

use crate::error::GitvaultError;

/// Abstraction over AWS SSM Parameter Store operations.
///
/// [`RealSsmBackend`] wraps `aws_sdk_ssm::Client`; in tests the
/// mockall-generated [`MockSsmBackend`] is injected so every command path can
/// be exercised without live AWS credentials.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait SsmBackend: Send + Sync {
    /// Fetch all parameters whose name starts with `prefix`.
    ///
    /// Returns `(name, value)` pairs with the full SSM parameter path as name.
    async fn fetch_params(&self, prefix: &str) -> Result<Vec<(String, String)>, GitvaultError>;

    /// Write `value` to the SSM parameter at `path` as a `SecureString`.
    async fn put_param(&self, path: &str, value: &str) -> Result<(), GitvaultError>;
}

/// Production [`SsmBackend`] backed by a live `aws_sdk_ssm::Client`.
pub struct RealSsmBackend(pub aws_sdk_ssm::Client);

#[async_trait::async_trait]
impl SsmBackend for RealSsmBackend {
    async fn fetch_params(&self, prefix: &str) -> Result<Vec<(String, String)>, GitvaultError> {
        let mut results = Vec::new();
        let mut next_token: Option<String> = None;

        loop {
            let mut req = self
                .0
                .get_parameters_by_path()
                .path(prefix)
                .recursive(true)
                .with_decryption(true);

            if let Some(ref tok) = next_token {
                req = req.next_token(tok);
            }

            let resp = req
                .send()
                .await
                .map_err(|e| GitvaultError::Other(e.to_string()))?;

            for param in resp.parameters() {
                if let (Some(name), Some(value)) = (param.name(), param.value()) {
                    results.push((name.to_string(), value.to_string()));
                }
            }

            next_token = resp.next_token().map(str::to_string);
            if next_token.is_none() {
                break;
            }
        }

        Ok(results)
    }

    async fn put_param(&self, path: &str, value: &str) -> Result<(), GitvaultError> {
        self.0
            .put_parameter()
            .name(path)
            .value(value)
            .r#type(ParameterType::SecureString)
            .overwrite(true)
            .send()
            .await
            .map_err(|e| GitvaultError::Other(e.to_string()))?;
        Ok(())
    }
}
