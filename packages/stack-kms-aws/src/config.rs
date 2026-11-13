//! The region and endpoint of an AWS KMS client.

use crate::credentials::{process_env, EnvLookup};

/// The configuration is not usable.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// No region was given, and neither `AWS_REGION` nor
    /// `AWS_DEFAULT_REGION` is set.
    #[error("no AWS region: set AWS_REGION or give one in the config")]
    NoRegion,
    /// The region is not a region name.
    #[error("{0:?} is not an AWS region name")]
    InvalidRegion(String),
    /// The endpoint is not an absolute HTTP or HTTPS URL.
    #[error("{0:?} is not an HTTP or HTTPS endpoint URL")]
    InvalidEndpoint(String),
}

/// The DNS suffix of the AWS partition of `region`.
pub(crate) fn dns_suffix(region: &str) -> &'static str {
    if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    }
}

/// The region and endpoint of an [`AwsKms`](crate::AwsKms) client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AwsKmsConfig {
    region: String,
    endpoint: String,
}

impl AwsKmsConfig {
    /// The AWS KMS endpoint of `region` (`https://kms.<region>.amazonaws.com/`).
    pub fn new(region: impl Into<String>) -> Result<Self, ConfigError> {
        let region = region.into();
        let valid = !region.is_empty()
            && region.len() <= 64
            && region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !valid {
            return Err(ConfigError::InvalidRegion(region));
        }
        let endpoint = format!("https://kms.{region}.{}/", dns_suffix(&region));
        Ok(Self { region, endpoint })
    }

    /// The region from `AWS_REGION`, else `AWS_DEFAULT_REGION`, and the
    /// endpoint from `AWS_ENDPOINT_URL_KMS`, else `AWS_ENDPOINT_URL`, else
    /// the region's.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_env_lookup(&process_env())
    }

    /// As [`from_env`](Self::from_env), reading the variables with `env`.
    pub fn from_env_lookup(env: &EnvLookup) -> Result<Self, ConfigError> {
        let region = env("AWS_REGION")
            .or_else(|| env("AWS_DEFAULT_REGION"))
            .ok_or(ConfigError::NoRegion)?;
        let config = Self::new(region)?;
        match env("AWS_ENDPOINT_URL_KMS").or_else(|| env("AWS_ENDPOINT_URL")) {
            Some(endpoint) => config.with_endpoint(endpoint),
            None => Ok(config),
        }
    }

    /// Send to `endpoint` instead of the region's AWS KMS endpoint: a VPC
    /// endpoint, a FIPS endpoint, or a local emulator such as LocalStack
    /// (`http://localhost:4566`). Requests are still signed for the region.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Result<Self, ConfigError> {
        let endpoint = endpoint.into();
        let parsed = url::Url::parse(&endpoint)
            .map_err(|_| ConfigError::InvalidEndpoint(endpoint.clone()))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
            return Err(ConfigError::InvalidEndpoint(endpoint));
        }
        self.endpoint = parsed.to_string();
        Ok(self)
    }

    /// The region.
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> EnvLookup {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Arc::new(move |name| map.get(name).cloned())
    }

    #[test]
    fn the_endpoint_follows_the_region_and_partition() {
        let config = AwsKmsConfig::new("ap-southeast-2").unwrap();
        assert_eq!(config.region(), "ap-southeast-2");
        assert_eq!(
            config.endpoint(),
            "https://kms.ap-southeast-2.amazonaws.com/"
        );
        assert_eq!(
            AwsKmsConfig::new("cn-north-1").unwrap().endpoint(),
            "https://kms.cn-north-1.amazonaws.com.cn/"
        );
        for bad in ["", "US-EAST-1", "us east 1", "us-east-1.evil.com/"] {
            assert_eq!(
                AwsKmsConfig::new(bad),
                Err(ConfigError::InvalidRegion(bad.to_owned()))
            );
        }
    }

    #[test]
    fn the_region_and_endpoint_come_from_the_environment() {
        assert_eq!(
            AwsKmsConfig::from_env_lookup(&env(&[])),
            Err(ConfigError::NoRegion)
        );
        let config =
            AwsKmsConfig::from_env_lookup(&env(&[("AWS_DEFAULT_REGION", "eu-west-1")])).unwrap();
        assert_eq!(config.region(), "eu-west-1");
        let config = AwsKmsConfig::from_env_lookup(&env(&[
            ("AWS_REGION", "us-west-2"),
            ("AWS_DEFAULT_REGION", "eu-west-1"),
            ("AWS_ENDPOINT_URL", "http://localhost:4566"),
        ]))
        .unwrap();
        assert_eq!(config.region(), "us-west-2");
        assert_eq!(config.endpoint(), "http://localhost:4566/");
        let config = AwsKmsConfig::from_env_lookup(&env(&[
            ("AWS_REGION", "us-west-2"),
            ("AWS_ENDPOINT_URL", "http://localhost:4566"),
            ("AWS_ENDPOINT_URL_KMS", "http://localhost:4567"),
        ]))
        .unwrap();
        assert_eq!(config.endpoint(), "http://localhost:4567/");
    }

    #[test]
    fn an_endpoint_must_be_http_or_https() {
        let config = AwsKmsConfig::new("us-east-1").unwrap();
        for bad in ["localhost:4566", "ftp://localhost/", "not a url"] {
            assert_eq!(
                config.clone().with_endpoint(bad),
                Err(ConfigError::InvalidEndpoint(bad.to_owned()))
            );
        }
    }
}
