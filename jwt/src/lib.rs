#![doc(
    issue_tracker_base_url = "https://github.com/mycelial/snowflake-rs/issues",
    test(no_crate_inject)
)]
#![doc = include_str ! ("../README.md")]

use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

#[cfg(not(any(feature = "rust_crypto", feature = "aws_lc_rs")))]
compile_error!(
    "snowflake-jwt needs a crypto backend: enable either the `rust_crypto` feature \
     (the default, pure Rust) or the `aws_lc_rs` feature."
);

/// Makes sure `jsonwebtoken` has a crypto provider to sign with.
///
/// `jsonwebtoken` infers the process-wide provider from its own crate features, but only when
/// exactly one backend is enabled. Cargo features are additive, so a dependency graph that pulls
/// this crate in twice with different backends selected ends up with both enabled, and the
/// inference then panics on first use. Install one explicitly to keep that build working.
///
/// `aws_lc_rs` wins the tie: `rust_crypto` is the default feature, so a build with both enabled is
/// one where somebody asked for `aws_lc_rs` on top of the default.
#[cfg(all(feature = "rust_crypto", feature = "aws_lc_rs"))]
fn install_crypto_provider() {
    // An error means a provider was already installed; the application's own choice wins.
    let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
}

/// No-op: with a single backend enabled `jsonwebtoken` works out the provider by itself.
#[cfg(not(all(feature = "rust_crypto", feature = "aws_lc_rs")))]
fn install_crypto_provider() {}

#[derive(Error, Debug)]
pub enum JwtError {
    #[error(transparent)]
    Rsa(#[from] rsa::Error),

    #[error(transparent)]
    Pkcs8(#[from] rsa::pkcs8::Error),

    #[error(transparent)]
    Spki(#[from] rsa::pkcs8::spki::Error),

    #[error(transparent)]
    Pkcs1(#[from] rsa::pkcs1::Error),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    Der(#[from] rsa::pkcs1::der::Error),

    #[error(transparent)]
    JwtEncoding(#[from] jsonwebtoken::errors::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    #[serde(with = "jwt_numeric_date")]
    iat: OffsetDateTime,
    #[serde(with = "jwt_numeric_date")]
    exp: OffsetDateTime,
}

impl Claims {
    /// If a token should always be equal to its representation after serializing and deserializing
    /// again, this function must be used for construction. `OffsetDateTime` contains a microsecond
    /// field but JWT timestamps are defined as UNIX timestamps (seconds). This function normalizes
    /// the timestamps.
    pub fn new(iss: String, sub: String, iat: OffsetDateTime, exp: OffsetDateTime) -> Self {
        // normalize the timestamps by stripping of microseconds
        let iat = iat
            .date()
            .with_hms_milli(iat.hour(), iat.minute(), iat.second(), 0)
            .unwrap()
            .assume_utc();
        let exp = exp
            .date()
            .with_hms_milli(exp.hour(), exp.minute(), exp.second(), 0)
            .unwrap()
            .assume_utc();

        Self { iss, sub, iat, exp }
    }
}

mod jwt_numeric_date {
    //! Custom serialization of OffsetDateTime to conform with the JWT spec (RFC 7519 section 2, "Numeric Date")
    use serde::{self, Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    /// Serializes an OffsetDateTime to a Unix timestamp (milliseconds since 1970/1/1T00:00:00T)
    pub fn serialize<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let timestamp = date.unix_timestamp();
        serializer.serialize_i64(timestamp)
    }

    /// Attempts to deserialize an i64 and use as a Unix timestamp
    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        OffsetDateTime::from_unix_timestamp(i64::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid Unix timestamp value"))
    }
}

fn pubkey_fingerprint(pubkey: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);

    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// Strip cloud/region segments from an `<account>.<...>.<user>` identifier.
///
/// Snowflake's JWT `iss` / `sub` claims require the account-identifier portion
/// to be either the bare account-locator (e.g. `PF52218`) or the
/// `<orgname>-<accountname>` form — never the regionful name
/// (`PF52218.WEST-US-2.AZURE.<USER>`). When the URL the SDK targets uses the
/// regionful host (`<locator>.<region>.<cloud>.snowflakecomputing.com`), the
/// caller must still pass the regionful account here so the URL stays correct,
/// but the JWT claims must drop everything between the first segment and the
/// final user segment.
///
/// Rules:
/// - 2 segments (`<account>.<user>` or `<org>-<account>.<user>`) → unchanged.
/// - 3+ segments → keep first (account-locator) and last (user), drop middle
///   (`<region>` or `<region>.<cloud>`).
fn strip_region_from_identifier(full_identifier: &str) -> String {
    let segments: Vec<&str> = full_identifier.split('.').collect();
    if segments.len() <= 2 {
        full_identifier.to_owned()
    } else {
        format!("{}.{}", segments[0], segments[segments.len() - 1])
    }
}

pub fn generate_jwt_token(
    private_key_pem: &str,
    // Snowflake expects uppercase <account identifier>.<username>
    full_identifier: &str,
) -> Result<String, JwtError> {
    // Reading a private key:
    // rsa-2048.p8 -> public key -> der bytes -> hash
    let pkey = rsa::RsaPrivateKey::from_pkcs8_pem(private_key_pem)?;
    let pubk = pkey.to_public_key().to_public_key_der()?;

    // Snowflake's JWT iss/sub take the account-locator-only form even when the
    // SDK addresses the regionful URL host; strip cloud/region segments here so
    // legacy account-locator deployments (e.g. `pf52218.west-us-2.azure`) get
    // an iss that Snowflake accepts.
    let claim_identifier = strip_region_from_identifier(full_identifier);

    let iss = format!(
        "{}.SHA256:{}",
        claim_identifier,
        pubkey_fingerprint(pubk.as_bytes())
    );

    let iat = OffsetDateTime::now_utc();
    let exp = iat + Duration::days(1);

    install_crypto_provider();

    let claims = Claims::new(iss, claim_identifier, iat, exp);
    let ek = EncodingKey::from_rsa_der(pkey.to_pkcs1_der()?.as_bytes());

    let res = encode(&Header::new(Algorithm::RS256), &claims, &ek)?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::strip_region_from_identifier;

    #[test]
    fn two_segments_unchanged() {
        assert_eq!(
            strip_region_from_identifier("ACCOUNT.USER"),
            "ACCOUNT.USER"
        );
    }

    #[test]
    fn org_account_form_unchanged() {
        assert_eq!(
            strip_region_from_identifier("MYORG-MYACCT.USER"),
            "MYORG-MYACCT.USER"
        );
    }

    #[test]
    fn three_segments_region_dropped() {
        assert_eq!(
            strip_region_from_identifier("PF52218.WEST-US-2.USER"),
            "PF52218.USER"
        );
    }

    #[test]
    fn four_segments_region_and_cloud_dropped() {
        assert_eq!(
            strip_region_from_identifier("PF52218.WEST-US-2.AZURE.USER"),
            "PF52218.USER"
        );
    }
}
