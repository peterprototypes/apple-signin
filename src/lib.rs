//! # Apple Sign-In
//!
//! This crate provides an API to verify and decode Apple's identity JWT. The token is typically generated via
//! [ASAuthorizationController](https://developer.apple.com/documentation/authenticationservices/asauthorizationcontroller)
//! from the [AuthenticationServices](https://developer.apple.com/documentation/authenticationservices) iOS framework.
//!
//! This crate validates the `identityToken` instance property present in the
//! [ASAuthorizationAppleIDCredential](https://developer.apple.com/documentation/authenticationservices/asauthorizationappleidcredential) class.
//!
//! Currently this crate doesn't support fetching and validating identity tokens via the `authorizationCode` provided in
//! [ASAuthorizationAppleIDCredential](https://developer.apple.com/documentation/authenticationservices/asauthorizationappleidcredential)
//!
//! To implement Sign In with Apple:
//! - You have to have a valid, paid Apple developer account.
//! - Generate an identifier in <https://developer.apple.com/account/resources/identifiers/list> (eg. `com.example.myapp`)
//! - Make sure `Sign In with Apple` Capability is enabled on that identifier.
//! - Configure your app in Xcode to use that identifier as bundle identifier.
//! - Enable the `Sign In with Apple` Capability in Xcode as well.
//! - An `identityToken` generated with the `AuthenticationServices` framework can be sent to a backend server for validation.
//! - Use this crate to validate and decode the token.
//!
//! Apple will only provide the email field (and name if requested) the first time you test Sign In with Apple in the simulator with your account.
//! Subsequent authorization requests on iOS will only yeld the [user id](JwtPayload::user_id) field.
//!
//! To get the email field again:
//! 1. Go to Settings, then tap your name.
//! 1. Tap Sign-In & Security, then tap Sign in with Apple.
//! 1. Select the app or developer, then tap Stop Using Apple ID.
//! 1. You may need to restart the simulator or device
//!
//! ## Usage
//! Create a new client and configure it with your app bundle id(s).
//!
//! ```
//! use apple_signin::AppleJwtClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let mut client = AppleJwtClient::new(&["com.example.myapp"]);
//!     let payload = client.decode("[IDENTITY TOKEN]").await?;
//!
//!     dbg!(payload);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Caching
//!
//! It is recommended to keep the client instance around and not create a new one on every validation request.
//! The client will fetch and cache JWT keys provided by Apple from <https://appleid.apple.com/auth/keys>.
//! Only if the cached keys stop working will the client try to fetch new ones.
//!
mod error;
use std::fmt;

pub use error::AppleJwtError;

use jsonwebtoken::{errors::ErrorKind, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

const KEYS_URL: &str = "https://appleid.apple.com/auth/keys";

/// Indicates whether the user appears to be a real person.
/// Apple recommends using this to mitigate fraud.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum RealUserStatus {
    Unsupported = 0,
    Unknown = 1,
    LikelyReal = 2,
}

/// Contains the extracted information from a valid JWT
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwtPayload {
    /// App bundle id
    #[serde(rename = "aud")]
    pub audience: String,
    pub auth_time: Option<u64>,
    pub c_hash: Option<String>,
    /// A string value that represents the user’s email address.
    /// The email address is either the user’s real email address or the proxy address,
    /// depending on their private email relay service. This value may be empty for
    /// Sign in with Apple at Work & School users. For example, younger students may
    /// not have an email address.
    pub email: Option<String>,
    /// Indicates whether Apple verifies the email.
    /// The system may not verify email addresses for Sign in with Apple at Work & School users
    #[serde(deserialize_with = "deserialize_bool", default)]
    pub email_verified: Option<bool>,
    /// Indicates whether the email that the user shares is the proxy address.
    #[serde(deserialize_with = "deserialize_bool", default)]
    pub is_private_email: Option<bool>,
    /// The time that the identity token expires, in number of seconds since the Unix epoch in UTC.
    /// Validated that the value is greater than the current date
    #[serde(rename = "exp")]
    pub expiration_time: Option<u64>,
    /// The time that Apple issued the identity token, in number of seconds since the Unix epoch in UTC.
    #[serde(rename = "iat")]
    pub issued_at: u64,
    /// Token issuer, the value is validated to be `https://appleid.apple.com`.
    #[serde(rename = "iss")]
    pub issuer: String,
    /// Indicates whether the user appears to be a real person.
    /// This field is present only in iOS 14 and later, macOS 11 and later, watchOS 7 and later, tvOS 14 and later. The claim isn’t present or supported for web-based apps.
    pub real_user_status: Option<RealUserStatus>,
    /// Unique identifier for the user:
    /// - A unique, stable string, serves as the primary identifier of the user
    /// - Uses the same identifier across all of the apps in the development team associated with an Apple Developer account
    /// - Differs for the same user across different development teams, and can’t identify a user across development teams
    /// - Doesn’t change if the user stops using Sign in with Apple with an app and later starts using it again
    /// - Typically stores alongside the user’s primary key in a database
    #[serde(rename = "sub")]
    pub user_id: String,

    /// The user's name, if requested.
    pub name: Option<AppleName>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppleName {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AppleJwtClient {
    keyset_cache: Option<JwkSet>,
    validation: Validation,
}

impl AppleJwtClient {
    pub fn new<T: ToString>(app_bundle_ids: &[T]) -> Self {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(app_bundle_ids);
        validation.set_issuer(&["https://appleid.apple.com"]);
        validation.set_required_spec_claims(&["exp", "sub", "iss", "aud"]);

        Self {
            keyset_cache: None,
            validation,
        }
    }

    /// Validate and decode Apple identity JWT
    pub async fn decode(&mut self, identity_token: &str) -> Result<JwtPayload, AppleJwtError> {
        let header = jsonwebtoken::decode_header(identity_token)?;

        let Some(key_id) = header.kid else {
            return Err(AppleJwtError::MissingKeyId);
        };

        let mut res;

        loop {
            let (just_loaded, keyset) = self.take_cached_keyset().await?;

            res = Self::try_decode(&key_id, &keyset, identity_token, &self.validation);

            let is_keyset_error = match res {
                Err(ref e) => match e {
                    AppleJwtError::MissingJwk(_) => true,
                    AppleJwtError::JwtError(e) => matches!(
                        e.kind(),
                        ErrorKind::InvalidEcdsaKey
                            | ErrorKind::InvalidRsaKey(_)
                            | ErrorKind::InvalidAlgorithmName
                            | ErrorKind::InvalidKeyFormat
                    ),
                    _ => false,
                },
                _ => false,
            };

            if just_loaded || res.is_ok() || !is_keyset_error {
                self.keyset_cache = Some(keyset);

                break;
            }
        }

        res
    }

    fn try_decode(
        kid: &str,
        keyset: &JwkSet,
        token: &str,
        validation: &Validation,
    ) -> Result<JwtPayload, AppleJwtError> {
        let Some(jwk) = keyset.find(kid) else {
            return Err(AppleJwtError::MissingJwk(kid.to_string()));
        };

        let key = DecodingKey::from_jwk(jwk)?;

        let token = jsonwebtoken::decode::<JwtPayload>(token, &key, validation)?;

        Ok(token.claims)
    }

    async fn take_cached_keyset(&mut self) -> Result<(bool, JwkSet), AppleJwtError> {
        if let Some(keyset) = self.keyset_cache.take() {
            return Ok((false, keyset));
        }

        let keyset = reqwest::get(KEYS_URL).await?.json::<JwkSet>().await?;

        Ok((true, keyset))
    }
}

fn deserialize_bool<'de, D: Deserializer<'de>>(data: D) -> Result<Option<bool>, D::Error> {
    data.deserialize_option(AppleOptionalBool)
}

struct AppleOptionalBool;

impl<'de> Visitor<'de> for AppleOptionalBool {
    type Value = Option<bool>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("null or a string (\"true\" or \"false\") or a bool (true or false)")
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(None)
    }

    fn visit_some<D>(self, d: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Some(d.deserialize_any(AppleBool)?))
    }
}

struct AppleBool;

impl<'de> Visitor<'de> for AppleBool {
    type Value = bool;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string (\"true\" or \"false\") or a bool (true or false)")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v)
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v == "true")
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v == "true")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(v == "true")
    }
}
