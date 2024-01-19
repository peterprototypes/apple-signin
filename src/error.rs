use std::error::Error;
use std::fmt;

use jsonwebtoken::errors::Error as JwtError;
use reqwest::Error as ReqwestError;

/// A network, validation or decoding error
#[non_exhaustive]
#[derive(Debug)]
pub enum AppleJwtError {
    /// The JWK id in the provided identity token has no counterpart in <https://appleid.apple.com/auth/keys>
    MissingJwk(String),
    /// The JWK header is missing the key id field (kid)
    MissingKeyId,
    /// Error from the [jsonwebtoken] crate
    JwtError(JwtError),
    /// Error from the [reqwest] crate. Can occur when fetching keys from <https://appleid.apple.com/auth/keys>
    HttpError(ReqwestError),
}

impl Error for AppleJwtError {}

impl fmt::Display for AppleJwtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingJwk(kid) => {
                write!(
                    f,
                    "JSON Web Key id '{}' missing in {}",
                    kid,
                    crate::KEYS_URL
                )
            }
            Self::MissingKeyId => {
                f.write_str("Identity token header is missing key id (kid) field")
            }
            Self::JwtError(e) => e.fmt(f),
            Self::HttpError(e) => e.fmt(f),
        }
    }
}

impl From<JwtError> for AppleJwtError {
    fn from(value: JwtError) -> Self {
        Self::JwtError(value)
    }
}

impl From<ReqwestError> for AppleJwtError {
    fn from(value: ReqwestError) -> Self {
        Self::HttpError(value)
    }
}
