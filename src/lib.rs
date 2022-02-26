use jsonwebtoken::{Algorithm, Validation};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::keys::{GoogleKeyProviderError, GooglePublicKeyProvider};

mod keys;

#[cfg(any(test, feature = "test-helper"))]
pub mod test_helper;


///
/// Parser errors
///
#[derive(Error, Debug)]
pub enum ParserError {
    #[error("Wrong header.")]
    WrongHeader,
    #[error("Unknown kid.")]
    UnknownKid,
    #[error("Download public key error - {0}.")]
    KeyProvider(GoogleKeyProviderError),
    #[error("Wrong token format - {0}.")]
    WrongToken(jsonwebtoken::errors::Error),
}

///
/// Parse & Validate Google JWT token.
/// Use public key from http(s) server.
///
pub struct Parser {
    client_id: String,
    key_provider: tokio::sync::Mutex<GooglePublicKeyProvider>,
}

impl Parser {
    pub const GOOGLE_CERT_URL: &'static str = "https://www.googleapis.com/oauth2/v3/certs";

    pub fn new(client_id: &str) -> Self {
        Parser::new_with_custom_cert_url(client_id, Parser::GOOGLE_CERT_URL)
    }

    pub fn new_with_custom_cert_url(client_id: &str, public_key_url: &str) -> Self {
        Self {
            client_id: client_id.to_owned(),
            key_provider: tokio::sync::Mutex::new(GooglePublicKeyProvider::new(public_key_url)),
        }
    }

    ///
    /// Parse and validate token.
    /// Download and cache public keys from http(s) server.
    /// Use expire time header for reload keys.
    ///
    pub async fn parse<T: DeserializeOwned>(&self, token: &str) -> Result<T, ParserError> {
        let mut provider = self.key_provider.lock().await;
        match jsonwebtoken::decode_header(token) {
            Ok(header) => match header.kid {
                None => Result::Err(ParserError::UnknownKid),
                Some(kid) => match provider.get_key(kid.as_str()).await {
                    Ok(key) => {
                        let aud = vec![self.client_id.to_owned()];
                        let mut validation = Validation::new(Algorithm::RS256);
                        validation.set_audience(&aud);
                        validation.set_issuer(&["https://accounts.google.com".to_string(), "accounts.google.com".to_string()]);
                        validation.validate_exp = true;
                        validation.validate_nbf = false;
                        let result = jsonwebtoken::decode::<T>(token, &key, &validation);
                        match result {
                            Result::Ok(token_data) => Result::Ok(token_data.claims),
                            Result::Err(error) => Result::Err(ParserError::WrongToken(error)),
                        }
                    }
                    Err(e) => {
                        let error = ParserError::KeyProvider(e);
                        Result::Err(error)
                    }
                },
            },
            Err(_) => Result::Err(ParserError::WrongHeader),
        }
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::errors::ErrorKind;

    use crate::ParserError;
    use crate::test_helper::{setup, TokenClaims};

    #[tokio::test]
    async fn should_correct() {
        let claims = TokenClaims::new();
        let (token, parser, _server) = setup(&claims);
        let result = parser.parse::<TokenClaims>(token.as_str()).await;
        let result = result.unwrap();
        assert_eq!(result.email, claims.email);
    }

    #[tokio::test]
    async fn should_validate_exp() {
        let claims = TokenClaims::new_expired();
        let (token, validator, _server) = setup(&claims);
        let result = validator.parse::<TokenClaims>(token.as_str()).await;

        assert!(
            if let ParserError::WrongToken(error) = result.err().unwrap() {
                if let ErrorKind::ExpiredSignature = error.into_kind() {
                    true
                } else {
                    false
                }
            } else {
                false
            }
        );
    }

    #[tokio::test]
    async fn should_validate_iss() {
        let mut claims = TokenClaims::new();
        claims.iss = "https://some.com".to_owned();
        let (token, validator, _server) = setup(&claims);
        let result = validator.parse::<TokenClaims>(token.as_str()).await;
        assert!(
            if let ParserError::WrongToken(error) = result.err().unwrap() {
                if let ErrorKind::InvalidIssuer = error.into_kind() {
                    true
                } else {
                    false
                }
            } else {
                false
            }
        );
    }

    #[tokio::test]
    async fn should_validate_aud() {
        let mut claims = TokenClaims::new();
        claims.aud = "other-id".to_owned();
        let (token, validator, _server) = setup(&claims);
        let result = validator.parse::<TokenClaims>(token.as_str()).await;
        assert!(
            if let ParserError::WrongToken(error) = result.err().unwrap() {
                if let ErrorKind::InvalidAudience = error.into_kind() {
                    true
                } else {
                    false
                }
            } else {
                false
            }
        );
    }
}
