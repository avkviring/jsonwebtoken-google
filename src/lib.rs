use std::collections::HashSet;



use jsonwebtoken::{Algorithm, Validation};
use serde::de::DeserializeOwned;


use crate::keys::{GoogleKeyProvider, GoogleKeyProviderError};

pub mod keys;

#[derive(Debug)]
pub enum ValidateError {
    None,
    WrongHeader,
    UnknownKid,
    KeyProvider(GoogleKeyProviderError),
    WrongToken(jsonwebtoken::errors::Error),
}

pub struct Validator {
    key_provider: tokio::sync::Mutex<GoogleKeyProvider>,
}

impl Validator {
    pub async fn new() -> Self {
        Self {
            key_provider: tokio::sync::Mutex::new(GoogleKeyProvider::new()),
        }
    }

    #[cfg(test)]
    pub async fn stub(url: &str) -> Self {
        Self {
            key_provider: tokio::sync::Mutex::new(GoogleKeyProvider::stub(url)),
        }
    }

    pub async fn validate<T: DeserializeOwned>(
        &self,
        client_id: &str,
        token: &str,
    ) -> Result<T, ValidateError> {
        let mut provider = self.key_provider.lock().await;
        match jsonwebtoken::decode_header(token) {
            Ok(header) => match header.kid {
                None => Result::Err(ValidateError::UnknownKid),
                Some(kid) => match provider.get_key(kid.as_str()).await {
                    Ok(key) => {
                        let mut aud = HashSet::default();
                        aud.insert(client_id.to_owned());
                        let validation = Validation {
                            leeway: 0,
                            validate_exp: true,
                            validate_nbf: false,
                            aud: Option::Some(aud),
                            iss: Option::Some("https://accounts.google.com".to_owned()),
                            sub: None,
                            algorithms: vec![Algorithm::RS256],
                        };
                        let result = jsonwebtoken::decode::<T>(token, &key, &validation);
                        match result {
                            Result::Ok(token_data) => Result::Ok(token_data.claims),
                            Result::Err(error) => Result::Err(ValidateError::WrongToken(error)),
                        }
                    }
                    Err(e) => {
                        let error = ValidateError::KeyProvider(e);
                        Result::Err(error)
                    }
                },
            },
            Err(_) => Result::Err(ValidateError::WrongHeader),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::{Add, Sub};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use httpmock::MockServer;
    use jsonwebtoken::errors::ErrorKind;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use openssl::rsa::Rsa;
    
    use rand::thread_rng;
    use serde::{Deserialize, Serialize};

    
    use crate::{ValidateError, Validator};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct TokenClaims {
        pub email: String,
        pub aud: String,
        pub iss: String,
        pub exp: u64,
    }

    const KID: &str = "some-kid";
    const CLIENT_ID: &str = "some-client-id";
    const EMAIL: &str = "alex@kviring.com";

    #[tokio::test]
    async fn should_correct() {
        let claims = TokenClaims {
            email: EMAIL.to_owned(),
            aud: CLIENT_ID.to_owned(),
            exp: SystemTime::now()
                .add(Duration::from_secs(10))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            iss: "https://accounts.google.com".to_owned(),
        };
        let (token, validator, _server) = setup(&claims).await;
        let result = validator
            .validate::<TokenClaims>(CLIENT_ID, token.as_str())
            .await;
        let result = result.unwrap();
        assert_eq!(result.email, claims.email);
    }

    #[tokio::test]
    async fn should_validate_exp() {
        let claims = TokenClaims {
            email: EMAIL.to_owned(),
            aud: CLIENT_ID.to_owned(),
            exp: SystemTime::now()
                .sub(Duration::from_secs(1))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            iss: "https://accounts.google.com".to_owned(),
        };
        let (token, validator, _server) = setup(&claims).await;
        let result = validator
            .validate::<TokenClaims>(CLIENT_ID, token.as_str())
            .await;
        assert!(
            if let ValidateError::WrongToken(error) = result.err().unwrap() {
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
        let claims = TokenClaims {
            email: EMAIL.to_owned(),
            aud: CLIENT_ID.to_owned(),
            exp: SystemTime::now()
                .add(Duration::from_secs(10))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            iss: "https://some.com".to_owned(),
        };
        let (token, validator, _server) = setup(&claims).await;
        let result = validator
            .validate::<TokenClaims>(CLIENT_ID, token.as_str())
            .await;
        assert!(
            if let ValidateError::WrongToken(error) = result.err().unwrap() {
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
        let claims = TokenClaims {
            email: EMAIL.to_owned(),
            aud: "other-id".to_owned(),
            exp: SystemTime::now()
                .add(Duration::from_secs(10))
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            iss: "https://accounts.google.com".to_owned(),
        };
        let (token, validator, _server) = setup(&claims).await;
        let result = validator
            .validate::<TokenClaims>(CLIENT_ID, token.as_str())
            .await;
        assert!(
            if let ValidateError::WrongToken(error) = result.err().unwrap() {
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

    async fn setup(claims: &TokenClaims) -> (String, Validator, MockServer) {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_owned());
        header.typ = Some("JWT".to_owned());
        let _rng = thread_rng();
        let bits = 2048;
        let private_key = Rsa::generate(bits).unwrap();
        let der = private_key.private_key_to_der().unwrap();
        let key = EncodingKey::from_rsa_der(&der);
        let token = jsonwebtoken::encode::<TokenClaims>(&header, &claims, &key).unwrap();
        let n = base64::encode_config(private_key.n().to_vec(), base64::URL_SAFE_NO_PAD);
        let e = base64::encode_config(private_key.e().to_vec(), base64::URL_SAFE_NO_PAD);
        let resp = format!("{{\"keys\": [{{\"kty\": \"RSA\",\"use\": \"sig\",\"e\": \"{}\",\"n\": \"{}\",\"alg\": \"RS256\",\"kid\": \"{}\"}}]}}", e, n, KID);

        let server = MockServer::start();
        let _server_mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/");

            then.status(200)
                .header(
                    "cache-control",
                    "public, max-age=24920, must-revalidate, no-transform",
                )
                .header("Content-Type", "application/json; charset=UTF-8")
                .body(resp);
        });

        (
            token,
            Validator::stub(server.url("/").as_str()).await,
            server,
        )
    }
}
