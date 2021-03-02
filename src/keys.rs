use std::collections::HashMap;

use std::time::Instant;

use headers::Header;
use jsonwebtoken::DecodingKey;
use reqwest::header::{HeaderMap, CACHE_CONTROL};

use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct GoogleKeys {
    keys: Vec<GoogleKey>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct GoogleKey {
    alg: jsonwebtoken::Algorithm,
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug)]
pub enum GoogleKeyProviderError {
    KeyNotFound,
    FetchError(String),
    ParseError(String),
}

#[derive(Debug)]
pub struct GooglePublicKeyProvider {
    url: String,
    keys: HashMap<String, GoogleKey>,
    expiration_time: Option<Instant>,
}

impl GooglePublicKeyProvider {
    pub fn new(public_key_url: &str) -> Self {
        Self {
            url: public_key_url.to_owned(),
            keys: Default::default(),
            expiration_time: None,
        }
    }

    pub async fn reload(&mut self) -> Result<(), GoogleKeyProviderError> {
        match reqwest::get(&self.url).await {
            Ok(r) => {
                let expiration_time = GooglePublicKeyProvider::parse_expiration_time(&r.headers());
                match r.json::<GoogleKeys>().await {
                    Ok(google_keys) => {
                        self.keys.clear();
                        for key in google_keys.keys.into_iter() {
                            self.keys.insert(key.kid.clone(), key);
                        }
                        self.expiration_time = expiration_time;
                        Result::Ok(())
                    }
                    Err(e) => Result::Err(GoogleKeyProviderError::ParseError(format!("{:?}", e))),
                }
            }
            Err(e) => Result::Err(GoogleKeyProviderError::FetchError(format!("{:?}", e))),
        }
    }

    fn parse_expiration_time(header_map: &HeaderMap) -> Option<Instant> {
        match headers::CacheControl::decode(&mut header_map.get_all(CACHE_CONTROL).iter()) {
            Ok(header) => match header.max_age() {
                None => None,
                Some(max_age) => Some(Instant::now() + max_age),
            },
            Err(_) => None,
        }
    }

    pub fn is_expire(&self) -> bool {
        if let Some(expire) = self.expiration_time {
            Instant::now() > expire
        } else {
            false
        }
    }

    pub async fn get_key(
        &mut self,
        kid: &str,
    ) -> Result<DecodingKey<'static>, GoogleKeyProviderError> {
        if self.expiration_time.is_none() || self.is_expire() {
            self.reload().await?
        }
        match self.keys.get(&kid.to_owned()) {
            None => Result::Err(GoogleKeyProviderError::KeyNotFound),
            Some(key) => {
                let key = DecodingKey::from_rsa_components(key.n.as_str(), key.e.as_str());
                Result::Ok(key.into_static())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use httpmock::MockServer;
    use jsonwebtoken::DecodingKey;

    use crate::keys::{GoogleKeyProviderError, GooglePublicKeyProvider};

    #[tokio::test]
    async fn should_parse_keys() {
        let n = "3g46w4uRYBx8CXFauWh6c5yO4ax_VDu5y8ml_Jd4Gx711155PTdtLeRuwZOhJ6nRy8YvLFPXc_aXtHifnQsi9YuI_vo7LGG2v3CCxh6ndZBjIeFkxErMDg4ELt2DQ0PgJUQUAKCkl2_gkVV9vh3oxahv_BpIgv1kuYlyQQi5JWeF7zAIm0FaZ-LJT27NbsCugcZIDQg9sztTN18L3-P_kYwvAkKY2bGYNU19qLFM1gZkzccFEDZv3LzAz7qbdWkwCoK00TUUH8TNjqmK67bytYzgEgkfF9q9szEQ5TrRL0uFg9LxT3kSTLYqYOVaUIX3uaChwaa-bQvHuNmryu7i9w";
        let e = "AQAB";
        let kid = "some-kid";
        let resp = format!("{{\"keys\": [{{\"kty\": \"RSA\",\"use\": \"sig\",\"e\": \"{}\",\"n\": \"{}\",\"alg\": \"RS256\",\"kid\": \"{}\"}}]}}", e, n, kid);

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
        let original = DecodingKey::from_rsa_components(n, e);
        let mut provider = GooglePublicKeyProvider::new(server.url("/").as_str());
        assert!(matches!(provider.get_key(kid).await, Result::Ok(result) if result==original));
        assert!(matches!(
            provider.get_key("missing-key").await,
            Result::Err(_)
        ));
    }

    #[tokio::test]
    async fn should_expire_and_reload() {
        let server = MockServer::start();
        let n = "3g46w4uRYBx8CXFauWh6c5yO4ax_VDu5y8ml_Jd4Gx711155PTdtLeRuwZOhJ6nRy8YvLFPXc_aXtHifnQsi9YuI_vo7LGG2v3CCxh6ndZBjIeFkxErMDg4ELt2DQ0PgJUQUAKCkl2_gkVV9vh3oxahv_BpIgv1kuYlyQQi5JWeF7zAIm0FaZ-LJT27NbsCugcZIDQg9sztTN18L3-P_kYwvAkKY2bGYNU19qLFM1gZkzccFEDZv3LzAz7qbdWkwCoK00TUUH8TNjqmK67bytYzgEgkfF9q9szEQ5TrRL0uFg9LxT3kSTLYqYOVaUIX3uaChwaa-bQvHuNmryu7i9w";
        let e = "AQAB";
        let kid = "some-kid";
        let resp = format!("{{\"keys\": [{{\"kty\": \"RSA\",\"use\": \"sig\",\"e\": \"{}\",\"n\": \"{}\",\"alg\": \"RS256\",\"kid\": \"{}\"}}]}}", e, n, kid);

        let mut server_mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/");
            then.status(200)
                .header(
                    "cache-control",
                    "public, max-age=3, must-revalidate, no-transform",
                )
                .header("Content-Type", "application/json; charset=UTF-8")
                .body("{\"keys\":[]}");
        });

        let mut provider = GooglePublicKeyProvider::new(server.url("/").as_str());
        let key_result = provider.get_key(kid).await;
        assert!(matches!(
            key_result,
            Result::Err(GoogleKeyProviderError::KeyNotFound)
        ));

        server_mock.delete();
        let _server_mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/");
            then.status(200)
                .header(
                    "cache-control",
                    "public, max-age=3, must-revalidate, no-transform",
                )
                .header("Content-Type", "application/json; charset=UTF-8")
                .body(resp);
        });

        std::thread::sleep(Duration::from_secs(4));
        let key_result = provider.get_key(kid).await;
        assert!(matches!(key_result, Result::Ok(_)));
    }
}
