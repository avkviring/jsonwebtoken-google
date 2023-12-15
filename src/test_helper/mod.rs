use std::ops::Add;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use httpmock::MockServer;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rand::thread_rng;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};

use crate::Parser;

pub const KID: &str = "some-kid";
pub const CLIENT_ID: &str = "some-client-id";
pub const EMAIL: &str = "alex@kviring.com";
pub const SUB: &str = "11112222333344445555";

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub email: String,
    pub aud: String,
    pub iss: String,
    pub sub: String,
    pub exp: u64,
}

impl TokenClaims {
    pub fn new() -> Self {
        TokenClaims::new_with_expire(Duration::from_secs(10))
    }

    pub fn new_with_expire(expire: Duration) -> Self {
        Self {
            email: EMAIL.to_owned(),
            aud: CLIENT_ID.to_owned(),
            exp: SystemTime::now()
                .add(expire)
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            iss: "https://accounts.google.com".to_owned(),
            sub: SUB.to_owned(),
        }
    }

    pub fn new_expired() -> Self {
        let mut result = TokenClaims::new();
        result.exp = 0;
        result
    }
}

impl Default for TokenClaims {
    fn default() -> Self {
        Self::new()
    }
}

pub fn setup(claims: &TokenClaims) -> (String, Parser, MockServer) {
    let (token, server) = setup_public_key_server(claims);
    (
        token,
        Parser::new_with_custom_cert_url(CLIENT_ID, server.url("/").as_str()),
        server,
    )
}

pub fn setup_public_key_server(claims: &TokenClaims) -> (String, MockServer) {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    header.typ = Some("JWT".to_owned());
    let bits = 2048;
    let private_key =
        RsaPrivateKey::new(&mut thread_rng(), bits).expect("failed to generate a key");
    let der = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();
    let key = EncodingKey::from_rsa_pem(der.as_bytes()).unwrap();
    let token = jsonwebtoken::encode::<TokenClaims>(&header, claims, &key).unwrap();
    let n = URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be());
    let resp = format!("{{\"keys\": [{{\"kty\": \"RSA\",\"use\": \"sig\",\"e\": \"{}\",\"n\": \"{}\",\"alg\": \"RS256\",\"kid\": \"{}\"}}]}}", e, n, KID);

    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(httpmock::Method::GET).path("/");

        then.status(200)
            .header(
                "cache-control",
                "public, max-age=24920, must-revalidate, no-transform",
            )
            .header("Content-Type", "application/json; charset=UTF-8")
            .body(resp);
    });
    (token, server)
}
