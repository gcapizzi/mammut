use crate::oauth::{Authenticator, Config, Token, TokenCache};

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const PASSWORD_LEN: usize = 128;

#[derive(Debug, Default, Serialize, Deserialize)]
struct TokenRequestBody {
    #[serde(skip_serializing_if = "String::is_empty")]
    code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    grant_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    redirect_uri: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    code_verifier: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenResposeBody {
    token_type: String,
    expires_in: Option<u64>,
    access_token: String,
    refresh_token: Option<String>,
    scope: String,
}

pub trait Client {
    fn get_access_token(&self) -> Result<String>;
    fn refresh_access_token(&self) -> Result<String>;
}

pub struct DefaultClient<'a, H, A, C> {
    http_client: &'a H,
    authenticator: &'a A,
    cache: &'a C,
    config: Config<'a>,
}

impl<H, A, C> Client for DefaultClient<'_, H, A, C>
where
    H: crate::http::Client,
    A: Authenticator,
    C: TokenCache,
{
    fn get_access_token(&self) -> Result<String> {
        let token = self.get_token()?;
        Ok(token.access_token().clone())
    }

    fn refresh_access_token(&self) -> Result<String> {
        let token = self
            .cache
            .get()
            .and_then(|t| self.refresh_token(t))
            .or_else(|_| self.login())?;
        Ok(token.access_token().clone())
    }
}

impl<'a, H, A, C> DefaultClient<'a, H, A, C>
where
    H: crate::http::Client,
    A: Authenticator,
    C: TokenCache,
{
    pub fn new(
        http_client: &'a H,
        authenticator: &'a A,
        cache: &'a C,
        config: Config<'a>,
    ) -> DefaultClient<'a, H, A, C> {
        DefaultClient {
            http_client,
            authenticator,
            cache,
            config,
        }
    }

    fn get_token(&self) -> Result<Token> {
        self.cache
            .get()
            .and_then(|t| {
                if t.is_expired() {
                    self.refresh_token(t)
                } else {
                    Ok(t)
                }
            })
            .or_else(|_| self.login())
    }

    fn login(&self) -> Result<Token> {
        let pkce_verifier = random_chars(PASSWORD_LEN);
        let pkce_challenge = base64::encode_config(sha256(&pkce_verifier), base64::URL_SAFE_NO_PAD);
        let state = random_string(PASSWORD_LEN)?;

        let mut auth_url = url::Url::parse(self.config.auth_url)?;
        auth_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", self.config.client_id)
            .append_pair("redirect_uri", self.config.redirect_url)
            .append_pair("scope", "tweet.read users.read offline.access")
            .append_pair("state", state.as_str())
            .append_pair("code_challenge", pkce_challenge.as_str())
            .append_pair("code_challenge_method", "S256");

        let redirect_url = self.authenticator.authenticate_user(&auth_url)?;

        let redirect_url_params: HashMap<_, _> = redirect_url.query_pairs().into_owned().collect();
        let code = redirect_url_params
            .get("code")
            .ok_or(anyhow!("no `code`"))?;
        let received_state = redirect_url_params
            .get("state")
            .ok_or(anyhow!("no `state`"))?;

        if received_state != &state {
            bail!("wrong state!");
        }

        self.token(TokenRequestBody {
            code: code.to_string(),
            grant_type: "authorization_code".to_string(),
            redirect_uri: self.config.redirect_url.to_string(),
            code_verifier: String::from_utf8(pkce_verifier)?,
            ..Default::default()
        })
    }

    fn refresh_token(&self, token: Token) -> Result<Token> {
        self.token(TokenRequestBody {
            grant_type: "refresh_token".to_string(),
            refresh_token: token
                .refresh_token()
                .as_ref()
                .ok_or(anyhow!("no refresh token"))?
                .to_string(),
            ..Default::default()
        })
    }

    fn token(&self, req_body: TokenRequestBody) -> Result<Token> {
        let basic_auth = base64::encode(format!(
            "{}:{}",
            self.config.client_id, self.config.client_secret
        ));
        let req = ::http::Request::post(self.config.token_url)
            .header("Authorization", format!("Basic {}", basic_auth))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(serde_urlencoded::to_string(req_body)?)?;

        let resp = self.http_client.send(req)?;
        let resp_body: TokenResposeBody = serde_json::from_reader(resp.into_body())?;

        let token = Token::new(
            resp_body.access_token,
            resp_body.refresh_token,
            resp_body.expires_in,
        );

        self.cache.set(&token)?;

        Ok(token)
    }
}

fn random_chars(length: usize) -> Vec<u8> {
    use rand::Rng;
    (0..length)
        .map(|_| {
            let idx = rand::thread_rng().gen_range(0..CHARSET.len());
            CHARSET[idx]
        })
        .collect()
}

fn random_string(length: usize) -> Result<String> {
    Ok(String::from_utf8(random_chars(length))?)
}

fn sha256(data: impl AsRef<[u8]>) -> impl AsRef<[u8]> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(&data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use crate::{
        http,
        oauth::{self, Client, TokenCache},
    };
    use expect::{
        expect,
        matchers::{equal, option::be_none},
    };
    use std::collections::HashMap;

    #[test]
    fn get_access_token_when_the_token_is_not_cached_it_logs_in() {
        let authenticator =
            oauth::authenticator::mock::Authenticator::new("the-auth-code".to_string());
        let http_client = http::mock::Client::new([::http::Response::builder()
            .status(200)
            .body(
                r#"{
                "token_type": "bearer",
                "expires_in": 1,
                "access_token": "ACCESS_TOKEN",
                "refresh_token": "REFRESH_TOKEN",
                "scope": "SCOPE"
            }"#
                .to_string(),
            )
            .unwrap()]);
        let cache = oauth::cache::mock::TokenCache::empty();

        let client = oauth::DefaultClient::new(
            &http_client,
            &authenticator,
            &cache,
            oauth::Config {
                client_id: "id",
                client_secret: "secret",
                auth_url: "https://the-auth-url",
                token_url: "https://the-token-url",
                redirect_url: "https://the-redirect-url",
            },
        );

        expect(&client.get_access_token().unwrap()).to(equal("ACCESS_TOKEN".to_string()));

        let auth_url = authenticator.last_auth_url().unwrap();
        expect(&auth_url.origin().unicode_serialization()).to(equal("https://the-auth-url"));

        let auth_url_params: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();
        expect(auth_url_params.get("response_type").unwrap()).to(equal("code"));
        expect(auth_url_params.get("client_id").unwrap()).to(equal("id"));
        expect(auth_url_params.get("scope").unwrap())
            .to(equal("tweet.read users.read offline.access"));
        expect(&auth_url_params.get("code_challenge_method")).to(equal(Some(&"S256".to_string())));

        let redirect_url = auth_url_params.get("redirect_uri").unwrap();
        expect(&redirect_url).to(equal("https://the-redirect-url"));

        let code_challenge = auth_url_params.get("code_challenge").unwrap();

        let reqs = http_client.requests();
        let token_req = reqs.last().unwrap();

        expect(&token_req.method()).to(equal("POST"));
        expect(&token_req.uri()).to(equal("https://the-token-url/"));

        // base64("id:secret") = "aWQ6c2VjcmV0"
        expect(token_req.headers().get("authorization").unwrap()).to(equal("Basic aWQ6c2VjcmV0"));
        expect(token_req.headers().get("content-type").unwrap())
            .to(equal("application/x-www-form-urlencoded"));

        expect(&token_req.body().get("code").unwrap()).to(equal("the-auth-code"));
        expect(&token_req.body().get("grant_type").unwrap()).to(equal("authorization_code"));
        expect(&token_req.body().get("redirect_uri").unwrap()).to(equal(redirect_url));

        let code_verifier = token_req.body().get("code_verifier").unwrap();
        expect(&code_challenge).to(equal(&sha256(code_verifier)));

        let cached_token = cache.get().unwrap();
        expect(&cached_token.access_token()).to(equal(&"ACCESS_TOKEN".to_string()));
        expect(&cached_token.refresh_token()).to(equal(&Some("REFRESH_TOKEN".to_string())));
        expect(&cached_token.is_expired()).to(equal(false));
    }

    #[test]
    fn get_access_token_when_the_token_is_cached_and_not_expired_it_returns_it() {
        let authenticator = oauth::authenticator::mock::Authenticator::new(String::new());
        let http_client = http::mock::Client::new([]);
        let token = oauth::Token::new("CACHED_ACCESS_TOKEN".to_string(), None, Some(1));
        let cache = oauth::cache::mock::TokenCache::with_value(token.clone());

        let client = oauth::DefaultClient::new(
            &http_client,
            &authenticator,
            &cache,
            oauth::Config {
                client_id: "id",
                client_secret: "secret",
                auth_url: "https://the-auth-url",
                token_url: "https://the-token-url",
                redirect_url: "https://the-redirect-url",
            },
        );

        expect(&client.get_access_token().unwrap()).to(equal("CACHED_ACCESS_TOKEN".to_string()));

        expect(&authenticator.last_auth_url()).to(be_none());
        expect(&http_client.requests().len()).to(equal(0));
        expect(&cache.get().unwrap()).to(equal(token));
    }

    #[test]
    fn get_access_token_when_the_token_is_cached_but_expired_and_refreshable_it_refreshes_it() {
        let authenticator =
            oauth::authenticator::mock::Authenticator::new("the-auth-code".to_string());
        let http_client = http::mock::Client::new([::http::Response::builder()
            .status(200)
            .body(
                r#"{
                "token_type": "bearer",
                "expires_in": 1,
                "access_token": "REFRESHED_ACCESS_TOKEN",
                "refresh_token": "REFRESH_TOKEN",
                "scope": "SCOPE"
            }"#
                .to_string(),
            )
            .unwrap()]);
        let token = oauth::Token::new(
            "CACHED_ACCESS_TOKEN".to_string(),
            Some("CACHED_REFRESH_TOKEN".to_string()),
            Some(0),
        );
        let cache = oauth::cache::mock::TokenCache::with_value(token.clone());

        let client = oauth::DefaultClient::new(
            &http_client,
            &authenticator,
            &cache,
            oauth::Config {
                client_id: "id",
                client_secret: "secret",
                auth_url: "https://the-auth-url",
                token_url: "https://the-token-url",
                redirect_url: "https://the-redirect-url",
            },
        );

        expect(&client.get_access_token().unwrap()).to(equal("REFRESHED_ACCESS_TOKEN".to_string()));

        let reqs = http_client.requests();
        let token_req = reqs.last().unwrap();

        expect(&token_req.method()).to(equal("POST"));
        expect(&token_req.uri()).to(equal("https://the-token-url/"));

        // base64("id:secret") = "aWQ6c2VjcmV0"
        expect(token_req.headers().get("authorization").unwrap()).to(equal("Basic aWQ6c2VjcmV0"));
        expect(token_req.headers().get("content-type").unwrap())
            .to(equal("application/x-www-form-urlencoded"));

        expect(&token_req.body().get("grant_type").unwrap()).to(equal("refresh_token"));
        expect(&token_req.body().get("refresh_token").unwrap())
            .to(equal(&"CACHED_REFRESH_TOKEN".to_string()));

        let cached_token = cache.get().unwrap();
        expect(&cached_token.access_token()).to(equal(&"REFRESHED_ACCESS_TOKEN".to_string()));
        expect(&cached_token.refresh_token()).to(equal(&Some("REFRESH_TOKEN".to_string())));
        expect(&cached_token.is_expired()).to(equal(false));
    }

    #[test]
    fn get_access_token_when_the_token_is_cached_but_expired_and_not_refreshable_it_logs_in() {
        let authenticator =
            oauth::authenticator::mock::Authenticator::new("the-auth-code".to_string());
        let http_client = http::mock::Client::new([::http::Response::builder()
            .status(200)
            .body(
                r#"{
                "token_type": "bearer",
                "expires_in": 1,
                "access_token": "NEW_ACCESS_TOKEN",
                "scope": "SCOPE"
            }"#
                .to_string(),
            )
            .unwrap()]);
        let token = oauth::Token::new("CACHED_ACCESS_TOKEN".to_string(), None, Some(0));
        let cache = oauth::cache::mock::TokenCache::with_value(token.clone());

        let client = oauth::DefaultClient::new(
            &http_client,
            &authenticator,
            &cache,
            oauth::Config {
                client_id: "id",
                client_secret: "secret",
                auth_url: "https://the-auth-url",
                token_url: "https://the-token-url",
                redirect_url: "https://the-redirect-url",
            },
        );

        expect(&client.get_access_token().unwrap()).to(equal("NEW_ACCESS_TOKEN".to_string()));

        let reqs = http_client.requests();
        let token_req = reqs.last().unwrap();

        expect(&token_req.method()).to(equal("POST"));
        expect(&token_req.uri()).to(equal("https://the-token-url/"));
        expect(&token_req.body().get("code").unwrap()).to(equal("the-auth-code"));
        expect(&token_req.body().get("grant_type").unwrap()).to(equal("authorization_code"));

        let cached_token = cache.get().unwrap();
        expect(&cached_token.access_token()).to(equal(&"NEW_ACCESS_TOKEN".to_string()));
    }

    #[test]
    fn get_access_token_when_refreshing_fails_it_logs_in_again() {
        let authenticator =
            oauth::authenticator::mock::Authenticator::new("the-auth-code".to_string());
        let http_client = http::mock::Client::new([
            ::http::Response::builder()
                .status(500)
                .body("".to_string())
                .unwrap(),
            ::http::Response::builder()
                .status(200)
                .body(
                    r#"{
                    "token_type": "bearer",
                    "expires_in": 1,
                    "access_token": "NEW_ACCESS_TOKEN",
                    "refresh_token": "NEW_REFRESH_TOKEN",
                    "scope": "SCOPE"
                }"#
                    .to_string(),
                )
                .unwrap(),
        ]);
        let token = oauth::Token::new(
            "CACHED_ACCESS_TOKEN".to_string(),
            Some("CACHED_REFRESH_TOKEN".to_string()),
            Some(0),
        );
        let cache = oauth::cache::mock::TokenCache::with_value(token.clone());

        let client = oauth::DefaultClient::new(
            &http_client,
            &authenticator,
            &cache,
            oauth::Config {
                client_id: "id",
                client_secret: "secret",
                auth_url: "https://the-auth-url",
                token_url: "https://the-token-url",
                redirect_url: "https://the-redirect-url",
            },
        );

        expect(&client.get_access_token().unwrap()).to(equal("NEW_ACCESS_TOKEN".to_string()));

        let reqs = http_client.requests();
        let token_req = reqs.last().unwrap();

        expect(&token_req.method()).to(equal("POST"));
        expect(&token_req.uri()).to(equal("https://the-token-url/"));
        expect(&token_req.body().get("code").unwrap()).to(equal("the-auth-code"));
        expect(&token_req.body().get("grant_type").unwrap()).to(equal("authorization_code"));

        let cached_token = cache.get().unwrap();
        expect(&cached_token.access_token()).to(equal(&"NEW_ACCESS_TOKEN".to_string()));
    }

    #[test]
    fn get_access_token_handles_tokens_with_no_expiration() {
        let authenticator =
            oauth::authenticator::mock::Authenticator::new("the-auth-code".to_string());
        let http_client = http::mock::Client::new([::http::Response::builder()
            .status(200)
            .body(
                r#"{
                "token_type": "bearer",
                "access_token": "ACCESS_TOKEN",
                "scope": "SCOPE"
            }"#
                .to_string(),
            )
            .unwrap()]);
        let cache = oauth::cache::mock::TokenCache::empty();

        let client = oauth::DefaultClient::new(
            &http_client,
            &authenticator,
            &cache,
            oauth::Config {
                client_id: "id",
                client_secret: "secret",
                auth_url: "https://the-auth-url",
                token_url: "https://the-token-url",
                redirect_url: "https://the-redirect-url",
            },
        );

        expect(&client.get_access_token().unwrap()).to(equal("ACCESS_TOKEN".to_string()));

        let auth_url = authenticator.last_auth_url().unwrap();
        expect(&auth_url.origin().unicode_serialization()).to(equal("https://the-auth-url"));

        let reqs = http_client.requests();
        let token_req = reqs.last().unwrap();

        expect(&token_req.method()).to(equal("POST"));
        expect(&token_req.uri()).to(equal("https://the-token-url/"));
        expect(&token_req.body().get("code").unwrap()).to(equal("the-auth-code"));
        expect(&token_req.body().get("grant_type").unwrap()).to(equal("authorization_code"));

        let cached_token = cache.get().unwrap();
        expect(&cached_token.access_token()).to(equal(&"ACCESS_TOKEN".to_string()));
        expect(&cached_token.is_expired()).to(equal(false));
    }

    #[test]
    fn refresh_access_token_refreshes_the_token() {
        let authenticator = oauth::authenticator::mock::Authenticator::new(String::new());
        let http_client = http::mock::Client::new([::http::Response::builder()
            .status(200)
            .body(
                r#"{
                "token_type": "bearer",
                "expires_in": 1,
                "access_token": "REFRESHED_ACCESS_TOKEN",
                "refresh_token": "REFRESH_TOKEN",
                "scope": "SCOPE"
            }"#
                .to_string(),
            )
            .unwrap()]);
        let token = oauth::Token::new(
            "CACHED_ACCESS_TOKEN".to_string(),
            Some("CACHED_REFRESH_TOKEN".to_string()),
            Some(0),
        );
        let cache = oauth::cache::mock::TokenCache::with_value(token.clone());

        let client = oauth::DefaultClient::new(
            &http_client,
            &authenticator,
            &cache,
            oauth::Config {
                client_id: "id",
                client_secret: "secret",
                auth_url: "https://the-auth-url",
                token_url: "https://the-token-url",
                redirect_url: "https://the-redirect-url",
            },
        );

        expect(&client.refresh_access_token().unwrap())
            .to(equal("REFRESHED_ACCESS_TOKEN".to_string()));

        let reqs = http_client.requests();
        let token_req = reqs.last().unwrap();

        expect(&token_req.method()).to(equal("POST"));
        expect(&token_req.uri()).to(equal("https://the-token-url/"));

        // base64("id:secret") = "aWQ6c2VjcmV0"
        expect(token_req.headers().get("authorization").unwrap()).to(equal("Basic aWQ6c2VjcmV0"));
        expect(token_req.headers().get("content-type").unwrap())
            .to(equal("application/x-www-form-urlencoded"));

        expect(&token_req.body().get("grant_type").unwrap()).to(equal("refresh_token"));
        expect(&token_req.body().get("refresh_token").unwrap())
            .to(equal(&"CACHED_REFRESH_TOKEN".to_string()));

        let cached_token = cache.get().unwrap();
        expect(&cached_token.access_token()).to(equal(&"REFRESHED_ACCESS_TOKEN".to_string()));
        expect(&cached_token.refresh_token()).to(equal(&Some("REFRESH_TOKEN".to_string())));
        expect(&cached_token.is_expired()).to(equal(false));
    }

    #[test]
    fn refresh_access_token_when_refreshing_fails_it_logs_in_again() {
        let authenticator =
            oauth::authenticator::mock::Authenticator::new("the-auth-code".to_string());
        let http_client = http::mock::Client::new([
            ::http::Response::builder()
                .status(500)
                .body("".to_string())
                .unwrap(),
            ::http::Response::builder()
                .status(200)
                .body(
                    r#"{
                    "token_type": "bearer",
                    "expires_in": 1,
                    "access_token": "NEW_ACCESS_TOKEN",
                    "refresh_token": "NEW_REFRESH_TOKEN",
                    "scope": "SCOPE"
                }"#
                    .to_string(),
                )
                .unwrap(),
        ]);
        let token = oauth::Token::new(
            "CACHED_ACCESS_TOKEN".to_string(),
            Some("CACHED_REFRESH_TOKEN".to_string()),
            Some(0),
        );
        let cache = oauth::cache::mock::TokenCache::with_value(token.clone());

        let client = oauth::DefaultClient::new(
            &http_client,
            &authenticator,
            &cache,
            oauth::Config {
                client_id: "id",
                client_secret: "secret",
                auth_url: "https://the-auth-url",
                token_url: "https://the-token-url",
                redirect_url: "https://the-redirect-url",
            },
        );

        expect(&client.refresh_access_token().unwrap()).to(equal("NEW_ACCESS_TOKEN".to_string()));

        let reqs = http_client.requests();
        let token_req = reqs.last().unwrap();

        expect(&token_req.method()).to(equal("POST"));
        expect(&token_req.uri()).to(equal("https://the-token-url/"));
        expect(&token_req.body().get("code").unwrap()).to(equal("the-auth-code"));
        expect(&token_req.body().get("grant_type").unwrap()).to(equal("authorization_code"));

        let cached_token = cache.get().unwrap();
        expect(&cached_token.access_token()).to(equal(&"NEW_ACCESS_TOKEN".to_string()));
    }

    fn sha256(data: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        base64::encode_config(hash, base64::URL_SAFE_NO_PAD)
    }
}

#[cfg(test)]
pub mod mock {
    use anyhow::{anyhow, Result};

    pub struct Client {
        token: std::cell::RefCell<Result<String, String>>,
    }

    impl Client {
        pub fn new(token: Result<String, String>) -> Client {
            Client {
                token: std::cell::RefCell::new(token),
            }
        }
    }

    impl crate::oauth::Client for Client {
        fn get_access_token(&self) -> Result<String> {
            self.token.borrow().clone().map_err(|e| anyhow!(e))
        }

        fn refresh_access_token(&self) -> Result<String> {
            _ = self
                .token
                .replace_with(|t| t.clone().map(|t| format!("{}-REFRESHED", t)));
            self.get_access_token()
        }
    }
}
