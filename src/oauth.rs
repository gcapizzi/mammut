use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const PASSWORD_LEN: usize = 128;

const CACHE_KEY: &str = "token";

#[derive(PartialEq, Debug, Deserialize, Serialize, Clone)]
pub struct Token {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: std::time::SystemTime,
}

impl Token {
    fn new(access_token: String, refresh_token: Option<String>, expires_in: u64) -> Token {
        Token {
            access_token,
            refresh_token,
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(expires_in),
        }
    }

    fn access_token(&self) -> &String {
        &self.access_token
    }

    fn refresh_token(&self) -> &Option<String> {
        &self.refresh_token
    }

    fn is_expired(&self) -> bool {
        self.expires_at <= std::time::SystemTime::now()
    }
}

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
    expires_in: u64,
    access_token: String,
    refresh_token: Option<String>,
    scope: String,
}

pub struct Config<'a> {
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub auth_url: &'a str,
    pub token_url: &'a str,
    pub redirect_url: &'a str,
}

#[async_trait]
pub trait Authenticator {
    async fn authenticate_user(&self, auth_url: &url::Url) -> Result<url::Url>;
}

pub struct AsyncH1Authenticator {}

impl AsyncH1Authenticator {
    pub fn new() -> AsyncH1Authenticator {
        AsyncH1Authenticator {}
    }
}

#[async_trait]
impl Authenticator for AsyncH1Authenticator {
    async fn authenticate_user(&self, auth_url: &url::Url) -> Result<url::Url> {
        println!("{}", &auth_url);

        let auth_url_params: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();
        let redirect_uri = auth_url_params
            .get("redirect_uri")
            .ok_or(anyhow!("no `redirect_uri`"))?;
        let redirect_url = url::Url::parse(redirect_uri)?;
        let addrs = redirect_url.socket_addrs(|| None)?;
        let listener = async_std::net::TcpListener::bind(&*addrs).await?;
        let (mut stream, _) = listener.accept().await?;
        let (request, _) = async_h1::server::decode(stream.clone())
            .await
            .map_err(|e| anyhow!(e))?
            .ok_or(anyhow!("no request :/"))?;
        let mut response = http_types::Response::new(http_types::StatusCode::Ok);
        response.set_body("done!");
        let mut response_encoder = async_h1::server::Encoder::new(response, request.method());
        async_std::io::copy(&mut response_encoder, &mut stream).await?;
        Ok(request.url().clone())
    }
}

pub trait TokenCache {
    fn set(&self, value: &Token) -> Result<()>;
    fn get(&self) -> Result<Token>;
}

pub struct XDGTokenCache {
    prefix: String,
}

impl XDGTokenCache {
    pub fn new(prefix: String) -> XDGTokenCache {
        XDGTokenCache { prefix }
    }
}

impl TokenCache for XDGTokenCache {
    fn get(&self) -> Result<Token> {
        let path = xdg::BaseDirectories::with_prefix(&self.prefix)?.get_cache_file(CACHE_KEY);
        let value_file = std::fs::File::open(path)?;
        Ok(serde_json::from_reader(&value_file)?)
    }

    fn set(&self, value: &Token) -> Result<()> {
        let path = xdg::BaseDirectories::with_prefix(&self.prefix)?.place_cache_file(CACHE_KEY)?;
        let value_file = std::fs::File::create(path)?;
        serde_json::to_writer(&value_file, &value)?;
        Ok(())
    }
}

pub struct Client<'a, H, A, C> {
    http_client: &'a H,
    authenticator: &'a A,
    cache: &'a C,
    config: Config<'a>,
}

impl<'a, H, A, C> Client<'a, H, A, C>
where
    H: http_client::HttpClient,
    A: Authenticator,
    C: TokenCache,
{
    pub fn new(
        http_client: &'a H,
        authenticator: &'a A,
        cache: &'a C,
        config: Config<'a>,
    ) -> Client<'a, H, A, C> {
        Client {
            http_client,
            authenticator,
            cache,
            config,
        }
    }

    pub async fn get_access_token(&self) -> Result<String> {
        let token = self.get_token().await?;
        Ok(token.access_token().clone())
    }

    async fn get_token(&self) -> Result<Token> {
        if let Ok(t) = self.cache.get() {
            if t.is_expired() {
                let new_t = if let Ok(t) = self.refresh_token(t).await {
                    t
                } else {
                    self.login().await?
                };
                self.cache.set(&new_t)?;
                Ok(new_t)
            } else {
                return Ok(t);
            }
        } else {
            let new_t = self.login().await?;
            self.cache.set(&new_t)?;
            Ok(new_t)
        }
    }

    async fn login(&self) -> Result<Token> {
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

        let redirect_url = self
            .authenticator
            .authenticate_user(&auth_url)
            .await
            .map_err(|e| anyhow!(e))?;

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
        .await
    }

    async fn refresh_token(&self, token: Token) -> Result<Token> {
        self.token(TokenRequestBody {
            grant_type: "refresh_token".to_string(),
            refresh_token: token
                .refresh_token()
                .as_ref()
                .ok_or(anyhow!("no refresh token"))?
                .to_string(),
            ..Default::default()
        })
        .await
    }

    async fn token(&self, req_body: TokenRequestBody) -> Result<Token> {
        let mut token_req =
            http_types::Request::new(http_types::Method::Post, self.config.token_url);
        let body = http_types::Body::from_form(&req_body).map_err(|e| anyhow!(e))?;
        token_req.set_body(body);
        let basic_auth = base64::encode(format!(
            "{}:{}",
            self.config.client_id, self.config.client_secret
        ));
        token_req.insert_header("Authorization", format!("Basic {}", basic_auth));

        let mut token_resp = self
            .http_client
            .send(token_req)
            .await
            .map_err(|e| anyhow!(e))?;
        let resp_body: TokenResposeBody = token_resp.body_json().await.map_err(|e| anyhow!(e))?;

        Ok(Token::new(
            resp_body.access_token,
            resp_body.refresh_token,
            resp_body.expires_in,
        ))
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
pub mod mock;

#[cfg(test)]
mod tests;
