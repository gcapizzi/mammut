use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const PASSWORD_LEN: usize = 128;

const CACHE_KEY: &str = "token";

#[derive(PartialEq, Debug, Deserialize, Serialize, Clone)]
pub struct Token {
    access_token: String,
    refresh_token: Option<String>,
    created_at: std::time::SystemTime,
    expires_in: Option<u64>,
}

impl Token {
    fn new(access_token: String, refresh_token: Option<String>, expires_in: Option<u64>) -> Token {
        Token {
            access_token,
            refresh_token,
            created_at: std::time::SystemTime::now(),
            expires_in,
        }
    }

    fn access_token(&self) -> &String {
        &self.access_token
    }

    fn refresh_token(&self) -> &Option<String> {
        &self.refresh_token
    }

    fn expires_at(&self) -> Option<std::time::SystemTime> {
        self.expires_in
            .map(|s| self.created_at + std::time::Duration::from_secs(s))
    }

    fn is_expired(&self) -> bool {
        self.expires_at()
            .map(|t| t <= std::time::SystemTime::now())
            .unwrap_or(false)
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
    expires_in: Option<u64>,
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

pub trait Authenticator {
    fn authenticate_user(&self, auth_url: &url::Url) -> Result<url::Url>;
}

pub struct StdAuthenticator {}

impl StdAuthenticator {
    pub fn new() -> StdAuthenticator {
        StdAuthenticator {}
    }
}

impl Authenticator for StdAuthenticator {
    fn authenticate_user(&self, auth_url: &url::Url) -> Result<url::Url> {
        use std::io::{BufRead, Write};

        println!("{}", &auth_url);

        let auth_url_params: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();
        let redirect_uri = auth_url_params
            .get("redirect_uri")
            .ok_or(anyhow!("no `redirect_uri`"))?;
        let redirect_url = url::Url::parse(redirect_uri)?;
        let addrs = redirect_url.socket_addrs(|| None)?;
        let listener = std::net::TcpListener::bind(&*addrs)?;
        let (mut stream, _) = listener.accept()?;
        let mut buf = std::io::BufReader::new(&stream);
        let mut start_line = String::new();
        buf.read_line(&mut start_line)?;
        let path = start_line.split(" ").nth(1).ok_or(anyhow!("no path"))?;
        stream.write_all("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\ndone!".as_bytes())?;
        Ok(redirect_url.join(path)?)
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
pub mod mock;

#[cfg(test)]
mod tests;
