use crate::{cache, http, io};
use anyhow::anyhow;
use serde::{Deserialize, Serialize};

const AUTH_URL: &str = "https://twitter.com/i/oauth2/authorize";
const TOKEN_URL: &str = "https://api.twitter.com/2/oauth2/token";

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const PASSWORD_LEN: usize = 128;

const CACHE_KEY: &str = "token";

#[derive(Deserialize, Serialize)]
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

pub struct Credentials {
    id: String,
    secret: String,
}

impl Credentials {
    pub fn new(id: String, secret: String) -> Credentials {
        Credentials { id, secret }
    }
}

pub struct Client<'a, H, R, C, U> {
    credentials: Credentials,
    http_client: &'a H,
    http_receiver: R,
    cache: C,
    user_interface: U,
}

impl<'a, H, R, C, U> Client<'a, H, R, C, U>
where
    H: http_client::HttpClient,
    R: http::Receiver,
    C: cache::Cache<Token>,
    U: io::UserInterface,
{
    pub fn new(
        credentials: Credentials,
        http_client: &'a H,
        http_receiver: R,
        cache: C,
        user_interface: U,
    ) -> Client<'a, H, R, C, U> {
        Client {
            credentials,
            http_client,
            http_receiver,
            cache,
            user_interface,
        }
    }

    pub async fn get_access_token(&self) -> Result<String, anyhow::Error> {
        let token = self.get_token().await?;
        Ok(token.access_token().clone())
    }

    async fn get_token(&self) -> Result<Token, anyhow::Error> {
        if let Ok(t) = self.cache.get(CACHE_KEY) {
            if t.is_expired() {
                let new_t = if let Ok(t) = self.refresh_token(t).await {
                    t
                } else {
                    self.login().await?
                };
                self.cache.set(CACHE_KEY, &new_t)?;
                Ok(new_t)
            } else {
                return Ok(t);
            }
        } else {
            let new_t = self.login().await?;
            self.cache.set(CACHE_KEY, &new_t)?;
            Ok(new_t)
        }
    }

    async fn login(&self) -> Result<Token, anyhow::Error> {
        let redirect_addr = "0.0.0.0:8000";
        let redirect_uri = format!("http://{}", redirect_addr);

        let pkce_verifier = random_chars(PASSWORD_LEN);
        let pkce_challenge = base64::encode_config(sha256(&pkce_verifier), base64::URL_SAFE_NO_PAD);
        let state = random_string(PASSWORD_LEN)?;

        let mut auth_url = url::Url::parse(AUTH_URL)?;
        auth_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", self.credentials.id.as_str())
            .append_pair("redirect_uri", redirect_uri.as_str())
            .append_pair("scope", "tweet.read users.read offline.access")
            .append_pair("state", state.as_str())
            .append_pair("code_challenge", pkce_challenge.as_str())
            .append_pair("code_challenge_method", "S256");

        self.user_interface
            .println(format!("Browse to: {}", auth_url).as_str());

        let (code, received_state) = self.receive_redirect(redirect_addr).await?;

        if received_state != state {
            return Err(anyhow!("wrong state!"));
        }

        let mut token_req = http_types::Request::new(http_types::Method::Post, TOKEN_URL);
        let req_body = TokenRequestBody {
            code,
            grant_type: "authorization_code".to_string(),
            redirect_uri,
            code_verifier: String::from_utf8(pkce_verifier)?,
            ..Default::default()
        };
        let body = http_types::Body::from_form(&req_body).map_err(|e| anyhow!(e))?;
        token_req.set_body(body);
        let basic_auth = base64::encode(format!(
            "{}:{}",
            self.credentials.id, self.credentials.secret
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

    async fn refresh_token(&self, token: Token) -> Result<Token, anyhow::Error> {
        let client_id = std::env::var("TWT_CLIENT_ID")?;
        let client_secret = std::env::var("TWT_CLIENT_SECRET")?;

        let mut token_req = http_types::Request::new(http_types::Method::Post, TOKEN_URL);
        let req_body = TokenRequestBody {
            grant_type: "refresh_token".to_string(),
            refresh_token: token
                .refresh_token()
                .as_ref()
                .ok_or(anyhow!("no refresh token"))?
                .to_string(),
            ..Default::default()
        };
        let body = http_types::Body::from_form(&req_body).map_err(|e| anyhow!(e))?;
        token_req.set_body(body);
        let basic_auth = base64::encode(format!("{}:{}", client_id, client_secret));
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

    async fn receive_redirect(&self, addr: &str) -> Result<(String, String), anyhow::Error> {
        let request = self
            .http_receiver
            .receive(addr.parse()?)
            .await
            .map_err(|e| anyhow!(e))?;
        let query = request.url().query_pairs();
        let code = query
            .into_iter()
            .find(|(k, _)| k == "code")
            .ok_or(anyhow!("no `code`!"))?
            .1;
        let state = query
            .into_iter()
            .find(|(k, _)| k == "state")
            .ok_or(anyhow!("no `state`!"))?
            .1;
        Ok((String::from(code), String::from(state)))
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

fn random_string(length: usize) -> Result<String, anyhow::Error> {
    Ok(String::from_utf8(random_chars(length))?)
}

fn sha256(data: impl AsRef<[u8]>) -> impl AsRef<[u8]> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(&data);
    hasher.finalize()
}
