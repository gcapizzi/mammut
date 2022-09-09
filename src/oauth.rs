use anyhow::anyhow;
use serde::{Deserialize, Serialize};

const AUTH_URL: &str = "https://twitter.com/i/oauth2/authorize";
const TOKEN_URL: &str = "https://api.twitter.com/2/oauth2/token";

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const PASSWORD_LEN: usize = 128;

#[derive(Deserialize, Serialize)]
struct Token {
    access_token: String,
    expires_at: std::time::SystemTime,
}

impl Token {
    fn new(access_token: String, expires_in: u64) -> Token {
        Token {
            access_token,
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(expires_in),
        }
    }

    fn access_token(&self) -> &String {
        &self.access_token
    }

    fn is_expired(&self) -> bool {
        self.expires_at <= std::time::SystemTime::now()
    }
}

pub async fn get_token(http_client: impl http_client::HttpClient) -> Result<String, anyhow::Error> {
    let token = if let Ok(t) = load_from_disk() {
        t
    } else {
        login(http_client).await.and_then(save_to_disk)?
    };
    Ok(token.access_token().clone())
}

fn load_from_disk() -> Result<Token, anyhow::Error> {
    let path = xdg::BaseDirectories::with_prefix("twt")?.get_cache_file("token");
    let token_str = std::fs::read_to_string(path)?;
    let token = toml::from_str::<Token>(&token_str)?;
    if token.is_expired() {
        Err(anyhow!("token is expired"))
    } else {
        Ok(token)
    }
}

fn save_to_disk(token: Token) -> Result<Token, anyhow::Error> {
    let path = xdg::BaseDirectories::with_prefix("twt")?.place_cache_file("token")?;
    std::fs::write(path, toml::to_string(&token)?)?;
    Ok(token)
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenRequestBody {
    code: String,
    grant_type: String,
    redirect_uri: String,
    code_verifier: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenResposeBody {
    token_type: String,
    expires_in: u64,
    access_token: String,
    scope: String,
}

async fn login(http_client: impl http_client::HttpClient) -> Result<Token, anyhow::Error> {
    let redirect_addr = "0.0.0.0:8000";
    let redirect_uri = format!("http://{}", redirect_addr);

    let client_id = std::env::var("TWT_CLIENT_ID")?;
    let client_secret = std::env::var("TWT_CLIENT_SECRET")?;

    let pkce_verifier = random_chars(PASSWORD_LEN);
    let pkce_challenge = base64::encode_config(sha256(&pkce_verifier), base64::URL_SAFE_NO_PAD);
    let state = random_string(PASSWORD_LEN)?;

    let mut auth_url = url::Url::parse(AUTH_URL)?;
    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id.as_str())
        .append_pair("redirect_uri", redirect_uri.as_str())
        .append_pair("scope", "tweet.read users.read")
        .append_pair("state", state.as_str())
        .append_pair("code_challenge", pkce_challenge.as_str())
        .append_pair("code_challenge_method", "S256");

    println!("Browse to: {}", auth_url);

    let (code, received_state) = receive_redirect(redirect_addr)?;

    if received_state != state {
        return Err(anyhow!("wrong state!"));
    }

    let mut token_req = http_types::Request::new(http_types::Method::Post, TOKEN_URL);
    let req_body = TokenRequestBody {
        code,
        grant_type: "authorization_code".to_string(),
        redirect_uri,
        code_verifier: String::from_utf8(pkce_verifier)?,
    };
    let body = http_types::Body::from_form(&req_body).map_err(|e| anyhow!(e))?;
    token_req.set_body(body);
    let basic_auth = base64::encode(format!("{}:{}", client_id, client_secret));
    token_req.insert_header("Authorization", format!("Basic {}", basic_auth));

    let mut token_resp = http_client.send(token_req).await.map_err(|e| anyhow!(e))?;
    let resp_body: TokenResposeBody = token_resp.body_json().await.map_err(|e| anyhow!(e))?;

    Ok(Token::new(resp_body.access_token, resp_body.expires_in))
}

fn receive_redirect(addr: &str) -> Result<(String, String), anyhow::Error> {
    let server = tiny_http::Server::http(addr).unwrap();
    let request = server.recv()?;
    let url = url::Url::parse("http://base")?.join(request.url())?;
    let query = url.query_pairs();
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
    request.respond(tiny_http::Response::from_string("done!"))?;
    Ok((String::from(code), String::from(state)))
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
