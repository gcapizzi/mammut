use anyhow::anyhow;
use oauth2::TokenResponse;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct Token {
    access_token: String,
    expires_at: std::time::SystemTime,
}

impl Token {
    fn new(access_token: String, expires_in: std::time::Duration) -> Token {
        Token {
            access_token,
            expires_at: std::time::SystemTime::now() + expires_in,
        }
    }

    fn access_token(&self) -> &String {
        &self.access_token
    }

    fn is_expired(&self) -> bool {
        self.expires_at <= std::time::SystemTime::now()
    }
}

pub fn get_token(
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
) -> Result<String, anyhow::Error> {
    let token = load_from_disk()
        .or_else(|_| login(client_id, client_secret, auth_url, token_url).and_then(save_to_disk))?;

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

fn login(
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
) -> Result<Token, anyhow::Error> {
    let redirect_addr = "0.0.0.0:8000";
    let redirect_url = oauth2::RedirectUrl::new(format!("http://{}", redirect_addr))?;

    let client_id = oauth2::ClientId::new(client_id);
    let client_secret = oauth2::ClientSecret::new(client_secret);
    let auth_url = oauth2::AuthUrl::new(auth_url)?;
    let token_url = oauth2::TokenUrl::new(token_url)?;
    let oauth2_client =
        oauth2::basic::BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
            .set_redirect_uri(redirect_url);

    let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_state) = oauth2_client
        .authorize_url(oauth2::CsrfToken::new_random)
        .add_scope(oauth2::Scope::new("tweet.read".to_string()))
        .add_scope(oauth2::Scope::new("users.read".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    println!("Browse to: {}", auth_url);

    let (code, state) = receive_redirect(redirect_addr)?;

    if &state != csrf_state.secret() {
        return Err(anyhow!("wrong state!"));
    }

    let token_response = oauth2_client
        .exchange_code(oauth2::AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request(oauth2::ureq::http_client)?;

    Ok(Token::new(
        token_response.access_token().secret().clone(),
        token_response
            .expires_in()
            .ok_or(anyhow!("no expires_in field"))?,
    ))
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
