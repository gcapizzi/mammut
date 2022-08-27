use anyhow::anyhow;
use oauth2::TokenResponse;

pub struct Session {
    token_response: oauth2::basic::BasicTokenResponse,
}

impl Session {
    pub fn token(&self) -> &String {
        self.token_response.access_token().secret()
    }
}

pub fn login(
    client_id: String,
    client_secret: String,
    auth_url: String,
    token_url: String,
) -> Result<Session, anyhow::Error> {
    let token_response = if let Ok(token_str) = std::fs::read_to_string("/tmp/twt_token") {
        toml::from_str(&token_str)?
    } else {
        let redirect_addr = "0.0.0.0:8000";
        let redirect_url = oauth2::RedirectUrl::new(format!("http://{}", redirect_addr))?;

        let client_id = oauth2::ClientId::new(client_id);
        let client_secret = oauth2::ClientSecret::new(client_secret);
        let auth_url = oauth2::AuthUrl::new(auth_url)?;
        let token_url = oauth2::TokenUrl::new(token_url)?;
        let oauth2_client = oauth2::basic::BasicClient::new(
            client_id,
            Some(client_secret),
            auth_url,
            Some(token_url),
        )
        .set_redirect_uri(redirect_url);

        let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_state) = oauth2_client
            .authorize_url(oauth2::CsrfToken::new_random)
            .add_scope(oauth2::Scope::new("tweet.read".to_string()))
            .add_scope(oauth2::Scope::new("users.read".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        println!("Browse to: {}", auth_url);

        let (code, state) = authorise(redirect_addr)?;

        if &state != csrf_state.secret() {
            return Err(anyhow!("wrong state!"));
        }

        let ts = oauth2_client
            .exchange_code(oauth2::AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier)
            .request(oauth2::ureq::http_client)?;

        std::fs::write("/tmp/twt_token", toml::to_string(&ts)?)?;

        ts
    };

    Ok(Session { token_response })
}

fn authorise(addr: &str) -> Result<(String, String), anyhow::Error> {
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
