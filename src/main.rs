mod cache;
mod http;
mod oauth;
mod twitter;

use futures::executor::block_on;

fn main() -> Result<(), anyhow::Error> {
    let client_id = std::env::var("TWT_CLIENT_ID")?;
    let client_secret = std::env::var("TWT_CLIENT_SECRET")?;

    let http_client = http_client::h1::H1Client::new();
    let authenticator = oauth::AsyncH1Authenticator::new();
    let cache = cache::XDG::new("twt".to_string());
    let oauth_client = oauth::Client::new(
        &http_client,
        &authenticator,
        &cache,
        oauth::Config {
            client_id: client_id.as_str(),
            client_secret: client_secret.as_str(),
            auth_url: "https://twitter.com/i/oauth2/authorize",
            token_url: "https://api.twitter.com/2/oauth2/token",
            redirect_url: "http://0.0.0.0:8000",
        },
    );
    let token = block_on(oauth_client.get_access_token())?;
    let authenticated_client = http::AuthenticatedClient::new(http_client, token);
    let client = twitter::Client::new(authenticated_client);

    dbg!(block_on(client.tweets([
        "1460323737035677698",
        "1519781379172495360",
        "1519781381693353984",
    ]))
    .unwrap());

    Ok(())
}
