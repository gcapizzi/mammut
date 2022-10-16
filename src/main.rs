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
        oauth::Credentials::new(client_id, client_secret),
        &http_client,
        &authenticator,
        &cache,
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
