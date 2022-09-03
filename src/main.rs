mod http;
mod oauth;
mod twitter;

use futures::executor::block_on;

const AUTH_URL: &str = "https://twitter.com/i/oauth2/authorize";
const TOKEN_URL: &str = "https://api.twitter.com/2/oauth2/token";

fn main() -> Result<(), anyhow::Error> {
    let token = oauth::get_token(
        std::env::var("TWT_CLIENT_ID")?,
        std::env::var("TWT_CLIENT_SECRET")?,
        AUTH_URL.to_string(),
        TOKEN_URL.to_string(),
    )?;
    let http_client = http::AuthenticatedClient::new(http_client::h1::H1Client::new(), token);
    let client = twitter::Client::new(http_client);

    dbg!(block_on(client.tweets([
        "1460323737035677698",
        "1519781379172495360",
        "1519781381693353984",
    ]))
    .unwrap());

    Ok(())
}
