mod http;
mod oauth;
mod twitter;

use futures::executor::block_on;

fn main() -> Result<(), anyhow::Error> {
    let http_client = http_client::h1::H1Client::new();
    let token = block_on(oauth::get_access_token(&http_client))?;
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
