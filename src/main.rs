mod http;
mod oauth;
mod twitter;

use anyhow::{anyhow, Result};

fn main() -> Result<()> {
    let client_id = std::env::var("TWT_CLIENT_ID")?;
    let client_secret = std::env::var("TWT_CLIENT_SECRET")?;

    let http_client = http::UreqClient::new();
    let authenticator = oauth::StdAuthenticator::new();
    let cache = oauth::XDGTokenCache::new("mammut".to_string());
    let oauth_client = oauth::DefaultClient::new(
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
    let authenticated_http_client = http::AuthenticatedClient::new(&http_client, &oauth_client);
    let client = twitter::Client::new(&authenticated_http_client);

    let m = clap::Command::new("mammut")
        .version(clap::crate_version!())
        .subcommand_required(true)
        .subcommand(
            clap::Command::new("get-tweets")
                .arg(clap::Arg::new("ids").num_args(1..=100).required(true)),
        )
        .get_matches();

    match m.subcommand() {
        Some(("get-tweets", args)) => {
            let ids = args
                .get_many("ids")
                .ok_or(anyhow!("no ids!"))?
                .cloned()
                .collect::<Vec<String>>();
            let tweets = client.get_tweets(&ids)?;
            println!("{:?}", tweets)
        }
        _ => {}
    }

    Ok(())
}
