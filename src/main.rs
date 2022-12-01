mod config;
mod http;
mod mastodon;
mod oauth;

use anyhow::Result;

const APP_NAME: &str = "mammut";

fn main() -> Result<()> {
    let m = clap::Command::new(APP_NAME)
        .version(clap::crate_version!())
        .subcommand_required(true)
        .subcommand(
            clap::Command::new("target")
                .arg(
                    clap::Arg::new("url")
                        .required(true)
                        .value_parser(url::Url::parse),
                )
                .arg(clap::Arg::new("client_id").long("client-id").required(true))
                .arg(
                    clap::Arg::new("client_secret")
                        .long("client-secret")
                        .required(true),
                )
                .arg(
                    clap::Arg::new("redirect_url")
                        .long("redirect-url")
                        .required(true)
                        .value_parser(url::Url::parse),
                ),
        )
        .subcommand(clap::Command::new("get-status").arg(clap::Arg::new("id").required(true)))
        .get_matches();

    let config_store = config::XDGStore::new(APP_NAME.to_string());

    if let Some(("target", args)) = m.subcommand() {
        return config_store.save(&config::Config {
            client_id: args.get_one::<String>("client_id").unwrap().to_string(),
            client_secret: args.get_one::<String>("client_secret").unwrap().to_string(),
            base_url: args.get_one::<url::Url>("url").unwrap().to_string(),
            redirect_url: args
                .get_one::<url::Url>("redirect_url")
                .unwrap()
                .to_string(),
        });
    }

    let http_client = http::UreqClient::new();
    let authenticator = oauth::StdAuthenticator::new();
    let cache = oauth::XDGTokenCache::new(APP_NAME.to_string());
    let config = config_store.load()?;
    let base_url = url::Url::parse(&config.base_url)?;
    let auth_url = base_url.join("/oauth/authorize")?.to_string();
    let token_url = base_url.join("/oauth/token")?.to_string();
    let oauth_client = oauth::DefaultClient::new(
        &http_client,
        &authenticator,
        &cache,
        oauth::Config {
            client_id: &config.client_id,
            client_secret: &config.client_secret,
            auth_url: &auth_url,
            token_url: &token_url,
            redirect_url: &config.redirect_url,
            scope: "read",
        },
    );
    let authenticated_http_client = http::AuthenticatedClient::new(&http_client, &oauth_client);
    let client = mastodon::Client::new(&authenticated_http_client, base_url);

    match m.subcommand() {
        Some(("get-status", args)) => {
            let id = args.get_one::<String>("id").unwrap();
            let status = client.get_status(&id)?;
            println!("{:#?}", status)
        }
        _ => {}
    }

    Ok(())
}
