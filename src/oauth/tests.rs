mod mock;

use crate::cache::Cache;
use crate::oauth;
use expect::{
    expect,
    matchers::{equal, option::be_none},
};
use futures::executor::block_on;
use std::collections::HashMap;

#[async_std::test]
async fn when_the_token_is_not_cached_it_logins_and_saves_the_token() {
    let credentials = oauth::Credentials::new("id".to_string(), "secret".to_string());

    let authenticator = mock::Authenticator::new("the-auth-code".to_string());
    let http_client = mock::HttpClient::new();
    let cache = mock::Cache::new(HashMap::new());

    let client = oauth::Client::new(credentials, &http_client, &authenticator, &cache);

    expect(&client.get_access_token().await.unwrap()).to(equal("ACCESS_TOKEN".to_string()));

    let auth_url = authenticator.last_auth_url().unwrap();
    let auth_url_params: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();
    expect(auth_url_params.get("response_type").unwrap()).to(equal("code"));
    expect(auth_url_params.get("client_id").unwrap()).to(equal("id"));
    expect(auth_url_params.get("scope").unwrap()).to(equal("tweet.read users.read offline.access"));
    expect(&auth_url_params.get("code_challenge_method")).to(equal(Some(&"S256".to_string())));

    let redirect_url = auth_url_params.get("redirect_uri").unwrap();
    expect(&redirect_url).to(equal("http://0.0.0.0:8000"));

    let code_challenge = auth_url_params.get("code_challenge").unwrap();

    let mut token_req = http_client.last_request().unwrap();

    // base64("id:secret") = "aWQ6c2VjcmV0"
    expect(token_req.header("Authorization").unwrap()).to(equal("Basic aWQ6c2VjcmV0"));

    let token_req_body = block_on(token_req.body_string()).unwrap();
    let token_req_map: HashMap<String, String> =
        serde_urlencoded::from_str(token_req_body.as_str()).unwrap();
    expect(&token_req_map.get("code").unwrap()).to(equal("the-auth-code"));
    expect(&token_req_map.get("grant_type").unwrap()).to(equal("authorization_code"));
    expect(&token_req_map.get("redirect_uri").unwrap()).to(equal(redirect_url));

    let code_verifier = token_req_map.get("code_verifier").unwrap();
    expect(&code_challenge).to(equal(&sha256(code_verifier)));

    let cached_token = cache.get("token").unwrap();
    expect(&cached_token.access_token()).to(equal(&"ACCESS_TOKEN".to_string()));
    expect(&cached_token.refresh_token()).to(equal(&Some("REFRESH_TOKEN".to_string())));
    expect(&cached_token.is_expired()).to(equal(false));
}

#[async_std::test]
async fn when_the_token_is_cached_and_not_expired_it_returns_it() {
    let credentials = oauth::Credentials::new(String::new(), String::new());
    let authenticator = mock::Authenticator::new(String::new());
    let http_client = mock::HttpClient::new();
    let token = oauth::Token::new("CACHED_ACCESS_TOKEN".to_string(), None, 1);
    let cache = mock::Cache::new(HashMap::from([("token".to_string(), token.clone())]));

    let client = oauth::Client::new(credentials, &http_client, &authenticator, &cache);

    expect(&client.get_access_token().await.unwrap()).to(equal("CACHED_ACCESS_TOKEN".to_string()));

    expect(&authenticator.last_auth_url()).to(be_none());
    expect(&http_client.last_request()).to(be_none());
    expect(&cache.get("token").unwrap()).to(equal(token));
}

#[async_std::test]
async fn when_the_token_is_cached_but_expired_and_refreshable_it_refreshes_it_and_saves_it() {
    let credentials = oauth::Credentials::new("id".to_string(), "secret".to_string());

    let authenticator = mock::Authenticator::new("the-auth-code".to_string());
    let http_client = mock::HttpClient::new();
    let token = oauth::Token::new(
        "CACHED_ACCESS_TOKEN".to_string(),
        Some("CACHED_REFRESH_TOKEN".to_string()),
        0,
    );
    let cache = mock::Cache::new(HashMap::from([("token".to_string(), token.clone())]));

    let client = oauth::Client::new(credentials, &http_client, &authenticator, &cache);

    expect(&client.get_access_token().await.unwrap()).to(equal("ACCESS_TOKEN".to_string()));

    let mut token_req = http_client.last_request().unwrap();

    // base64("id:secret") = "aWQ6c2VjcmV0"
    expect(token_req.header("Authorization").unwrap()).to(equal("Basic aWQ6c2VjcmV0"));

    let token_req_body = block_on(token_req.body_string()).unwrap();
    let token_req_map: HashMap<String, String> =
        serde_urlencoded::from_str(token_req_body.as_str()).unwrap();
    expect(&token_req_map.get("grant_type").unwrap()).to(equal("refresh_token"));
    expect(&token_req_map.get("refresh_token").unwrap())
        .to(equal(&"CACHED_REFRESH_TOKEN".to_string()));

    let cached_token = cache.get("token").unwrap();
    expect(&cached_token.access_token()).to(equal(&"ACCESS_TOKEN".to_string()));
    expect(&cached_token.refresh_token()).to(equal(&Some("REFRESH_TOKEN".to_string())));
    expect(&cached_token.is_expired()).to(equal(false));
}

fn sha256(data: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    base64::encode_config(hash, base64::URL_SAFE_NO_PAD)
}
