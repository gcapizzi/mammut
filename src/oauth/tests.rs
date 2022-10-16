mod mock;

use crate::cache::Cache;
use crate::oauth;
use expect::{expect, matchers::equal};
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

    let cached_token = cache.get(oauth::CACHE_KEY).unwrap();
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
