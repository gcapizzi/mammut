use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

const BASE_URL: &str = "https://api.twitter.com/2/";

pub struct Client<'a, C> {
    http_client: &'a C,
    token: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Tweet {
    id: String,
    text: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct Error {
    r#type: String,
    title: String,
    detail: String,
}

#[derive(Deserialize)]
struct TweetsResponse {
    data: Option<Vec<Tweet>>,
    errors: Option<Vec<Error>>,
}

impl<'a, C: http_client::HttpClient> Client<'a, C> {
    pub fn new(http_client: &'a C, token: String) -> Client<'a, C> {
        Client { http_client, token }
    }

    pub async fn get_tweets(&self, ids: impl IntoIterator<Item = String>) -> Result<Vec<Tweet>> {
        let mut url = url::Url::parse(BASE_URL)?.join("tweets")?;
        let ids_str = &ids.into_iter().collect::<Vec<String>>().join(",");
        url.query_pairs_mut().append_pair("ids", ids_str);
        let body = self.get(url).await?;
        let response: TweetsResponse = serde_json::from_str(&body).map_err(|e| anyhow!(e))?;

        let errors = response.errors.unwrap_or(Vec::new());
        if errors.is_empty() {
            Ok(response.data.unwrap_or(Vec::new()))
        } else {
            Err(anyhow!(serde_json::to_string_pretty(&errors)?))
        }
    }

    async fn get(&self, url: url::Url) -> Result<String> {
        let mut req = http_types::Request::get(url);
        req.append_header("Authorization", format!("Bearer {}", self.token));
        let mut resp = self.http_client.send(req).await.map_err(|e| anyhow!(e))?;
        let body = resp.body_string().await.map_err(|e| anyhow!(e))?;
        if resp.status().is_success() {
            Ok(body)
        } else {
            Err(anyhow!(
                "{} {}: {}",
                resp.status(),
                resp.status().canonical_reason(),
                body
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{http, twitter::*};
    use expect::{
        expect,
        matchers::{collection::contain, equal, result::be_err, string::match_regex},
    };

    #[async_std::test]
    async fn it_fetches_the_tweets() {
        let http_client = http::mock::HttpClient::new([http::mock::HttpResponse {
            status: 200,
            body: r#"{
                "data": [
                    { "id": "id-foo", "text": "foo" },
                    { "id": "id-bar", "text": "bar" }
                ]
            }"#
            .to_string(),
        }]);
        let client = Client::new(&http_client, "the-token".to_string());

        let tweets = client
            .get_tweets(vec!["foo".to_string(), "bar".to_string()])
            .await
            .unwrap();

        expect(&tweets.len()).to(equal(2));
        expect(&tweets).to(contain(Tweet {
            id: "id-foo".to_string(),
            text: "foo".to_string(),
        }));
        expect(&tweets).to(contain(Tweet {
            id: "id-bar".to_string(),
            text: "bar".to_string(),
        }));

        let reqs = http_client.requests();
        let tweets_req = reqs.last().unwrap();

        expect(&tweets_req.method).to(equal("GET"));
        expect(&tweets_req.url).to(equal(format!("{}{}", BASE_URL, "tweets?ids=foo%2Cbar")));
        expect(tweets_req.headers.get("authorization").unwrap()).to(equal("Bearer the-token"));
    }

    #[async_std::test]
    async fn when_the_response_contains_errors_it_returns_them() {
        let http_client = http::mock::HttpClient::new([http::mock::HttpResponse {
            status: 200,
            body: r#"{
                "errors": [
                    { "type": "about:blank", "title": "foo-error", "detail": "foo-detail" },
                    { "type": "about:blank", "title": "bar-error", "detail": "bar-detail" }
                ]
            }"#
            .to_string(),
        }]);
        let client = Client::new(&http_client, String::new());

        let error = client.get_tweets(vec!["foo".to_string()]).await;
        expect(&error).to(be_err());

        let error_str = &error.unwrap_err().to_string();
        expect(error_str).to(match_regex("about:blank"));
        expect(error_str).to(match_regex("foo-error"));
        expect(error_str).to(match_regex("foo-detail"));
        expect(error_str).to(match_regex("bar-error"));
        expect(error_str).to(match_regex("bar-detail"));
    }

    #[async_std::test]
    async fn when_the_request_fails_it_returns_an_error() {
        let http_client = http::mock::HttpClient::new([]);
        let client = Client::new(&http_client, "the-token".to_string());

        let error = client.get_tweets(vec!["foo".to_string()]).await;

        expect(&error).to(be_err());
        expect(&error.unwrap_err().to_string()).to(equal("no responses set!"));
    }
}
