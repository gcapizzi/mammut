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

impl<'a, C: crate::http::Client> Client<'a, C> {
    pub fn new(http_client: &'a C, token: String) -> Client<'a, C> {
        Client { http_client, token }
    }

    pub fn get_tweets<T: AsRef<str>>(&self, ids: &[T]) -> Result<Vec<Tweet>> {
        let mut url = url::Url::parse(BASE_URL)?.join("tweets")?;
        let ids_str: String =
            itertools::Itertools::intersperse(ids.iter().map(|s| s.as_ref()), ",").collect();
        url.query_pairs_mut().append_pair("ids", &ids_str);
        let body = self.get(url)?;
        let response: TweetsResponse = serde_json::from_str(&body).map_err(|e| anyhow!(e))?;

        let errors = response.errors.unwrap_or(Vec::new());
        if errors.is_empty() {
            Ok(response.data.unwrap_or(Vec::new()))
        } else {
            Err(anyhow!(serde_json::to_string_pretty(&errors)?))
        }
    }

    fn get(&self, url: url::Url) -> Result<String> {
        let req = http::Request::get(url.to_string())
            .header("Authorization", format!("Bearer {}", self.token))
            .body("")?;
        let mut resp = self.http_client.send(req)?;
        let mut body = String::new();
        resp.body_mut().read_to_string(&mut body)?;
        if resp.status().is_success() {
            Ok(body)
        } else {
            Err(anyhow!("{}: {}", resp.status(), body))
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

    #[test]
    fn it_fetches_the_tweets() {
        let http_client = http::mock::Client::new([::http::Response::builder()
            .status(200)
            .body(
                r#"{
                    "data": [
                        { "id": "id-foo", "text": "foo" },
                        { "id": "id-bar", "text": "bar" }
                    ]
                }"#
                .to_string(),
            )
            .unwrap()]);
        let client = Client::new(&http_client, "the-token".to_string());

        let tweets = client.get_tweets(&["foo", "bar"]).unwrap();

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

        expect(&tweets_req.method()).to(equal("GET"));
        expect(&tweets_req.uri()).to(equal(
            format!("{}{}", BASE_URL, "tweets?ids=foo%2Cbar").as_str(),
        ));
        expect(tweets_req.headers().get("authorization").unwrap()).to(equal("Bearer the-token"));
    }

    #[test]
    fn when_the_response_contains_errors_it_returns_them() {
        let http_client = http::mock::Client::new([::http::Response::builder()
            .status(200)
            .body(
                r#"{
                    "errors": [
                        { "type": "about:blank", "title": "foo-error", "detail": "foo-detail" },
                        { "type": "about:blank", "title": "bar-error", "detail": "bar-detail" }
                    ]
                }"#
                .to_string(),
            )
            .unwrap()]);
        let client = Client::new(&http_client, String::new());

        let error = client.get_tweets(&["foo"]);
        expect(&error).to(be_err());

        let error_str = &error.unwrap_err().to_string();
        expect(error_str).to(match_regex("about:blank"));
        expect(error_str).to(match_regex("foo-error"));
        expect(error_str).to(match_regex("foo-detail"));
        expect(error_str).to(match_regex("bar-error"));
        expect(error_str).to(match_regex("bar-detail"));
    }

    #[test]
    fn when_the_request_fails_it_returns_an_error() {
        let http_client = http::mock::Client::new([::http::Response::builder()
            .status(400)
            .body("boom".to_string())
            .unwrap()]);
        let client = Client::new(&http_client, String::new());

        let error = client.get_tweets(&["foo"]);

        expect(&error).to(be_err());
        expect(&error.unwrap_err().to_string()).to(equal("400 Bad Request: boom"));
    }

    #[test]
    fn when_the_request_cant_be_made_it_returns_an_error() {
        let http_client = http::mock::Client::new([]);
        let client = Client::new(&http_client, String::new());

        let error = client.get_tweets(&["foo"]);

        expect(&error).to(be_err());
        expect(&error.unwrap_err().to_string()).to(equal("no responses set!"));
    }
}
