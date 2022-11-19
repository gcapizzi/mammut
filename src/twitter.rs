use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

const BASE_URL: &str = "https://api.twitter.com/2/";

pub struct Client<'a, C> {
    http_client: &'a C,
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

#[derive(Debug, Deserialize)]
pub struct Tweets {
    #[serde(default)]
    data: Vec<Tweet>,
    #[serde(default)]
    errors: Vec<Error>,
}

impl<'a, C: crate::http::Client> Client<'a, C> {
    pub fn new(http_client: &'a C) -> Client<'a, C> {
        Client { http_client }
    }

    pub fn get_tweets<T: AsRef<str>>(&self, ids: &[T]) -> Result<Tweets> {
        let mut url = url::Url::parse(BASE_URL)?.join("tweets")?;
        let ids_str: String =
            itertools::Itertools::intersperse(ids.iter().map(|s| s.as_ref()), ",").collect();
        url.query_pairs_mut().append_pair("ids", &ids_str);
        let req = http::Request::get(url.to_string()).body("")?;

        let resp = self.http_client.send(req)?;
        let status = resp.status();
        let body = resp.into_body();

        if status.is_success() {
            serde_json::from_reader(body).map_err(|e| anyhow!(e))
        } else {
            Err(anyhow!("{}: {}", status, read(body)?))
        }
    }
}

fn read(mut reader: impl std::io::Read) -> Result<String> {
    let mut str = String::new();
    reader.read_to_string(&mut str)?;
    Ok(str)
}

#[cfg(test)]
mod tests {
    use crate::{http, twitter::*};
    use expect::{
        expect,
        matchers::{
            collection::{be_empty, contain},
            equal,
            result::be_err,
        },
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
        let client = Client::new(&http_client);

        let tweets = client.get_tweets(&["foo", "bar"]).unwrap();

        expect(&tweets.data.len()).to(equal(2));
        expect(&tweets.data).to(contain(Tweet {
            id: "id-foo".to_string(),
            text: "foo".to_string(),
        }));
        expect(&tweets.data).to(contain(Tweet {
            id: "id-bar".to_string(),
            text: "bar".to_string(),
        }));
        expect(&tweets.errors).to(be_empty());

        let reqs = http_client.requests();
        let tweets_req = reqs.last().unwrap();

        expect(&tweets_req.method()).to(equal("GET"));
        expect(&tweets_req.uri()).to(equal(
            format!("{}{}", BASE_URL, "tweets?ids=foo%2Cbar").as_str(),
        ));
    }

    #[test]
    fn when_the_response_contains_errors_it_returns_them() {
        let http_client = http::mock::Client::new([::http::Response::builder()
            .status(200)
            .body(
                r#"{
                    "data": [
                        { "id": "id-foo", "text": "foo" },
                        { "id": "id-bar", "text": "bar" }
                    ],
                    "errors": [
                        { "type": "about:blank", "title": "foo-error", "detail": "foo-detail" },
                        { "type": "about:blank", "title": "bar-error", "detail": "bar-detail" }
                    ]
                }"#
                .to_string(),
            )
            .unwrap()]);
        let client = Client::new(&http_client);

        let tweets = client.get_tweets(&["foo"]).unwrap();

        expect(&tweets.data.len()).to(equal(2));
        expect(&tweets.errors.len()).to(equal(2));
        expect(&tweets.errors).to(contain(Error {
            r#type: "about:blank".to_string(),
            title: "foo-error".to_string(),
            detail: "foo-detail".to_string(),
        }));
        expect(&tweets.errors).to(contain(Error {
            r#type: "about:blank".to_string(),
            title: "bar-error".to_string(),
            detail: "bar-detail".to_string(),
        }));
    }

    #[test]
    fn when_the_request_fails_it_returns_an_error() {
        let http_client = http::mock::Client::new([::http::Response::builder()
            .status(400)
            .body("boom".to_string())
            .unwrap()]);
        let client = Client::new(&http_client);

        let error = client.get_tweets(&["foo"]);

        expect(&error).to(be_err());
        expect(&error.unwrap_err().to_string()).to(equal("400 Bad Request: boom"));
    }

    #[test]
    fn when_the_request_cant_be_made_it_returns_an_error() {
        let http_client = http::mock::Client::new([]);
        let client = Client::new(&http_client);

        let error = client.get_tweets(&["foo"]);

        expect(&error).to(be_err());
        expect(&error.unwrap_err().to_string()).to(equal("no responses set!"));
    }
}
