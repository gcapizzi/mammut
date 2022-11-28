use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

pub struct Client<'a, C> {
    http_client: &'a C,
    base_url: url::Url,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Status {
    id: String,
    content: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct Error {
    #[serde(rename = "error")]
    title: String,
    #[serde(rename = "error_description")]
    description: String,
}

impl<'a, C: crate::http::Client> Client<'a, C> {
    pub fn new(http_client: &'a C, base_url: url::Url) -> Client<'a, C> {
        Client {
            http_client,
            base_url,
        }
    }

    pub fn get_status<T: AsRef<str> + ?Sized>(&self, id: &T) -> Result<Status> {
        let url = self.base_url.join("/api/v1/statuses/")?.join(id.as_ref())?;
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
    use crate::{http, mastodon::*};
    use expect::{
        expect,
        matchers::{equal, result::be_err},
    };

    #[test]
    fn it_fetches_the_status() {
        let http_client = http::mock::Client::new([::http::Response::builder()
            .status(200)
            .body(r#"{ "id": "id", "content": "content" }"#.to_string())
            .unwrap()]);
        let base_url = url::Url::parse("https://the-base-url").unwrap();
        let client = Client::new(&http_client, base_url);

        let status = client.get_status("id").unwrap();

        expect(&status).to(equal(Status {
            id: "id".to_string(),
            content: "content".to_string(),
        }));

        let reqs = http_client.requests();
        let tweets_req = reqs.last().unwrap();

        expect(&tweets_req.method()).to(equal("GET"));
        expect(&tweets_req.uri()).to(equal("https://the-base-url/api/v1/statuses/id"));
    }

    #[test]
    fn when_the_request_fails_it_returns_an_error() {
        let http_client = http::mock::Client::new([::http::Response::builder()
            .status(400)
            .body("boom".to_string())
            .unwrap()]);
        let base_url = url::Url::parse("https://the-base-url").unwrap();
        let client = Client::new(&http_client, base_url);

        let error = client.get_status("foo");

        expect(&error).to(be_err());
        expect(&error.unwrap_err().to_string()).to(equal("400 Bad Request: boom"));
    }

    #[test]
    fn when_the_request_cant_be_made_it_returns_an_error() {
        let http_client = http::mock::Client::new([]);
        let base_url = url::Url::parse("https://the-base-url").unwrap();
        let client = Client::new(&http_client, base_url);

        let error = client.get_status("foo");

        expect(&error).to(be_err());
        expect(&error.unwrap_err().to_string()).to(equal("no responses set!"));
    }
}
