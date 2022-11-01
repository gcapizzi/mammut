const BASE_URL: &str = "https://api.twitter.com/2/";

pub struct Client<'a, C> {
    http_client: &'a C,
    token: String,
}

impl<'a, C: http_client::HttpClient> Client<'a, C> {
    pub fn new(http_client: &'a C, token: String) -> Client<'a, C> {
        Client { http_client, token }
    }

    pub async fn tweets(
        &self,
        ids: impl IntoIterator<Item = String>,
    ) -> Result<String, http_types::Error> {
        let mut url = url::Url::parse(BASE_URL)?.join("tweets")?;
        let ids_str = &ids.into_iter().collect::<Vec<String>>().join(",");
        url.query_pairs_mut().append_pair("ids", ids_str);
        let mut req = http_types::Request::get(url);
        req.append_header("Authorization", format!("Bearer {}", self.token));
        let mut resp = self.http_client.send(req).await?;
        resp.body_string().await
    }
}

#[cfg(test)]
mod tests {
    use crate::{http, twitter::*};
    use expect::{expect, matchers::equal};

    #[async_std::test]
    async fn it_fetches_the_tweets() {
        let http_client = http::mock::HttpClient::new([http::mock::HttpResponse {
            status: 200,
            body: "the-body".to_string(),
        }]);
        let client = Client::new(&http_client, "the-token".to_string());

        let out = client
            .tweets(vec!["foo".to_string(), "bar".to_string()])
            .await
            .unwrap();

        expect(&out).to(equal("the-body".to_string()));

        let reqs = http_client.requests();
        let tweets_req = reqs.last().unwrap();

        expect(&tweets_req.method).to(equal("GET"));
        expect(&tweets_req.url).to(equal(format!("{}{}", BASE_URL, "tweets?ids=foo%2Cbar")));
        expect(tweets_req.headers.get("authorization").unwrap()).to(equal("Bearer the-token"));
    }
}
