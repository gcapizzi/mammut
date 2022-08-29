use crate::http;

const BASE_URL: &str = "https://api.twitter.com/2/";

pub struct Client {
    http_client: http::AuthenticatedClient,
}

impl Client {
    pub fn new(http_client: http::AuthenticatedClient) -> Client {
        Client { http_client }
    }

    pub async fn tweets<const N: usize>(
        &self,
        ids: [&str; N],
    ) -> Result<String, http_types::Error> {
        let mut url = url::Url::parse(BASE_URL)?.join("tweets")?;
        url.query_pairs_mut().append_pair("ids", &ids.join(","));
        let mut resp = self.http_client.send(http_types::Request::get(url)).await?;
        resp.body_string().await
    }
}
