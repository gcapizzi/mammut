const BASE_URL: &str = "https://api.twitter.com/2/";

pub struct Client<C> {
    http_client: C,
}

impl<C: http_client::HttpClient> Client<C> {
    pub fn new(http_client: C) -> Client<C> {
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
