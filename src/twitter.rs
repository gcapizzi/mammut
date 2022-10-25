const BASE_URL: &str = "https://api.twitter.com/2/";

pub struct Client<C> {
    http_client: C,
    token: String,
}

impl<C: http_client::HttpClient> Client<C> {
    pub fn new(http_client: C, token: String) -> Client<C> {
        Client { http_client, token }
    }

    pub async fn tweets<const N: usize>(
        &self,
        ids: [&str; N],
    ) -> Result<String, http_types::Error> {
        let mut url = url::Url::parse(BASE_URL)?.join("tweets")?;
        url.query_pairs_mut().append_pair("ids", &ids.join(","));
        let mut req = http_types::Request::get(url);
        req.append_header("Authorization", format!("Bearer {}", self.token));
        let mut resp = self.http_client.send(req).await?;
        resp.body_string().await
    }
}
