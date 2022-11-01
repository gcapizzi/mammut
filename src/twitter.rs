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
