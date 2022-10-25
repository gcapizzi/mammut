use async_trait::async_trait;

#[derive(Debug)]
pub struct AuthenticatedClient<C> {
    token: String,
    client: C,
}

impl<C> AuthenticatedClient<C> {
    pub fn new(client: C, token: String) -> AuthenticatedClient<C> {
        AuthenticatedClient { client, token }
    }
}

#[async_trait]
impl<C: http_client::HttpClient> http_client::HttpClient for AuthenticatedClient<C> {
    async fn send(
        &self,
        request: http_types::Request,
    ) -> Result<http_types::Response, http_types::Error> {
        let bearer_token = format!("Bearer {}", self.token);
        let mut req: http_types::Request = request.into();
        req.append_header("Authorization", bearer_token.as_str());
        self.client.send(req).await
    }
}

#[cfg(test)]
pub mod mock;
