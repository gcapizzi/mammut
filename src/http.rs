use crate::oauth;

pub struct AuthenticatedClient {
    session: oauth::Session,
    client: surf::Client,
}

impl AuthenticatedClient {
    pub fn new(session: oauth::Session) -> AuthenticatedClient {
        AuthenticatedClient {
            session,
            client: surf::Client::new(),
        }
    }

    pub async fn send(
        &self,
        request: impl Into<http_types::Request>,
    ) -> Result<http_types::Response, http_types::Error> {
        let bearer_token = format!("Bearer {}", self.session.token());
        let mut req: http_types::Request = request.into();
        req.append_header("Authorization", bearer_token.as_str());
        self.client
            .send(req)
            .await
            .map(|r| r.into())
            .map_err(|e| e.into())
    }
}
