use crate::oauth;

pub struct AuthenticatedClient {
    session: oauth::Session,
}

impl AuthenticatedClient {
    pub fn new(session: oauth::Session) -> AuthenticatedClient {
        AuthenticatedClient { session }
    }

    pub fn get(&self, url: &url::Url) -> Result<String, anyhow::Error> {
        let bearer_token = format!("Bearer {}", self.session.token());
        let response_body = ureq::request_url("GET", url)
            .set("Authorization", bearer_token.as_str())
            .call()?
            .into_string()?;
        Ok(response_body)
    }
}
