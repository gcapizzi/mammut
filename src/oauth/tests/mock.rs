use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::collections::HashMap;

#[derive(Debug)]
pub struct HttpClient {
    req: std::sync::Mutex<Option<http_types::Request>>,
}

impl HttpClient {
    pub fn new() -> HttpClient {
        HttpClient {
            req: std::sync::Mutex::new(None),
        }
    }

    pub fn last_request(&self) -> Option<http_types::Request> {
        let mut req = self.req.lock().unwrap().clone()?;
        req.set_body(self.req.lock().unwrap().as_mut()?.take_body());
        Some(req)
    }
}

#[async_trait]
impl http_client::HttpClient for HttpClient {
    async fn send(
        &self,
        mut request: http_types::Request,
    ) -> Result<http_types::Response, http_types::Error> {
        let mut req = request.clone();
        req.set_body(request.take_body());
        *self.req.lock().unwrap() = Some(req);

        let mut resp = http_types::Response::new(200);
        resp.set_body(
            "{
                    \"token_type\": \"bearer\",
                    \"expires_in\": 1,
                    \"access_token\": \"ACCESS_TOKEN\",
                    \"refresh_token\": \"REFRESH_TOKEN\",
                    \"scope\": \"SCOPE\"
            }",
        );
        Ok(resp)
    }
}

pub struct Authenticator {
    code: String,
    auth_url: std::sync::Mutex<Option<url::Url>>,
}

impl Authenticator {
    pub fn new(code: String) -> Authenticator {
        Authenticator {
            code,
            auth_url: std::sync::Mutex::new(None),
        }
    }

    pub fn last_auth_url(&self) -> Option<url::Url> {
        self.auth_url.lock().unwrap().clone()
    }
}

#[async_trait]
impl crate::oauth::Authenticator for Authenticator {
    async fn authenticate_user(&self, auth_url: &url::Url) -> Result<url::Url> {
        *self.auth_url.lock().unwrap() = Some(auth_url.clone());

        let auth_url_params: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();
        let state = auth_url_params.get("state").ok_or(anyhow!("no `state`"))?;
        let redirect_uri = auth_url_params
            .get("redirect_uri")
            .ok_or(anyhow!("no `redirect_uri`"))?;
        url::Url::parse_with_params(
            redirect_uri.as_str(),
            &[("code", self.code.clone()), ("state", state.to_string())],
        )
        .map_err(|e| anyhow!(e))
    }
}

pub struct TokenCache {
    value: std::sync::Mutex<Option<crate::oauth::Token>>,
}

impl TokenCache {
    pub fn empty() -> TokenCache {
        TokenCache {
            value: std::sync::Mutex::new(None),
        }
    }

    pub fn with_value(value: crate::oauth::Token) -> TokenCache {
        TokenCache {
            value: std::sync::Mutex::new(Some(value)),
        }
    }
}

impl crate::oauth::TokenCache for TokenCache {
    fn get(&self) -> Result<crate::oauth::Token> {
        let token = self.value.lock().unwrap();
        token.clone().ok_or(anyhow!("no token"))
    }

    fn set(&self, value: &crate::oauth::Token) -> Result<()> {
        let mut token = self.value.lock().unwrap();
        *token = Some(value.clone());
        Ok(())
    }
}
