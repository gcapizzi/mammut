use crate::oauth;
use anyhow::{anyhow, Result};
use std::collections::HashMap;

pub struct Authenticator {
    code: String,
    auth_url: std::cell::RefCell<Option<url::Url>>,
}

impl Authenticator {
    pub fn new(code: String) -> Authenticator {
        Authenticator {
            code,
            auth_url: std::cell::RefCell::new(None),
        }
    }

    pub fn last_auth_url(&self) -> Option<url::Url> {
        self.auth_url.borrow().clone()
    }
}

impl oauth::Authenticator for Authenticator {
    fn authenticate_user(&self, auth_url: &url::Url) -> Result<url::Url> {
        *self.auth_url.borrow_mut() = Some(auth_url.clone());

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
    value: std::cell::RefCell<Option<oauth::Token>>,
}

impl TokenCache {
    pub fn empty() -> TokenCache {
        TokenCache {
            value: std::cell::RefCell::new(None),
        }
    }

    pub fn with_value(value: oauth::Token) -> TokenCache {
        TokenCache {
            value: std::cell::RefCell::new(Some(value)),
        }
    }
}

impl oauth::TokenCache for TokenCache {
    fn get(&self) -> Result<oauth::Token> {
        self.value.borrow().clone().ok_or(anyhow!("no token"))
    }

    fn set(&self, value: &oauth::Token) -> Result<()> {
        *self.value.borrow_mut() = Some(value.clone());
        Ok(())
    }
}

pub struct Client {
    token: std::cell::RefCell<Result<String, String>>,
}

impl Client {
    pub fn new(token: Result<String, String>) -> Client {
        Client {
            token: std::cell::RefCell::new(token),
        }
    }
}

impl oauth::Client for Client {
    fn get_access_token(&self) -> Result<String> {
        self.token.borrow().clone().map_err(|e| anyhow!(e))
    }

    fn refresh_access_token(&self) -> Result<String> {
        _ = self
            .token
            .replace_with(|t| t.clone().map(|t| format!("{}-REFRESHED", t)));
        self.get_access_token()
    }
}
