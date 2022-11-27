pub mod authenticator;
pub mod cache;
pub mod client;

pub use crate::oauth::authenticator::{Authenticator, StdAuthenticator};
pub use crate::oauth::cache::{TokenCache, XDGTokenCache};
pub use crate::oauth::client::{Client, DefaultClient};

use serde::{Deserialize, Serialize};

#[derive(PartialEq, Debug, Deserialize, Serialize, Clone)]
pub struct Token {
    access_token: String,
    refresh_token: Option<String>,
    created_at: std::time::SystemTime,
    expires_in: Option<u64>,
}

impl Token {
    fn new(access_token: String, refresh_token: Option<String>, expires_in: Option<u64>) -> Token {
        Token {
            access_token,
            refresh_token,
            created_at: std::time::SystemTime::now(),
            expires_in,
        }
    }

    fn access_token(&self) -> &String {
        &self.access_token
    }

    fn refresh_token(&self) -> &Option<String> {
        &self.refresh_token
    }

    fn expires_at(&self) -> Option<std::time::SystemTime> {
        self.expires_in
            .map(|s| self.created_at + std::time::Duration::from_secs(s))
    }

    fn is_expired(&self) -> bool {
        self.expires_at()
            .map(|t| t <= std::time::SystemTime::now())
            .unwrap_or(false)
    }
}

pub struct Config<'a> {
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub auth_url: &'a str,
    pub token_url: &'a str,
    pub redirect_url: &'a str,
}
