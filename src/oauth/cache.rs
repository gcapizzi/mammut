use crate::oauth::Token;

use anyhow::Result;

const CACHE_KEY: &str = "token";

pub trait TokenCache {
    fn set(&self, value: &Token) -> Result<()>;
    fn get(&self) -> Result<Token>;
}

pub struct XDGTokenCache {
    prefix: String,
}

impl XDGTokenCache {
    pub fn new(prefix: String) -> XDGTokenCache {
        XDGTokenCache { prefix }
    }
}

impl TokenCache for XDGTokenCache {
    fn get(&self) -> Result<Token> {
        let path = xdg::BaseDirectories::with_prefix(&self.prefix)?.get_cache_file(CACHE_KEY);
        let value_file = std::fs::File::open(path)?;
        Ok(serde_json::from_reader(&value_file)?)
    }

    fn set(&self, value: &Token) -> Result<()> {
        let path = xdg::BaseDirectories::with_prefix(&self.prefix)?.place_cache_file(CACHE_KEY)?;
        let value_file = std::fs::File::create(path)?;
        serde_json::to_writer(&value_file, &value)?;
        Ok(())
    }
}

#[cfg(test)]
pub mod mock {
    use crate::oauth;
    use anyhow::{anyhow, Result};

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
}
