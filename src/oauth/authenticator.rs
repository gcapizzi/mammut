use anyhow::{anyhow, Result};
use std::collections::HashMap;

pub trait Authenticator {
    fn authenticate_user(&self, auth_url: &url::Url) -> Result<url::Url>;
}

pub struct StdAuthenticator {}

impl StdAuthenticator {
    pub fn new() -> StdAuthenticator {
        StdAuthenticator {}
    }
}

impl Authenticator for StdAuthenticator {
    fn authenticate_user(&self, auth_url: &url::Url) -> Result<url::Url> {
        use std::io::{BufRead, Write};

        println!("{}", &auth_url);

        let auth_url_params: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();
        let redirect_uri = auth_url_params
            .get("redirect_uri")
            .ok_or(anyhow!("no `redirect_uri`"))?;
        let redirect_url = url::Url::parse(redirect_uri)?;
        let addrs = redirect_url.socket_addrs(|| None)?;
        let listener = std::net::TcpListener::bind(&*addrs)?;
        let (mut stream, _) = listener.accept()?;
        let mut buf = std::io::BufReader::new(&stream);
        let mut start_line = String::new();
        buf.read_line(&mut start_line)?;
        let path = start_line.split(" ").nth(1).ok_or(anyhow!("no path"))?;
        stream.write_all("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\ndone!".as_bytes())?;
        Ok(redirect_url.join(path)?)
    }
}

#[cfg(test)]
pub mod mock {
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
}
