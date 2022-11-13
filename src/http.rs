use anyhow::{anyhow, Result};

pub trait Client {
    fn send<T: AsRef<[u8]>>(
        &self,
        req: http::Request<T>,
    ) -> Result<http::Response<Box<dyn std::io::Read>>>;
}

pub struct UreqClient {}

impl UreqClient {
    pub fn new() -> UreqClient {
        UreqClient {}
    }

    fn to_ureq_request<T: AsRef<[u8]>>(req: http::Request<T>) -> Result<ureq::Response> {
        use ureq::OrAnyStatus;
        let mut ureq_req = ureq::request(req.method().as_str(), &req.uri().to_string());
        for (name, value) in req.headers() {
            ureq_req = ureq_req.set(name.as_str(), value.to_str()?);
        }
        ureq_req
            .send_bytes(req.body().as_ref())
            .or_any_status()
            .map_err(|e| anyhow!(e))
    }

    fn from_ureq_response(resp: ureq::Response) -> Result<http::Response<Box<dyn std::io::Read>>> {
        http::Response::builder()
            .status(resp.status())
            .body(resp.into_reader() as Box<dyn std::io::Read>)
            .map_err(|e| anyhow!(e))
    }
}

impl Client for UreqClient {
    fn send<T: AsRef<[u8]>>(
        &self,
        req: http::Request<T>,
    ) -> Result<http::Response<Box<dyn std::io::Read>>> {
        Self::to_ureq_request(req).and_then(Self::from_ureq_response)
    }
}

#[cfg(test)]
mod tests {
    use crate::http::Client;
    use expect::{expect, matchers::equal};

    #[test]
    fn it_returns_the_status_code() {
        let client = crate::http::UreqClient::new();
        let response = client
            .send(
                ::http::Request::get("https://httpbin.org/status/418")
                    .body("")
                    .unwrap(),
            )
            .unwrap();

        expect(&response.status()).to(equal(::http::StatusCode::IM_A_TEAPOT));
    }

    #[test]
    fn it_builds_a_request_and_returns_a_response() {
        let client = crate::http::UreqClient::new();
        let response = client
            .send(
                ::http::Request::post("https://httpbin.org/post?foo=bar")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body("foo=1&bar=2")
                    .unwrap(),
            )
            .unwrap();

        let body: serde_json::Value = serde_json::from_reader(response.into_body()).unwrap();
        if let serde_json::Value::Object(body_map) = body {
            let form_map = body_map.get("form").unwrap();
            expect(form_map).to(equal(serde_json::json!({"foo": "1", "bar": "2"})));
        } else {
            panic!("{}", body);
        }
    }
}

#[cfg(test)]
pub mod mock {
    use anyhow::{anyhow, Result};
    use std::collections::{HashMap, VecDeque};

    #[derive(Debug)]
    pub struct Client {
        requests: std::cell::RefCell<Vec<::http::Request<HashMap<String, String>>>>,
        responses: std::cell::RefCell<VecDeque<::http::Response<String>>>,
    }

    impl Client {
        pub fn new<const N: usize>(resps: [::http::Response<String>; N]) -> Client {
            Client {
                requests: std::cell::RefCell::new(Vec::new()),
                responses: std::cell::RefCell::new(VecDeque::from(resps)),
            }
        }

        pub fn requests(&self) -> std::cell::Ref<Vec<::http::Request<HashMap<String, String>>>> {
            self.requests.borrow()
        }
    }

    impl crate::http::Client for Client {
        fn send<T: AsRef<[u8]>>(
            &self,
            request: http::Request<T>,
        ) -> Result<http::Response<Box<dyn std::io::Read>>> {
            self.requests
                .borrow_mut()
                .push(request.map(|b| serde_urlencoded::from_bytes(b.as_ref()).unwrap()));

            self.responses
                .borrow_mut()
                .pop_front()
                .map(|r| r.map(|b| Box::new(std::io::Cursor::new(b)) as Box<dyn std::io::Read>))
                .ok_or(anyhow!("no responses set!"))
        }
    }
}
