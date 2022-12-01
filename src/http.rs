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
}

impl Client for UreqClient {
    fn send<T: AsRef<[u8]>>(
        &self,
        req: http::Request<T>,
    ) -> Result<http::Response<Box<dyn std::io::Read>>> {
        let mut ureq_req = ureq::request(req.method().as_str(), &req.uri().to_string());
        for (name, value) in req.headers() {
            ureq_req = ureq_req.set(name.as_str(), value.to_str()?);
        }

        use ureq::OrAnyStatus;
        let ureq_res = ureq_req.send_bytes(req.body().as_ref()).or_any_status()?;

        let mut res = http::Response::builder().status(ureq_res.status());
        for header_name in ureq_res.headers_names() {
            res = res.header(&header_name, ureq_res.header(&header_name).unwrap());
        }
        res.body(ureq_res.into_reader() as Box<dyn std::io::Read>)
            .map_err(|e| anyhow!(e))
    }
}

pub struct AuthenticatedClient<'a, H, O> {
    http_client: &'a H,
    oauth_client: &'a O,
}

impl<'a, H, O> AuthenticatedClient<'a, H, O>
where
    H: crate::http::Client,
    O: crate::oauth::Client,
{
    pub fn new(http_client: &'a H, oauth_client: &'a O) -> AuthenticatedClient<'a, H, O> {
        AuthenticatedClient {
            http_client,
            oauth_client,
        }
    }

    fn send_req_with_token<T: AsRef<[u8]>>(
        &self,
        token: String,
        req: &::http::Request<T>,
    ) -> Result<http::Response<Box<dyn std::io::Read>>> {
        let mut new_req_builder = ::http::Request::builder()
            .method(req.method())
            .uri(req.uri())
            .version(req.version())
            .header(
                ::http::header::AUTHORIZATION,
                ::http::HeaderValue::from_maybe_shared(format!("Bearer {}", token))?,
            );
        for (name, value) in req.headers() {
            new_req_builder = new_req_builder.header(name, value);
        }
        let new_req = new_req_builder.body(req.body())?;

        self.http_client.send(new_req)
    }
}

impl<'a, H, O> Client for AuthenticatedClient<'a, H, O>
where
    H: crate::http::Client,
    O: crate::oauth::Client,
{
    fn send<T: AsRef<[u8]>>(
        &self,
        req: ::http::Request<T>,
    ) -> Result<http::Response<Box<dyn std::io::Read>>> {
        self.send_req_with_token(self.oauth_client.get_access_token()?, &req)
            .and_then(|r| {
                if r.status() == ::http::StatusCode::UNAUTHORIZED {
                    self.send_req_with_token(self.oauth_client.refresh_access_token()?, &req)
                } else {
                    Ok(r)
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::http::Client;
    use ::http::{header, Request, Response, StatusCode, Version};
    use expect::{
        expect,
        matchers::{equal, option::equal_some},
    };

    #[test]
    fn http_client_returns_the_status_code() {
        let client = crate::http::UreqClient::new();
        let response = client
            .send(
                Request::get("https://httpbin.org/status/418")
                    .body("")
                    .unwrap(),
            )
            .unwrap();

        expect(&response.status()).to(equal(StatusCode::IM_A_TEAPOT));
    }

    #[test]
    fn http_client_builds_a_request_and_returns_a_response() {
        let client = crate::http::UreqClient::new();
        let response = client
            .send(
                Request::post("https://httpbin.org/post?foo=bar")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body("foo=1&bar=2")
                    .unwrap(),
            )
            .unwrap();

        expect(&response.headers()["Content-Type"]).to(equal("application/json"));

        let body: serde_json::Value = serde_json::from_reader(response.into_body()).unwrap();
        if let serde_json::Value::Object(body_map) = body {
            expect(body_map.get("args").unwrap()).to(equal(serde_json::json!({"foo": "bar"})));
            expect(body_map.get("form").unwrap())
                .to(equal(serde_json::json!({"foo": "1", "bar": "2"})));

            let headers = body_map.get("headers").unwrap();
            if let serde_json::Value::Object(headers_map) = headers {
                expect(headers_map.get("Content-Type").unwrap())
                    .to(equal("application/x-www-form-urlencoded"));
            } else {
                panic!("{}", headers)
            };
        } else {
            panic!("{}", body);
        }
    }

    #[test]
    fn authenticated_client_uses_the_oauth_client_to_authenticate_requests() {
        let http_client = crate::http::mock::Client::new([Response::builder()
            .status(StatusCode::OK)
            .body("the-response-body".to_string())
            .unwrap()]);
        let oauth_client = crate::oauth::client::mock::Client::new(Ok("the-token".to_string()));
        let authenticated_client =
            crate::http::AuthenticatedClient::new(&http_client, &oauth_client);

        let resp = authenticated_client
            .send(
                Request::get("/the-path")
                    .version(Version::HTTP_2)
                    .header(header::USER_AGENT, "the-user-agent")
                    .header(header::AUTHORIZATION, "the-wrong-auth")
                    .body("the-request-body".to_string())
                    .unwrap(),
            )
            .unwrap();

        expect(&resp.status()).to(equal(StatusCode::OK));

        let mut body = resp.into_body();
        let mut body_str = String::new();
        body.read_to_string(&mut body_str).unwrap();
        expect(&body_str).to(equal("the-response-body"));

        let reqs = http_client.requests();
        let req = reqs.last().unwrap();

        expect(&req.method()).to(equal("GET"));
        expect(&req.uri()).to(equal("/the-path"));
        expect(&req.headers().get(header::USER_AGENT)).to(equal_some("the-user-agent"));
        expect(&req.headers().get(header::AUTHORIZATION)).to(equal_some("Bearer the-token"));
        expect(&req.version()).to(equal(Version::HTTP_2));
    }

    #[test]
    fn authenticated_client_refreshes_the_token_on_401s() {
        let http_client = crate::http::mock::Client::new([
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(String::new())
                .unwrap(),
            Response::builder()
                .status(StatusCode::OK)
                .body("the-body".to_string())
                .unwrap(),
        ]);
        let oauth_client = crate::oauth::client::mock::Client::new(Ok("the-token".to_string()));
        let authenticated_client =
            crate::http::AuthenticatedClient::new(&http_client, &oauth_client);

        let resp = authenticated_client
            .send(
                Request::get("/the-path")
                    .version(Version::HTTP_2)
                    .header(header::USER_AGENT, "the-user-agent")
                    .body(String::new())
                    .unwrap(),
            )
            .unwrap();

        expect(&resp.status()).to(equal(StatusCode::OK));

        let reqs = http_client.requests();
        let req = reqs.last().unwrap();

        expect(&req.method()).to(equal("GET"));
        expect(&req.uri()).to(equal("/the-path"));
        expect(&req.headers().get(header::AUTHORIZATION))
            .to(equal_some("Bearer the-token-REFRESHED"));
        expect(&req.headers().get(header::USER_AGENT)).to(equal_some("the-user-agent"));
        expect(&req.version()).to(equal(Version::HTTP_2));
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
