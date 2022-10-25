use anyhow::anyhow;
use async_trait::async_trait;
use futures::executor::block_on;
use std::collections::{HashMap, VecDeque};

#[derive(Debug)]
pub struct HttpClient {
    requests: std::sync::Mutex<Vec<HttpRequest>>,
    responses: std::sync::Mutex<VecDeque<HttpResponse>>,
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

impl HttpClient {
    pub fn new<const N: usize>(resps: [HttpResponse; N]) -> HttpClient {
        HttpClient {
            requests: std::sync::Mutex::new(Vec::new()),
            responses: std::sync::Mutex::new(VecDeque::from(resps)),
        }
    }

    pub fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().unwrap().to_vec()
    }
}

impl From<HttpResponse> for http_types::Response {
    fn from(r: HttpResponse) -> http_types::Response {
        let mut resp = http_types::Response::new(r.status);
        resp.set_body(r.body);
        resp
    }
}

#[async_trait]
impl http_client::HttpClient for HttpClient {
    async fn send(
        &self,
        mut request: http_types::Request,
    ) -> Result<http_types::Response, http_types::Error> {
        let body = block_on(request.body_string()).unwrap();
        let body_map: HashMap<String, String> = serde_urlencoded::from_str(&body).unwrap();
        self.requests.lock().unwrap().push(HttpRequest {
            method: request.method().to_string(),
            url: request.url().origin().unicode_serialization(),
            headers: request
                .into_iter()
                .map(|(n, v)| (n.to_string(), v.last().to_string()))
                .collect(),
            body: body_map,
        });

        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .map(|r| r.into())
            .ok_or(http_types::Error::new(500, anyhow!("no responses set!")))
    }
}
