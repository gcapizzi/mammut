use async_trait::async_trait;

#[async_trait]
pub trait Receiver {
    async fn receive(
        &self,
        address: async_std::net::SocketAddr,
    ) -> Result<http_types::Request, http_types::Error>;
}

pub struct AsyncH1Receiver {}

impl AsyncH1Receiver {
    pub fn new() -> AsyncH1Receiver {
        AsyncH1Receiver {}
    }
}

#[async_trait]
impl Receiver for AsyncH1Receiver {
    async fn receive(
        &self,
        address: async_std::net::SocketAddr,
    ) -> Result<http_types::Request, http_types::Error> {
        let listener = async_std::net::TcpListener::bind(address).await?;
        let (mut stream, _) = listener.accept().await?;
        let (request, _) = async_h1::server::decode(stream.clone()).await?.unwrap();
        let mut response = http_types::Response::new(http_types::StatusCode::Ok);
        response.set_body("done!");
        let mut response_encoder = async_h1::server::Encoder::new(response, request.method());
        async_std::io::copy(&mut response_encoder, &mut stream).await?;
        Ok(request)
    }
}

#[derive(Debug)]
pub struct AuthenticatedClient<C> {
    token: String,
    client: C,
}

impl<C> AuthenticatedClient<C> {
    pub fn new(client: C, token: String) -> AuthenticatedClient<C> {
        AuthenticatedClient { client, token }
    }
}

#[async_trait]
impl<C: http_client::HttpClient> http_client::HttpClient for AuthenticatedClient<C> {
    async fn send(
        &self,
        request: http_types::Request,
    ) -> Result<http_types::Response, http_types::Error> {
        let bearer_token = format!("Bearer {}", self.token);
        let mut req: http_types::Request = request.into();
        req.append_header("Authorization", bearer_token.as_str());
        self.client.send(req).await
    }
}
