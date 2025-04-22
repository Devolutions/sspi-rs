use std::future::Future;
use std::pin::Pin;

use sspi::network_client::reqwest_network_client::ReqwestNetworkClient;
use sspi::network_client::{AsyncNetworkClient, NetworkClient};
use sspi::{NetworkRequest, Result};

#[derive(Debug, Clone, Default)]
pub struct SyncNetworkClient(ReqwestNetworkClient);

impl SyncNetworkClient {
    pub fn new() -> Self {
        Self(ReqwestNetworkClient)
    }
}

impl AsyncNetworkClient for SyncNetworkClient {
    fn send<'a>(&'a mut self, request: &'a NetworkRequest) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + 'a>> {
        Box::pin(async move { self.0.send(request) })
    }
}
