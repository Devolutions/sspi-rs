use sspi::{credssp, AuthIdentity};
use sspi::network_client::{NetworkClient, NetworkClientFactory};
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone)]
struct DummyNetworkClientFactory;

impl NetworkClientFactory for DummyNetworkClientFactory {
    fn network_client(&self) -> Box<dyn NetworkClient> {
        unimplemented!()
    }

    fn box_clone(&self) -> Box<dyn NetworkClientFactory> {
        Box::new(Clone::clone(self))
    }
}

#[wasm_bindgen]
pub fn credssp_client() {
    let mut cred_ssp_client = credssp::CredSspClient::new(
        Vec::new(),
        AuthIdentity::default(),
        credssp::CredSspMode::WithCredentials,
        credssp::ClientMode::Negotiate(sspi::NegotiateConfig {
            protocol_config: Box::new(sspi::ntlm::NtlmConfig::default()),
            package_list: None,
            hostname: "testhostname".into(),
            network_client_factory: Box::new(DummyNetworkClientFactory),
        }),
        String::new(),
    )
    .unwrap();

    let next_ts_request = credssp::TsRequest::default();

    let result = cred_ssp_client.process(next_ts_request).unwrap();

    std::hint::black_box(result);
}
