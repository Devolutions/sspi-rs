use sspi::ntlm::NtlmConfig;
use sspi::{credssp, Credentials};
use wasm_bindgen::prelude::*;


#[wasm_bindgen]
pub fn credssp_client() {
    let mut cred_ssp_client = credssp::CredSspClient::new(
        Vec::new(),
        Credentials::AuthIdentity(Default::default()),
        credssp::CredSspMode::WithCredentials,
        credssp::ClientMode::Negotiate(sspi::NegotiateConfig {
            protocol_config: Box::<NtlmConfig>::default(),
            package_list: None,
            hostname: "testhostname".into(),
        }),
        String::new(),
    )
    .unwrap();

    let next_ts_request = credssp::TsRequest::default();

    let result = cred_ssp_client.process(next_ts_request).unwrap();

    std::hint::black_box(result);
}
