use sspi::internal::credssp;
use sspi::ntlm::AuthIdentity;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn credssp_client() {
    let mut cred_ssp_client = credssp::CredSspClient::new(
        Vec::new(),
        AuthIdentity::default(),
        credssp::CredSspMode::WithCredentials,
        credssp::ClientMode::Negotiate(sspi::NegotiateConfig {
            protocol_config: Box::new(sspi::ntlm::NtlmConfig),
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
