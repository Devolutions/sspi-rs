use base64::Engine;
use hyper::header::{
    ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, USER_AGENT,
};
use hyper::StatusCode;
use sspi::builders::EmptyInitializeSecurityContext;
use sspi::{
    AcquireCredentialsHandleResult, ClientRequestFlags, CredentialsBuffers, DataRepresentation,
    InitializeSecurityContextResult, KerberosConfig, Negotiate, SecurityBuffer, SecurityBufferType, SecurityStatus,
    Sspi,
};
use sspi::{Kerberos, SspiImpl};
use std::error::Error;
use tracing::debug;
use tracing::info;
const TARGET_NAME: &'static str = "HTTP/your-server-name.your.domain";

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG) // Adjust level as needed
        .init();
    let kdc_url = "kdc.your.domain:88".to_string();
    let client_hostname = whoami::hostname();
    let kerberos_config = KerberosConfig::new(&kdc_url, client_hostname.clone());
    let mut kerberos = Kerberos::new_client_from_config(kerberos_config).unwrap();

    let mut acq_creds_handle_result = get_cred_handle(&mut kerberos);

    let mut input = vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];
    let mut output = vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];

    loop {
        match step(
            &mut kerberos,
            &mut acq_creds_handle_result.credentials_handle,
            &mut input,
            &mut output,
        ) {
            Err(e) => panic!("error steping {:?}", e),
            Ok(result) => {
                let status_code = process_authentication(&mut input, &mut output)?;
                if status_code == StatusCode::OK {
                    info!("connection authenticated");
                    break Ok(());
                }

                if result.status == SecurityStatus::Ok && status_code != StatusCode::OK {
                    panic!("connection authentication failed");
                }
            }
        }
    }
}

fn get_cred_handle(kerberos: &mut Kerberos) -> AcquireCredentialsHandleResult<Option<CredentialsBuffers>> {
    let username = "user@your.domain".to_string();
    let password = "user's_password".to_string();
    let identity = sspi::AuthIdentity {
        username,
        password: password.into(),
        domain: None,
    };
    let acq_creds_handle_result = kerberos
        .acquire_credentials_handle()
        .with_credential_use(sspi::CredentialUse::Outbound)
        .with_auth_data(&identity.into())
        .execute()
        .expect("AcquireCredentialsHandle resulted in error");
    acq_creds_handle_result
}

fn process_authentication(
    input: &mut Vec<SecurityBuffer>,
    output: &mut Vec<SecurityBuffer>,
) -> Result<StatusCode, Box<dyn std::error::Error + Send + Sync>> {
    let output_token_in_binary = &output[0].buffer;
    let base_64_token = base64::engine::general_purpose::STANDARD.encode(output_token_in_binary);
    let server_result = send_http(base_64_token)?;
    debug!("server responde = {:?}", server_result);
    let www_authenticate = server_result
        .headers()
        .get("www-authenticate")
        .ok_or("www-authentication header not found")?;
    let server_token = www_authenticate.to_str().unwrap().replace("Negotiate ", "");
    if server_token.len() <= 5 {
        panic!("server token not found");
    }
    let decoded_new_token = base64::engine::general_purpose::STANDARD.decode(server_token).unwrap();
    clear(input);
    clear(output);
    input[0].buffer = decoded_new_token;

    Ok(server_result.status())
}

fn clear(buf: &mut Vec<SecurityBuffer>) {
    buf[0].buffer.clear();
}

fn send_http(negotiate_token: String) -> Result<reqwest::blocking::Response, Box<dyn Error + Send + Sync>> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post("http://your-server-name.your.domain:5985/wsman")
        .header(AUTHORIZATION, format!("Negotiate {}", negotiate_token))
        .header(HOST, "our-server-name.your.domain:5985")
        .header(CONNECTION, "keep-alive")
        .header(CONTENT_LENGTH, "0")
        .header(
            USER_AGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
        )
        .header(ACCEPT, "*/*")
        .header(ACCEPT_ENCODING, "gzip, deflate")
        .header(ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .send()?;

    Ok(resp)
}

fn step(
    kerberos: &mut Kerberos,
    credential_handle: &mut <Kerberos as SspiImpl>::CredentialsHandle,
    input_buffer: &mut Vec<sspi::SecurityBuffer>,
    output_buffer: &mut Vec<sspi::SecurityBuffer>,
) -> Result<InitializeSecurityContextResult, Box<dyn std::error::Error>> {
    output_buffer[0].buffer.clear();
    let mut builder = EmptyInitializeSecurityContext::<<Negotiate as SspiImpl>::CredentialsHandle>::new()
        .with_credentials_handle(credential_handle)
        .with_context_requirements(ClientRequestFlags::MUTUAL_AUTH)
        .with_target_data_representation(DataRepresentation::Native)
        .with_target_name(TARGET_NAME)
        .with_input(input_buffer)
        .with_output(output_buffer);

    let result = kerberos
        .initialize_security_context_impl(&mut builder)
        .resolve_with_default_network_client()?;

    Ok(result)
}
