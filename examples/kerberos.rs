use base64::Engine;
use hyper::header::{
    ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, USER_AGENT,
};
use hyper::StatusCode;
use sspi::builders::EmptyInitializeSecurityContext;
use sspi::{
    AcquireCredentialsHandleResult, ClientRequestFlags, CredentialsBuffers, DataRepresentation,
    InitializeSecurityContextResult, KerberosConfig, SecurityBuffer, SecurityBufferType, SecurityStatus, Sspi,
};
use sspi::{Kerberos, SspiImpl};
use std::error::Error;

static KDC_URL: &'static str = "tcp://computer_name.domain:88";
static HOSTNAME: &'static str = "computer_name.domain";
static USERNAME: &'static str = "user@domain";
static PASSWORD: &'static str = "Passoword";
static AUTH_METHOD: &'static str = "Negotiate"; // Negotiate or Kerberos

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let kerberos_config = KerberosConfig::new(&KDC_URL, HOSTNAME.to_string());
    let mut kerberos = Kerberos::new_client_from_config(kerberos_config).unwrap();

    let mut acq_creds_handle_result = get_cred_handle(&mut kerberos);

    let mut input_token = String::new();
    let mut client = reqwest::blocking::Client::new(); // super IMPORTANT, KEEP-ALIVE the http connection!
    loop {
        let (output_token, status) = step(
            &mut kerberos,
            &mut acq_creds_handle_result.credentials_handle,
            &input_token,
        );
        if status == SecurityStatus::ContinueNeeded || status == SecurityStatus::Ok {
            let (token_from_server, status_code) = process_authentication(&output_token, &mut client)?;
            if status_code == hyper::StatusCode::OK {
                println!("authenticated");
                break Ok(());
            }
            input_token = token_from_server;
        } else {
            panic!("Having problem continue authentication");
        }
    }
}

pub(crate) fn get_cred_handle(kerberos: &mut Kerberos) -> AcquireCredentialsHandleResult<Option<CredentialsBuffers>> {
    let identity = sspi::AuthIdentity {
        username: crate::USERNAME.to_string(),
        password: crate::PASSWORD.to_string().into(),
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

pub(crate) fn process_authentication(
    token_neeeds_to_be_sent: &String,
    client: &mut reqwest::blocking::Client,
) -> Result<(String, StatusCode), Box<dyn std::error::Error + Send + Sync>> {
    let server_result = send_http(token_neeeds_to_be_sent, client)?;
    if server_result.status() == StatusCode::OK {
        return Ok((String::new(), StatusCode::OK));
    }
    let www_authenticate = server_result
        .headers()
        .get("www-authenticate")
        .ok_or("expecting www-authentication header from server but not found")?;
    let server_token = www_authenticate
        .to_str()
        .unwrap()
        .replace(format!("{} ", AUTH_METHOD).as_str(), "");
    Ok((server_token, server_result.status()))
}

pub(crate) fn send_http(
    negotiate_token: &String,
    client: &mut reqwest::blocking::Client,
) -> Result<reqwest::blocking::Response, Box<dyn Error + Send + Sync>> {
    let resp = client
        .post(format!("http://{}:5985/wsman?PSVersion=7.3.8", HOSTNAME))
        .header(AUTHORIZATION, format!("{} {}", AUTH_METHOD, negotiate_token))
        .header(HOST, format!("{}:5985", HOSTNAME))
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

fn step_helper(
    kerberos: &mut Kerberos,
    cred_handle: &mut <Kerberos as SspiImpl>::CredentialsHandle,
    input_buffer: &mut Vec<sspi::SecurityBuffer>,
    output_buffer: &mut Vec<sspi::SecurityBuffer>,
) -> Result<InitializeSecurityContextResult, Box<dyn std::error::Error>> {
    let target_name = format!("HTTP/{}", crate::HOSTNAME);
    let mut builder = EmptyInitializeSecurityContext::<<Kerberos as SspiImpl>::CredentialsHandle>::new()
        .with_credentials_handle(cred_handle)
        .with_context_requirements(ClientRequestFlags::MUTUAL_AUTH)
        .with_target_data_representation(DataRepresentation::Native)
        .with_target_name(&target_name)
        .with_input(input_buffer)
        .with_output(output_buffer);

    let result = kerberos
        .initialize_security_context_impl(&mut builder)
        .resolve_with_default_network_client()?;
    Ok(result)
}

pub fn step(
    kerberos: &mut Kerberos,
    cred_handle: &mut <Kerberos as SspiImpl>::CredentialsHandle,
    input_token: &String,
) -> (String, SecurityStatus) {
    let input_buffer = base64::engine::general_purpose::STANDARD.decode(input_token).unwrap();
    let mut secure_input_buffer = vec![SecurityBuffer::new(input_buffer, SecurityBufferType::Token)];
    let mut secure_output_buffer = vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];
    match step_helper(
        kerberos,
        cred_handle,
        &mut secure_input_buffer,
        &mut secure_output_buffer,
    ) {
        Ok(result) => {
            let output_buffer = secure_output_buffer[0].to_owned();
            let res = (
                base64::engine::general_purpose::STANDARD.encode(output_buffer.buffer),
                result.status,
            );
            res
        }
        Err(_) => {
            panic!("error steping");
        }
    }
}
