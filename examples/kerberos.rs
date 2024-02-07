use std::error::Error;

use base64::Engine;
use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, USER_AGENT,
    WWW_AUTHENTICATE,
};
use reqwest::StatusCode;
use sspi::builders::EmptyInitializeSecurityContext;
use sspi::{
    AcquireCredentialsHandleResult, ClientRequestFlags, CredentialsBuffers, DataRepresentation,
    InitializeSecurityContextResult, Kerberos, KerberosConfig, SecurityBuffer, SecurityBufferType, SecurityStatus,
    Sspi, SspiImpl, Username,
};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let kdc_url = std::env::var("SSPI_KDC_URL").expect("missing KDC URL set in SSPI_KDC_URL"); //tcp://ad-compter-name.domain:88
    let hostname = std::env::var("SSPI_WINRM_HOST").expect("missing host name set in SSPI_WINRM_HOST"); // winrm_server_name.domain
    let username = std::env::var("SSPI_WINRM_USER").expect("missing username set in SSPI_WINRM_USER"); // username@domain
    let password = std::env::var("SSPI_WINRM_PASS").expect("missing password set in SSPI_WINRM_PASS");
    let auth_method = std::env::var("SSPI_WINRM_AUTH").expect("missing auth METHOD set in SSPI_WINRM_AUTH"); // Negotiate or Kerberos

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_env("SSPI_LOG_LEVEL"))
        .init();

    let kerberos_config = KerberosConfig::new(&kdc_url, hostname.clone());
    let mut kerberos = Kerberos::new_client_from_config(kerberos_config).unwrap();

    let mut acq_creds_handle_result = get_cred_handle(&mut kerberos, username, password);

    let mut input_token = String::new();
    let mut client = reqwest::blocking::Client::new(); // super IMPORTANT, KEEP-ALIVE the http connection!
    loop {
        let (output_token, status) = step(
            &mut kerberos,
            &mut acq_creds_handle_result.credentials_handle,
            &input_token,
            &hostname,
        );
        if status == SecurityStatus::ContinueNeeded || status == SecurityStatus::Ok {
            let (token_from_server, status_code) =
                process_authentication(&output_token, &mut client, &auth_method, &hostname)?;
            if status_code == reqwest::StatusCode::OK {
                println!("authenticated");
                break Ok(());
            }
            input_token = token_from_server;
        } else {
            panic!("Having problem continue authentication");
        }
    }
}

pub(crate) fn get_cred_handle(
    kerberos: &mut Kerberos,
    username: String,
    password: String,
) -> AcquireCredentialsHandleResult<Option<CredentialsBuffers>> {
    let identity = sspi::AuthIdentity {
        username: Username::parse(&username).expect("username is not in the correct format"),
        password: password.into(),
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
    auth_method: &str,
    hostname: &str,
) -> Result<(String, StatusCode), Box<dyn std::error::Error + Send + Sync>> {
    let server_result = send_http(token_neeeds_to_be_sent, client, hostname, auth_method)?;
    if server_result.status() == StatusCode::OK {
        return Ok((String::new(), StatusCode::OK));
    }
    let www_authenticate = server_result
        .headers()
        .get(WWW_AUTHENTICATE)
        .ok_or("expecting www-authentication header from server but not found")?;
    let server_token = www_authenticate
        .to_str()
        .unwrap()
        .replace(format!("{} ", auth_method).as_str(), "");
    Ok((server_token, server_result.status()))
}

pub(crate) fn send_http(
    negotiate_token: &String,
    client: &mut reqwest::blocking::Client,
    hostname: &str,
    auth_method: &str,
) -> Result<reqwest::blocking::Response, Box<dyn Error + Send + Sync>> {
    let resp = client
        .post(format!("http://{}:5985/wsman?PSVersion=7.3.8", hostname))
        .header(AUTHORIZATION, format!("{} {}", auth_method, negotiate_token))
        .header(HOST, format!("{}:5985", hostname))
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
    hostname: &str,
) -> Result<InitializeSecurityContextResult, Box<dyn std::error::Error>> {
    let target_name = format!("HTTP/{}", hostname);
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
    hostname: &str,
) -> (String, SecurityStatus) {
    let input_buffer = base64::engine::general_purpose::STANDARD.decode(input_token).unwrap();
    let mut secure_input_buffer = vec![SecurityBuffer::new(input_buffer, SecurityBufferType::Token)];
    let mut secure_output_buffer = vec![SecurityBuffer::new(Vec::new(), SecurityBufferType::Token)];
    match step_helper(
        kerberos,
        cred_handle,
        &mut secure_input_buffer,
        &mut secure_output_buffer,
        hostname,
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
            panic!("error stepping");
        }
    }
}
