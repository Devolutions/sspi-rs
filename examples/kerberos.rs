use std::error::Error;

use base64::Engine;
use proptest::char::any;
use reqwest::header::{
    ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, USER_AGENT,
    WWW_AUTHENTICATE,
};
use reqwest::StatusCode;
use sspi::{
    AcquireCredentialsHandleResult, BufferType, ClientRequestFlags, CredentialsBuffers, DataRepresentation,
    EncryptionFlags, InitializeSecurityContextResult, Kerberos, KerberosConfig, SecurityBuffer, SecurityBufferRef,
    SecurityStatus, Sspi, SspiImpl, Username,
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
    let output_token = loop {
        tracing::info!(?input_token, "step input token");
        let (output_token, status) = step(
            &mut kerberos,
            &mut acq_creds_handle_result.credentials_handle,
            &input_token,
            &hostname,
        );
        tracing::info!(?output_token, ?status, "step result");
        if status == SecurityStatus::ContinueNeeded || status == SecurityStatus::Ok {
            let (token_from_server, status_code) =
                process_authentication(&output_token, &mut client, &auth_method, &hostname)?;

            if status == SecurityStatus::Ok {
                tracing::info!(?token_from_server, "Authentication completed successfully");
                break output_token;
            }

            input_token = token_from_server;
        } else {
            panic!("Having problem continue authentication");
        }
    };

    tracing::info!(?output_token, "Authentication completed successfully");

    let mut request = std::fs::read("./soap.xml")?;

    let mut token = vec![0u8; kerberos.query_context_sizes()?.security_trailer as usize];
    let mut buffers = vec![
        SecurityBufferRef::data_buf(&mut request),
        SecurityBufferRef::token_buf(&mut token),
    ];

    let sec_status = kerberos.encrypt_message(EncryptionFlags::empty(), &mut buffers, 0)?;

    tracing::info!(?sec_status, "Encrypting message");

    // send_http(&hostname, &mut client, None, Some());

    Ok(())
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
        .execute(kerberos)
        .expect("AcquireCredentialsHandle resulted in error");
    acq_creds_handle_result
}

pub(crate) fn process_authentication(
    token_neeeds_to_be_sent: &String,
    client: &mut reqwest::blocking::Client,
    auth_method: &str,
    hostname: &str,
) -> Result<(String, StatusCode), Box<dyn std::error::Error + Send + Sync>> {
    let auth = format!("{} {}", auth_method, token_neeeds_to_be_sent);
    let server_result = send_http(hostname, client, Some(auth), None)?;

    let www_authenticate = server_result
        .headers()
        .get(WWW_AUTHENTICATE)
        .ok_or("expecting www-authentication header from server but not found")?;

    tracing::info!(?www_authenticate, "WWW-Authenticate header from server");

    let server_token = www_authenticate
        .to_str()
        .unwrap()
        .split_once(" ")
        .ok_or("expecting www-authentication header from server but not found")
        .unwrap()
        .1
        .to_owned();
    tracing::info!(?server_token, "Server token");

    Ok((server_token, server_result.status()))
}

pub(crate) fn send_http(
    hostname: &str,
    client: &mut reqwest::blocking::Client,
    authorization: Option<String>,
    body: Option<String>,
) -> Result<reqwest::blocking::Response, Box<dyn Error + Send + Sync>> {
    let builder = client
        .post(format!("http://{}:5985/wsman?PSVersion=7.3.8", hostname))
        .header(HOST, format!("{}:5985", hostname))
        .header(CONNECTION, "keep-alive")
        .header(CONTENT_LENGTH, "0")
        .header(
            USER_AGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
        )
        .header(ACCEPT, "*/*")
        .header(ACCEPT_ENCODING, "gzip, deflate")
        .header(ACCEPT_LANGUAGE, "en-US,en;q=0.9");

    let builder = if let Some(auth) = authorization {
        builder.header(AUTHORIZATION, auth)
    } else {
        builder
    };

    let resp = if let Some(body) = body {
        builder.header(CONTENT_LENGTH, body.len().to_string()).body(body)
    } else {
        builder
    }
    .send()?;

    Ok(resp)
}

fn step_helper(
    kerberos: &mut Kerberos,
    cred_handle: &mut <Kerberos as SspiImpl>::CredentialsHandle,
    input_buffer: &mut [SecurityBuffer],
    output_buffer: &mut [SecurityBuffer],
    hostname: &str,
) -> Result<InitializeSecurityContextResult, Box<dyn std::error::Error>> {
    let target_name = format!("HTTP/{}", hostname);
    let mut builder = kerberos
        .initialize_security_context()
        .with_credentials_handle(cred_handle)
        .with_context_requirements(ClientRequestFlags::INTEGRITY | ClientRequestFlags::CONFIDENTIALITY)
        .with_target_data_representation(DataRepresentation::Native)
        .with_target_name(&target_name)
        .with_input(input_buffer)
        .with_output(output_buffer);

    let result = kerberos
        .initialize_security_context_impl(&mut builder)?
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
    let mut secure_input_buffer = vec![SecurityBuffer::new(input_buffer, BufferType::Token)];
    let mut secure_output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    match step_helper(
        kerberos,
        cred_handle,
        &mut secure_input_buffer,
        &mut secure_output_buffer,
        hostname,
    ) {
        Ok(result) => {
            let output_buffer = secure_output_buffer[0].to_owned();
            (
                base64::engine::general_purpose::STANDARD.encode(output_buffer.buffer),
                result.status,
            )
        }
        Err(e) => {
            panic!("Error in step: {}", e);
        }
    }
}
