use picky_asn1_x509::enveloped_data::{ContentEncryptionAlgorithmIdentifier, KeyEncryptionAlgorithmIdentifier};
use picky_asn1_x509::{AesMode, AesParameters};
use sspi::credssp::SspiContext;
use sspi::{AuthIdentity, Credentials, Kerberos, KerberosConfig, Secret, Username};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::blob::{DpapiBlob, SidProtectionDescriptor};
use crate::crypto::{cek_decrypt, cek_encrypt, cek_generate, content_decrypt, content_encrypt};
use crate::epm::{build_tcpip_tower, EptMap, EptMapResult, Floor, EPM};
use crate::gkdi::{GetKey, GroupKeyEnvelope, ISD_KEY};
use crate::rpc::auth::AuthError;
use crate::rpc::bind::{BindAck, BindTimeFeatureNegotiationBitmask, ContextElement, ContextResultCode};
use crate::rpc::pdu::SecurityTrailer;
use crate::rpc::request::Response;
use crate::rpc::verification::{Command, CommandFlags, CommandPContext, VerificationTrailer};
use crate::rpc::{bind_time_feature_negotiation, AuthProvider, Decode, EncodeExt, RpcClient, NDR, NDR64};
use crate::{Error, Result};

const DEFAULT_RPC_PORT: u16 = 135;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("BindAcknowledge doesn't contain desired context element")]
    MissingDesiredContext,

    #[error("TCP floor is missing in EptMap response")]
    MissingTcpFloor,

    #[error("bad EptMap response status: {0}")]
    BadEptMapStatus(u32),
}

pub type ClientResult<T> = std::result::Result<T, ClientError>;

fn get_epm_contexts() -> Vec<ContextElement> {
    vec![ContextElement {
        context_id: 0,
        abstract_syntax: EPM,
        transfer_syntaxes: vec![NDR64],
    }]
}

fn get_isd_key_key_contexts() -> Vec<ContextElement> {
    vec![
        ContextElement {
            context_id: 0,
            abstract_syntax: ISD_KEY,
            transfer_syntaxes: vec![NDR64],
        },
        ContextElement {
            context_id: 1,
            abstract_syntax: ISD_KEY,
            transfer_syntaxes: vec![bind_time_feature_negotiation(BindTimeFeatureNegotiationBitmask::None)],
        },
    ]
}

fn get_ept_map_isd_key() -> EptMap {
    EptMap {
        obj: None,
        tower: build_tcpip_tower(ISD_KEY, NDR, 135, 0),
        entry_handle: None,
        max_towers: 4,
    }
}

fn get_verification_trailer() -> VerificationTrailer {
    VerificationTrailer {
        commands: vec![Command::Pcontext(CommandPContext {
            flags: CommandFlags::SecVtCommandEnd,
            interface_id: ISD_KEY,
            transfer_syntax: NDR64,
        })],
    }
}

#[instrument(level = "trace", ret)]
fn process_bind_result(requested_contexts: &[ContextElement], bind_ack: BindAck, desired_context: u16) -> Result<()> {
    bind_ack
        .results
        .iter()
        .enumerate()
        .filter_map(|(index, result)| {
            if result.result == ContextResultCode::Acceptance {
                requested_contexts.get(index).map(|ctx| ctx.context_id)
            } else {
                None
            }
        })
        .find(|context_id| *context_id == desired_context)
        .ok_or(ClientError::MissingDesiredContext)?;

    Ok(())
}

#[instrument(level = "trace", ret)]
fn process_ept_map_result(response: &Response) -> Result<u16> {
    let map_response = EptMapResult::decode(response.stub_data.as_slice())?;

    if map_response.status != 0 {
        Err(ClientError::BadEptMapStatus(map_response.status))?;
    }

    for tower in map_response.towers {
        for floor in tower {
            if let Floor::Tcp(tcp_floor) = floor {
                return Ok(tcp_floor.port);
            }
        }
    }

    Err(Error::from(ClientError::MissingTcpFloor))
}

#[instrument(level = "trace", ret)]
fn process_get_key_result(response: &Response, security_trailer: Option<SecurityTrailer>) -> Result<GroupKeyEnvelope> {
    let pad_length = response.stub_data.len()
        - security_trailer
            .as_ref()
            .map(|sec_trailer| usize::from(sec_trailer.pad_length))
            .unwrap_or_default();
    trace!(pad_length);

    let data = &response.stub_data[..pad_length];

    GetKey::unpack_response(data)
}

#[instrument(ret)]
fn decrypt_blob(blob: &DpapiBlob, key: &GroupKeyEnvelope) -> Result<Vec<u8>> {
    let kek = key.get_kek(&blob.key_identifier)?;

    // With the kek we can unwrap the encrypted cek in the LAPS payload.
    let cek = cek_decrypt(&blob.enc_cek_algorithm_id, &kek, &blob.enc_cek)?;

    // With the cek we can decrypt the encrypted content in the LAPS payload.
    Ok(content_decrypt(
        &blob.enc_content_algorithm_id,
        &cek,
        &blob.enc_content,
    )?)
}

#[instrument(ret)]
fn encrypt_blob(
    data: &[u8],
    key: &GroupKeyEnvelope,
    protection_descriptor: SidProtectionDescriptor,
) -> Result<Vec<u8>> {
    let enc_cek_algorithm_id = KeyEncryptionAlgorithmIdentifier::new_aes256_empty(AesMode::Wrap);
    let (cek, iv) = cek_generate(&enc_cek_algorithm_id)?;

    let enc_content_algorithm_id =
        ContentEncryptionAlgorithmIdentifier::new_aes256(AesMode::Gcm, AesParameters::InitializationVector(iv.into()));

    let enc_content = content_encrypt(&enc_content_algorithm_id, &cek, data)?;

    let (kek, key_identifier) = key.new_kek()?;
    let enc_cek = cek_encrypt(&enc_cek_algorithm_id, &kek, &cek)?;

    let mut buf = Vec::new();

    DpapiBlob {
        key_identifier,
        protection_descriptor,
        enc_cek,
        enc_cek_algorithm_id,
        enc_content,
        enc_content_algorithm_id,
    }
    .encode(true, &mut buf)?;

    Ok(buf)
}

struct GetKeyArgs<'server, 'username> {
    server: &'server str,
    target_sd: Vec<u8>,
    root_key_id: Option<Uuid>,
    l0: i32,
    l1: i32,
    l2: i32,
    username: &'username str,
    password: Secret<String>,
    kerberos_config: KerberosConfig,
}

#[instrument(level = "trace", ret)]
fn get_key(
    GetKeyArgs {
        server,
        target_sd,
        root_key_id,
        l0,
        l1,
        l2,
        username,
        password,
        kerberos_config,
    }: GetKeyArgs,
) -> Result<GroupKeyEnvelope> {
    let username = Username::parse(username).expect("correct username");

    let isd_key_port = {
        let mut rpc = RpcClient::connect(
            (server, DEFAULT_RPC_PORT),
            AuthProvider::new(
                SspiContext::Kerberos(
                    Kerberos::new_client_from_config(kerberos_config.clone()).map_err(AuthError::from)?,
                ),
                Credentials::AuthIdentity(AuthIdentity {
                    username: username.clone(),
                    password: password.clone(),
                }),
                server,
            )?,
        )?;

        info!("RPC connection has been established.");

        let epm_contexts = get_epm_contexts();
        let context_id = epm_contexts[0].context_id;
        let bind_ack = rpc.bind(&epm_contexts)?;

        info!("RPC bind/bind_ack finished successfully.");

        process_bind_result(&epm_contexts, bind_ack, context_id)?;

        let ept_map = get_ept_map_isd_key();
        let response = rpc.request(0, EptMap::OPNUM, ept_map.encode_to_vec()?)?;
        process_ept_map_result(&response.try_into_response()?)?
    };

    info!(isd_key_port);

    let mut rpc = RpcClient::connect(
        (server, isd_key_port),
        AuthProvider::new(
            SspiContext::Kerberos(Kerberos::new_client_from_config(kerberos_config).map_err(AuthError::from)?),
            Credentials::AuthIdentity(AuthIdentity { username, password }),
            server,
        )?,
    )?;

    info!("RPC connection has been established.");

    let isd_key_contexts = get_isd_key_key_contexts();
    let context_id = isd_key_contexts[0].context_id;
    let bind_ack = rpc.bind_authenticate(&isd_key_contexts)?;

    info!("RPC bind/bind_ack finished successfully.");

    process_bind_result(&isd_key_contexts, bind_ack, context_id)?;

    let get_key = GetKey {
        target_sd,
        root_key_id,
        l0_key_id: l0,
        l1_key_id: l1,
        l2_key_id: l2,
    };

    let response_pdu = rpc.authenticated_request(
        context_id,
        GetKey::OPNUM,
        get_key.encode_to_vec()?,
        Some(get_verification_trailer()),
    )?;
    let security_trailer = response_pdu.security_trailer.clone();

    info!("RPC GetKey Request finished successfully!");

    process_get_key_result(&response_pdu.try_into_response()?, security_trailer)
}

fn try_get_kerberos_config(
    server: &str,
    client_computer_name: Option<String>,
) -> Result<KerberosConfig> {
    let kdc_url = if let Ok(kdc_url) = std::env::var("SSPI_KDC_URL") {
        kdc_url
    } else {
        format!("tcp://{}:88", server)
    };

    let client_computer_name = if let Some(name) = client_computer_name {
        name
    } else {
        whoami::fallible::hostname()?
    };

    Ok(KerberosConfig {
        kdc_url: Some(Url::parse(&kdc_url).map_err(|error| Error::InvalidUrl {
            name: "KDC",
            url: kdc_url,
            error,
        })?),
        client_computer_name: Some(client_computer_name),
    })
}

/// Decrypt the DPAPI blob.
///
/// This function simulated the `NCryptUnprotectSecret` function. Decryption requires making RPC calls to the domain.
/// The username can be specified in FQDN (DOMAIN\username) or UPN (username@domain) format.
/// _Note_: `server` value should be target domain server hostname. Do not use IP address here.
///
/// MSDN:
/// * [NCryptUnprotectSecret function (ncryptprotect.h)](https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptunprotectsecret).
pub fn n_crypt_unprotect_secret(
    blob: &[u8],
    server: &str,
    username: &str,
    password: Secret<String>,
    client_computer_name: Option<String>,
) -> Result<Vec<u8>> {
    let dpapi_blob = DpapiBlob::decode(blob)?;
    let target_sd = dpapi_blob.protection_descriptor.get_target_sd()?;

    let root_key = get_key(GetKeyArgs {
        server,
        target_sd,
        root_key_id: Some(dpapi_blob.key_identifier.root_key_identifier),
        l0: dpapi_blob.key_identifier.l0,
        l1: dpapi_blob.key_identifier.l1,
        l2: dpapi_blob.key_identifier.l2,
        username,
        password,
        kerberos_config: try_get_kerberos_config(server, client_computer_name)?,
    })?;

    info!("Successfully requested root key.");

    decrypt_blob(&dpapi_blob, &root_key)
}

/// Encrypts data to a specified protection descriptor.
///
/// This function simulated the `NCryptProtectSecret` function. Encryption requires making RPCs call to the domain.
/// The username can be specified in FQDN (DOMAIN\username) or UPN (username@domain) format.
/// _Note_: `server` value should be target domain server hostname. Do not use IP address here.
///
/// MSDN:
/// * [NCryptProtectSecret function (`ncryptprotect.h`)](https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptprotectsecret).
pub fn n_crypt_protect_secret(
    data: &[u8],
    sid: String,
    root_key_id: Option<Uuid>,
    server: &str,
    username: &str,
    password: Secret<String>,
    client_computer_name: Option<String>,
) -> Result<Vec<u8>> {
    let l0 = -1;
    let l1 = -1;
    let l2 = -1;

    let descriptor = SidProtectionDescriptor { sid };
    let target_sd = descriptor.get_target_sd()?;

    let root_key = get_key(GetKeyArgs {
        server,
        target_sd,
        root_key_id,
        l0,
        l1,
        l2,
        username,
        password,
        kerberos_config: try_get_kerberos_config(server, client_computer_name)?,
    })?;

    info!("Successfully requested root key.");

    encrypt_blob(data, &root_key, descriptor)
}
