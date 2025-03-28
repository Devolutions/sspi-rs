use crate::blob::{DpapiBlob, SidProtectionDescriptor};
use crate::crypto::{cek_decrypt, cek_encrypt, cek_generate, content_decrypt, content_encrypt};
use crate::gkdi::{get_kek, new_kek, unpack_response, ISD_KEY};
use crate::rpc::auth::AuthError;
use crate::rpc::{bind_time_feature_negotiation, AuthProvider, RpcClient, NDR, NDR64};
use crate::{Error, Result, Transport};

use dpapi_core::{decode_owned, EncodeVec};
use dpapi_pdu::gkdi::{GetKey, GroupKeyEnvelope};
use dpapi_pdu::rpc::{
    build_tcpip_tower, BindAck, BindTimeFeatureNegotiationBitmask, Command, CommandFlags, CommandPContext,
    ContextElement, ContextResultCode, EntryHandle, EptMap, EptMapResult, Floor, Response, SecurityTrailer,
    VerificationTrailer, EPM,
};
use picky_asn1_x509::enveloped_data::{ContentEncryptionAlgorithmIdentifier, KeyEncryptionAlgorithmIdentifier};
use picky_asn1_x509::{AesMode, AesParameters};
use sspi::credssp::SspiContext;
use sspi::ntlm::NtlmConfig;
use sspi::{AsyncNetworkClient, AuthIdentity, Credentials, Negotiate, NegotiateConfig, Secret, Username};
use std::fmt::Debug;
use std::net::{SocketAddr, ToSocketAddrs};
use url::Url;
use uuid::Uuid;

const DEFAULT_RPC_PORT: u16 = 135;

pub const WSS_SCHEME: &str = "wss";

pub const WS_SCHEME: &str = "ws";

const TCP_SCHEME: &str = "tcp";

#[derive(Debug, thiserror::Error)]
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
        entry_handle: EntryHandle(None),
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
    let map_response: EptMapResult = decode_owned(response.stub_data.as_slice())?;

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

    unpack_response(data)
}

#[instrument(ret)]
fn decrypt_blob(blob: &DpapiBlob, key: &GroupKeyEnvelope) -> Result<Vec<u8>> {
    let kek = get_kek(key, &blob.key_identifier)?;

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

    let (kek, key_identifier) = new_kek(key)?;
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

#[derive(Debug, PartialEq)]
pub enum WebAppAuth {
    Custom { username: String, password: Secret<String> },
    None,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionUrlParseError {
    #[error("expected a TCP URL and an optional WebSocket URL")]
    IncorrectFormat,

    #[error("{0}")]
    InvalidUrl(&'static str),
}

/// RPC server connection options.
#[derive(Debug, PartialEq)]
pub enum ConnectionOptions {
    /// Regular TCP connection.
    Tcp(SocketAddr),
    /// Tunneled connection via Devolutions Gateway using a WebSocket.
    WebSocketTunnel {
        websocket_url: Url,
        web_app_auth: WebAppAuth,
        destination: SocketAddr,
    },
}

impl ConnectionOptions {
    /// Parses the RPC server connection string.
    /// If the TCP URL does not specify a port, `tcp_server_default_port` is used.
    pub fn parse(destination: &str, proxy_addr: Option<String>, tcp_server_default_port: u16) -> Result<Self> {
        let url_to_socket_addr = |url: &Url| -> Result<SocketAddr> {
            let tcp_host = url
                .host_str()
                .ok_or(ConnectionUrlParseError::InvalidUrl("URL does not contain a host"))?;
            (tcp_host, url.port().unwrap_or(tcp_server_default_port))
                .to_socket_addrs()?
                .next()
                .ok_or(ConnectionUrlParseError::InvalidUrl("cannot resolve the address of the TCP server").into())
        };

        if let Some(proxy_addr) = proxy_addr {
            let mut ws_url = Url::parse(&proxy_addr)?;
            let destination_url = if destination.contains("://") {
                if !destination.contains("tcp") {
                    return Err(ConnectionUrlParseError::IncorrectFormat.into());
                }
                Url::parse(destination)?
            } else {
                Url::parse(&format!("tcp://{}", destination))?
            };

            match (ws_url.scheme(), destination_url.scheme()) {
                (WS_SCHEME | WSS_SCHEME, TCP_SCHEME) => (),
                _ => return Err(ConnectionUrlParseError::IncorrectFormat.into()),
            }

            let web_app_auth = match ws_url.username() {
                "" => WebAppAuth::None,
                username => {
                    let username = username.to_owned();
                    let password = ws_url.password().unwrap_or_default().to_owned();

                    ws_url
                        .set_username("")
                        .expect("URL isn't `cannot-be-a-base`, so it should not fail");
                    ws_url
                        .set_password(None)
                        .expect("URL isn't `cannot-be-a-base`, so it should not fail");

                    WebAppAuth::Custom {
                        username,
                        password: password.into(),
                    }
                }
            };

            Ok(ConnectionOptions::WebSocketTunnel {
                websocket_url: ws_url.to_owned(),
                web_app_auth,
                destination: url_to_socket_addr(&destination_url)?,
            })
        } else {
            let tcp_url = if destination.contains("://") {
                if !destination.contains("tcp") {
                    return Err(ConnectionUrlParseError::IncorrectFormat.into());
                }
                Url::parse(destination)?
            } else {
                Url::parse(&format!("tcp://{}", destination))?
            };
            Ok(ConnectionOptions::Tcp(url_to_socket_addr(&tcp_url)?))
        }
    }

    /// Sets the new port for the TCP server.
    pub fn set_tcp_port(&mut self, new_port: u16) {
        match self {
            Self::Tcp(addr) => addr.set_port(new_port),
            Self::WebSocketTunnel {
                destination: tcp_addr, ..
            } => tcp_addr.set_port(new_port),
        }
    }
}

struct GetKeyArgs<'server> {
    server: &'server str,
    proxy_addr: Option<String>,
    target_sd: Vec<u8>,
    root_key_id: Option<Uuid>,
    l0: i32,
    l1: i32,
    l2: i32,
    username: Username,
    password: Secret<String>,
    negotiate_config: NegotiateConfig,
}

#[instrument(level = "trace", ret)]
async fn get_key<T: Transport + Debug>(
    GetKeyArgs {
        server,
        proxy_addr,
        target_sd,
        root_key_id,
        l0,
        l1,
        l2,
        username,
        password,
        negotiate_config,
    }: GetKeyArgs<'_>,
    network_client: &mut dyn AsyncNetworkClient,
) -> Result<GroupKeyEnvelope> {
    let mut connection_options = ConnectionOptions::parse(server, proxy_addr, DEFAULT_RPC_PORT)?;

    let isd_key_port = {
        let mut rpc = RpcClient::<T>::connect(
            &connection_options,
            AuthProvider::new(
                SspiContext::Negotiate(Negotiate::new(negotiate_config.clone()).map_err(AuthError::from)?),
                Credentials::AuthIdentity(AuthIdentity {
                    username: username.clone(),
                    password: password.clone(),
                }),
                server,
            )?,
        )
        .await?;

        info!("RPC connection has been established.");

        let epm_contexts = get_epm_contexts();
        let context_id = epm_contexts[0].context_id;
        let bind_ack = rpc.bind(&epm_contexts).await?;

        info!("RPC bind/bind_ack finished successfully.");

        process_bind_result(&epm_contexts, bind_ack, context_id)?;

        let ept_map = get_ept_map_isd_key();
        let response = rpc.request(0, EptMap::OPNUM, ept_map.encode_vec()?).await?;

        process_ept_map_result(&response.try_into_response()?)?
    };

    info!(isd_key_port);

    connection_options.set_tcp_port(isd_key_port);

    let mut rpc = RpcClient::<T>::connect(
        &connection_options,
        AuthProvider::new(
            SspiContext::Negotiate(Negotiate::new(negotiate_config).map_err(AuthError::from)?),
            Credentials::AuthIdentity(AuthIdentity { username, password }),
            server,
        )?,
    )
    .await?;

    info!("RPC connection has been established.");

    let isd_key_contexts = get_isd_key_key_contexts();
    let context_id = isd_key_contexts[0].context_id;
    let bind_ack = rpc.bind_authenticate(&isd_key_contexts, network_client).await?;

    info!("RPC bind/bind_ack finished successfully.");

    process_bind_result(&isd_key_contexts, bind_ack, context_id)?;

    let get_key = GetKey {
        target_sd,
        root_key_id,
        l0_key_id: l0,
        l1_key_id: l1,
        l2_key_id: l2,
    };

    let response_pdu = rpc
        .authenticated_request(
            context_id,
            GetKey::OPNUM,
            get_key.encode_vec()?,
            Some(get_verification_trailer()),
        )
        .await?;
    let security_trailer = response_pdu.security_trailer.clone();

    info!("RPC GetKey Request finished successfully!");

    process_get_key_result(&response_pdu.try_into_response()?, security_trailer)
}

fn try_get_negotiate_config(client_computer_name: Option<String>) -> Result<NegotiateConfig> {
    let client_computer_name = if let Some(name) = client_computer_name {
        name
    } else {
        whoami::fallible::hostname()?
    };

    // `NtlmConfig` is enough. If the KDC is available, the `Negotiate` module will use Kerberos.
    // So, we don't need to do any additional configurations here.
    let protocol_config = Box::new(NtlmConfig {
        client_computer_name: Some(client_computer_name.clone()),
    });

    Ok(NegotiateConfig::from_protocol_config(
        protocol_config,
        client_computer_name,
    ))
}

/// Decrypt the DPAPI blob.
///
/// This function simulated the `NCryptUnprotectSecret` function. Decryption requires making RPC calls to the domain.
/// The username can be specified in FQDN (DOMAIN\username) or UPN (username@domain) format.
/// _Note_: `server` value should be target domain server hostname. Do not use IP address here.
///
/// MSDN:
/// * [NCryptUnprotectSecret function (ncryptprotect.h)](https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptunprotectsecret).
#[instrument(err)]
pub async fn n_crypt_unprotect_secret<T: Transport + Debug>(
    blob: &[u8],
    server: &str,
    proxy_addr: Option<String>,
    username: &str,
    password: Secret<String>,
    client_computer_name: Option<String>,
    network_client: &mut dyn AsyncNetworkClient,
) -> Result<Secret<Vec<u8>>> {
    let dpapi_blob = DpapiBlob::decode(blob)?;
    let target_sd = dpapi_blob.protection_descriptor.get_target_sd()?;
    let username = Username::parse(username)
        .map_err(sspi::Error::from)
        .map_err(AuthError::from)?;

    let root_key = get_key::<T>(
        GetKeyArgs {
            server,
            proxy_addr,
            target_sd,
            root_key_id: Some(dpapi_blob.key_identifier.root_key_identifier),
            l0: dpapi_blob.key_identifier.l0,
            l1: dpapi_blob.key_identifier.l1,
            l2: dpapi_blob.key_identifier.l2,
            username,
            password,
            negotiate_config: try_get_negotiate_config(client_computer_name)?,
        },
        network_client,
    )
    .await?;

    info!("Successfully requested root key.");

    Ok(decrypt_blob(&dpapi_blob, &root_key)?.into())
}

/// Arguments for `n_crypt_protect_secret` function.
pub struct CryptProtectSecretArgs<'a> {
    /// Secret to encrypt.
    pub data: Secret<Vec<u8>>,
    /// User's SID.
    pub sid: String,
    /// Root key id.
    pub root_key_id: Option<Uuid>,
    /// Target server hostname.
    pub server: &'a str,
    /// Websocket proxy address.
    pub proxy_addr: Option<String>,
    /// Username to encrypt the DPAPI blob.
    pub username: &'a str,
    /// User's password.
    pub password: Secret<String>,
    /// Client's computer name.
    pub client_computer_name: Option<String>,
}

/// Encrypts data to a specified protection descriptor.
///
/// This function simulated the `NCryptProtectSecret` function. Encryption requires making RPCs call to the domain.
/// The username can be specified in FQDN (DOMAIN\username) or UPN (username@domain) format.
/// _Note_: `server` value should be target domain server hostname. Do not use IP address here.
///
/// MSDN:
/// * [NCryptProtectSecret function (`ncryptprotect.h`)](https://learn.microsoft.com/en-us/windows/win32/api/ncryptprotect/nf-ncryptprotect-ncryptprotectsecret).
#[instrument(ret)]
pub async fn n_crypt_protect_secret<T: Transport + Debug>(
    CryptProtectSecretArgs {
        data,
        sid,
        root_key_id,
        server,
        proxy_addr,
        username,
        password,
        client_computer_name,
    }: CryptProtectSecretArgs<'_>,
    network_client: &mut dyn AsyncNetworkClient,
) -> Result<Vec<u8>> {
    let l0 = -1;
    let l1 = -1;
    let l2 = -1;

    let descriptor = SidProtectionDescriptor { sid };
    let target_sd = descriptor.get_target_sd()?;
    let username = Username::parse(username)
        .map_err(sspi::Error::from)
        .map_err(AuthError::from)?;

    let root_key = get_key::<T>(
        GetKeyArgs {
            server,
            proxy_addr,
            target_sd,
            root_key_id,
            l0,
            l1,
            l2,
            username,
            password,
            negotiate_config: try_get_negotiate_config(client_computer_name)?,
        },
        network_client,
    )
    .await?;

    info!("Successfully requested root key.");

    encrypt_blob(data.as_ref(), &root_key, descriptor)
}
