use picky_asn1_x509::enveloped_data::{ContentEncryptionAlgorithmIdentifier, KeyEncryptionAlgorithmIdentifier};
use picky_asn1_x509::{AesAuthEncParams, AesMode, AesParameters};
use sspi::credssp::SspiContext;
use sspi::{AuthIdentity, Credentials, Kerberos, KerberosConfig, Secret, Username};
use url::Url;
use uuid::Uuid;
use thiserror::Error;

use crate::blob::{DpapiBlob, SidProtectionDescriptor};
use crate::crypto::{cek_decrypt, cek_encrypt, cek_generate, content_decrypt, content_encrypt};
use crate::epm::{build_tcpip_tower, EptMap, EptMapResult, Floor, EPM};
use crate::gkdi::{GetKey, GroupKeyEnvelope, ISD_KEY};
use crate::rpc::auth::AuthError;
use crate::rpc::bind::{BindAck, BindTimeFeatureNegotiationBitmask, ContextElement, ContextResultCode};
use crate::rpc::pdu::SecurityTrailer;
use crate::rpc::request::Response;
use crate::rpc::verification::{Command, CommandFlags, CommandPContext, VerificationTrailer};
use crate::rpc::{bind_time_feature_negotiation, AuthProvider, Decode, Encode, RpcClient, NDR, NDR64, EncodeExt};
use crate::{Result, Error};

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

fn process_bind_result(
    requested_contexts: &[ContextElement],
    bind_ack: BindAck,
    desired_context: u16,
) -> Result<()> {
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

fn process_get_key_result(
    response: &Response,
    security_trailer: Option<SecurityTrailer>,
) -> Result<GroupKeyEnvelope> {
    let pad_length = response.stub_data.len()
        - security_trailer
            .as_ref()
            .map(|sec_trailer| usize::from(sec_trailer.pad_length))
            .unwrap_or_default();
    println!("pad_length: {}", pad_length);

    let data = &response.stub_data[..pad_length];

    println!("data to parse: {:?}", data);

    GetKey::unpack_response(data)
}

fn decrypt_blob(blob: &DpapiBlob, key: &GroupKeyEnvelope) -> Result<Vec<u8>> {
    let kek = key.get_kek(&blob.key_identifier)?;

    // With the kek we can unwrap the encrypted cek in the LAPS payload.
    let cek = cek_decrypt(&blob.enc_cek_algorithm_id, &kek, &blob.enc_cek)?;

    // With the cek we can decrypt the encrypted content in the LAPS payload.
    Ok(content_decrypt(&blob.enc_content_algorithm_id, &cek, &blob.enc_content)?)
}

fn encrypt_blob(
    data: &[u8],
    key: &GroupKeyEnvelope,
    protection_descriptor: SidProtectionDescriptor,
) -> Result<Vec<u8>> {
    let enc_cek_algorithm_id = KeyEncryptionAlgorithmIdentifier::new_aes256_empty(AesMode::Wrap);
    let (cek, iv) = cek_generate(&enc_cek_algorithm_id)?;
    println!("cek generated.");

    let enc_content_algorithm_id = ContentEncryptionAlgorithmIdentifier::new_aes256(
        AesMode::Gcm,
        AesParameters::InitializationVector(iv.into()),
    );

    let enc_content = content_encrypt(&enc_content_algorithm_id, &cek, data)?;
    println!("content encrypted");

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

fn get_key(
    server: &str,
    target_sd: Vec<u8>,
    root_key_id: Option<Uuid>,
    l0: i32,
    l1: i32,
    l2: i32,
    username: &str,
    password: String,
    target_host: &str,
) -> Result<GroupKeyEnvelope> {
    let kerberos_config = KerberosConfig {
        kdc_url: Some(Url::parse(server).unwrap()),
        client_computer_name: None,
    };
    let username = Username::parse(username).expect("correct username");
    let password: Secret<String> = password.into();

    let isd_key_port = {
        let mut rpc = RpcClient::connect(
            (server, 135 /* default RPC port */),
            AuthProvider::new(
                SspiContext::Kerberos(Kerberos::new_client_from_config(kerberos_config.clone()).map_err(AuthError::from)?),
                Credentials::AuthIdentity(AuthIdentity {
                    username: username.clone(),
                    password: password.clone(),
                }),
                target_host,
            )?,
        )?;

        let epm_contexts = get_epm_contexts();
        let context_id = epm_contexts[0].context_id;
        let bind_ack = rpc.bind(&epm_contexts)?;
        process_bind_result(&epm_contexts, bind_ack, context_id)?;

        let ept_map = get_ept_map_isd_key();
        let response = rpc.request(0, EptMap::OPNUM, ept_map.encode_to_vec()?)?;
        process_ept_map_result(&response.try_into_response()?)?
    };

    let mut rpc = RpcClient::connect(
        (server, isd_key_port),
        AuthProvider::new(
            SspiContext::Kerberos(Kerberos::new_client_from_config(kerberos_config).map_err(AuthError::from)?),
            Credentials::AuthIdentity(AuthIdentity { username, password }),
            target_host,
        )?,
    )?;

    let isd_key_contexts = get_isd_key_key_contexts();
    let context_id = isd_key_contexts[0].context_id;
    let bind_ack = rpc.bind_authenticate(&isd_key_contexts)?;
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

    println!("I'm here!");

    process_get_key_result(&response_pdu.try_into_response()?, security_trailer)
}

pub fn n_crypt_unprotect_secret(blob: &[u8], server: &str, username: &str, password: String) -> Result<Vec<u8>> {
    let dpapi_blob = DpapiBlob::decode(blob)?;
    let target_sd = dpapi_blob.protection_descriptor.get_target_sd()?;

    let root_key = get_key(
        server,
        target_sd,
        Some(dpapi_blob.key_identifier.root_key_identifier),
        dpapi_blob.key_identifier.l0,
        dpapi_blob.key_identifier.l1,
        dpapi_blob.key_identifier.l2,
        username,
        password,
        "",
    )?;

    decrypt_blob(&dpapi_blob, &root_key)
}

pub fn n_crypt_protect_secret(
    data: &[u8],
    sid: String,
    root_key_identifier: Option<Uuid>,
    server: &str,
    domain_name: &str,
    username: &str,
    password: String,
) -> Result<Vec<u8>> {
    let l0 = -1;
    let l1 = -1;
    let l2 = -1;

    let descriptor = SidProtectionDescriptor { sid };
    let target_sd = descriptor.get_target_sd()?;

    let root_key = get_key(server, target_sd, root_key_identifier, l0, l1, l2, username, password, "")?;

    println!("the root key is here!! starting blob encryption");
    println!("{:?}", root_key);

    encrypt_blob(data, &root_key, descriptor)
}

#[cfg(test)]
mod tests {
    use uuid::uuid;

    use super::*;

    #[test]
    fn test_blob_encryption() {
        let data = b"TheBestTvarynka";
        let root_key = GroupKeyEnvelope {
            flags: 2,
            l0: 363,
            l1: 1,
            l2: 29,
            root_key_identifier: uuid!("883dee05-c4d1-9c40-ae3b-adcd600ded9e"),
            kdf_alg: "SP800_108_CTR_HMAC".to_owned(),
            kdf_parameters: vec![
                0, 0, 0, 0, 1, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 83, 0, 72, 0, 65, 0, 53, 0, 49, 0, 50, 0, 0, 0,
            ],
            secret_algorithm: "DH".to_owned(),
            secret_parameters: vec![
                12, 2, 0, 0, 68, 72, 80, 77, 0, 1, 0, 0, 135, 168, 230, 29, 180, 182, 102, 60, 255, 187, 209, 156, 101,
                25, 89, 153, 140, 238, 246, 8, 102, 13, 208, 242, 93, 44, 238, 212, 67, 94, 59, 0, 224, 13, 248, 241,
                214, 25, 87, 212, 250, 247, 223, 69, 97, 178, 170, 48, 22, 195, 217, 17, 52, 9, 111, 170, 59, 244, 41,
                109, 131, 14, 154, 124, 32, 158, 12, 100, 151, 81, 122, 189, 90, 138, 157, 48, 107, 207, 103, 237, 145,
                249, 230, 114, 91, 71, 88, 192, 34, 224, 177, 239, 66, 117, 191, 123, 108, 91, 252, 17, 212, 95, 144,
                136, 185, 65, 245, 78, 177, 229, 155, 184, 188, 57, 160, 191, 18, 48, 127, 92, 79, 219, 112, 197, 129,
                178, 63, 118, 182, 58, 202, 225, 202, 166, 183, 144, 45, 82, 82, 103, 53, 72, 138, 14, 241, 60, 109,
                154, 81, 191, 164, 171, 58, 216, 52, 119, 150, 82, 77, 142, 246, 161, 103, 181, 164, 24, 37, 217, 103,
                225, 68, 229, 20, 5, 100, 37, 28, 202, 203, 131, 230, 180, 134, 246, 179, 202, 63, 121, 113, 80, 96,
                38, 192, 184, 87, 246, 137, 150, 40, 86, 222, 212, 1, 10, 189, 11, 230, 33, 195, 163, 150, 10, 84, 231,
                16, 195, 117, 242, 99, 117, 215, 1, 65, 3, 164, 181, 67, 48, 193, 152, 175, 18, 97, 22, 210, 39, 110,
                17, 113, 95, 105, 56, 119, 250, 215, 239, 9, 202, 219, 9, 74, 233, 30, 26, 21, 151, 63, 179, 44, 155,
                115, 19, 77, 11, 46, 119, 80, 102, 96, 237, 189, 72, 76, 167, 177, 143, 33, 239, 32, 84, 7, 244, 121,
                58, 26, 11, 161, 37, 16, 219, 193, 80, 119, 190, 70, 63, 255, 79, 237, 74, 172, 11, 181, 85, 190, 58,
                108, 27, 12, 107, 71, 177, 188, 55, 115, 191, 126, 140, 111, 98, 144, 18, 40, 248, 194, 140, 187, 24,
                165, 90, 227, 19, 65, 0, 10, 101, 1, 150, 249, 49, 199, 122, 87, 242, 221, 244, 99, 229, 233, 236, 20,
                75, 119, 125, 230, 42, 170, 184, 168, 98, 138, 195, 118, 210, 130, 214, 237, 56, 100, 230, 121, 130,
                66, 142, 188, 131, 29, 20, 52, 143, 111, 47, 145, 147, 181, 4, 90, 242, 118, 113, 100, 225, 223, 201,
                103, 193, 251, 63, 46, 85, 164, 189, 27, 255, 232, 59, 156, 128, 208, 82, 185, 133, 209, 130, 234, 10,
                219, 42, 59, 115, 19, 211, 254, 20, 200, 72, 75, 30, 5, 37, 136, 185, 183, 210, 187, 210, 223, 1, 97,
                153, 236, 208, 110, 21, 87, 205, 9, 21, 179, 53, 59, 187, 100, 224, 236, 55, 127, 208, 40, 55, 13, 249,
                43, 82, 199, 137, 20, 40, 205, 198, 126, 182, 24, 75, 82, 61, 29, 178, 70, 195, 47, 99, 7, 132, 144,
                240, 14, 248, 214, 71, 209, 72, 212, 121, 84, 81, 94, 35, 39, 207, 239, 152, 197, 130, 102, 75, 76, 15,
                108, 196, 22, 89,
            ],
            private_key_length: 512,
            public_key_length: 2048,
            domain_name: "tbt.com".to_owned(),
            forest_name: "tbt.com".to_owned(),
            l1_key: vec![
                173, 80, 94, 248, 52, 158, 62, 37, 82, 120, 161, 181, 168, 210, 216, 6, 84, 85, 255, 134, 61, 225, 184,
                195, 235, 123, 168, 59, 13, 157, 215, 175, 133, 164, 129, 64, 178, 232, 166, 156, 18, 145, 123, 90,
                210, 248, 220, 223, 210, 108, 161, 159, 112, 41, 48, 44, 147, 172, 229, 34, 86, 44, 237, 121,
            ],
            l2_key: vec![
                185, 223, 10, 79, 180, 88, 169, 151, 13, 50, 5, 135, 168, 128, 151, 22, 60, 148, 47, 247, 62, 143, 220,
                186, 247, 6, 22, 104, 190, 69, 58, 147, 141, 21, 39, 18, 192, 238, 238, 169, 217, 55, 149, 237, 158,
                78, 18, 26, 237, 189, 143, 95, 197, 245, 230, 35, 107, 63, 172, 24, 46, 200, 102, 14,
            ],
        };
        let sid = SidProtectionDescriptor {
            sid: "S-1-5-21-1485435871-894665558-560847465-1104".to_owned(),
        };

        let result = encrypt_blob(data, &root_key, sid).unwrap();

        println!("result: {:?}", result);
    }
}
