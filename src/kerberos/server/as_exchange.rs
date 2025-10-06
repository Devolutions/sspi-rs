use crypto_bigint::rand_core::RngCore;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::Ticket;
use picky_krb::messages::TgtReq;
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::generator::YieldPointLocal;
use crate::kerberos::client::extractors::extract_encryption_params_from_as_rep;
use crate::kerberos::client::generators::{
    generate_as_req_kdc_body, get_client_principal_name_type, get_client_principal_realm, GenerateAsPaDataOptions,
    GenerateAsReqOptions,
};
use crate::kerberos::pa_datas::{AsRepSessionKeyExtractor, AsReqPaDataOptions};
use crate::kerberos::utils::unwrap_hostname;
use crate::kerberos::{client, TGT_SERVICE_NAME};
use crate::utils::utf16_bytes_to_utf8_string;
use crate::{ClientRequestFlags, CredentialsBuffers, Error, ErrorKind, Kerberos, Result};

/// Requests the TGT ticket from KDC.
///
/// Basically, it performs the AS exchange, saves the session key, and returns the ticket.
pub async fn request_tgt(
    server: &mut Kerberos,
    credentials: &CredentialsBuffers,
    tgt_req: &TgtReq,
    yield_point: &mut YieldPointLocal,
) -> Result<Ticket> {
    let service_name = &server
        .server
        .as_ref()
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidHandle,
                "Kerberos server properties are not initialized",
            )
        })?
        .service_name;
    if tgt_req.server_name.0 != *service_name {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!(
                "invalid ticket service name ({:?}): Kerberos server is configured for {:?}",
                tgt_req.server_name.0, service_name
            ),
        ));
    }

    let (username, password, realm, cname_type) = match credentials {
        CredentialsBuffers::AuthIdentity(auth_identity) => {
            let username = utf16_bytes_to_utf8_string(&auth_identity.user);
            let domain = utf16_bytes_to_utf8_string(&auth_identity.domain);
            let password = utf16_bytes_to_utf8_string(auth_identity.password.as_ref());

            let realm = get_client_principal_realm(&username, &domain);
            let cname_type = get_client_principal_name_type(&username, &domain);

            (username, password, realm, cname_type)
        }
        #[cfg(feature = "scard")]
        CredentialsBuffers::SmartCard(_) => {
            return Err(Error::new(
                ErrorKind::UnsupportedPreAuth,
                "smart card credentials are not supported in Kerberos application server",
            ));
        }
    };
    server.realm = Some(realm.clone());

    let mut rand = StdRng::try_from_os_rng()?;
    let nonce = rand.next_u32();
    let options = GenerateAsReqOptions {
        realm: &realm,
        username: &username,
        cname_type,
        snames: &[TGT_SERVICE_NAME, &realm],
        // 4 = size of u32
        nonce: &nonce.to_be_bytes(),
        hostname: &unwrap_hostname(server.config.client_computer_name.as_deref())?,
        context_requirements: ClientRequestFlags::empty(),
    };
    let kdc_req_body = generate_as_req_kdc_body(&options)?;

    let pa_data_options = match credentials {
        CredentialsBuffers::AuthIdentity(auth_identity) => {
            let domain = utf16_bytes_to_utf8_string(&auth_identity.domain);
            let salt = format!("{}{}", domain, username);

            AsReqPaDataOptions::AuthIdentity(GenerateAsPaDataOptions {
                password: &password,
                salt: salt.as_bytes().to_vec(),
                enc_params: server.encryption_params.clone(),
                with_pre_auth: false,
            })
        }
        #[cfg(feature = "scard")]
        CredentialsBuffers::SmartCard(_) => {
            return Err(Error::new(
                ErrorKind::UnsupportedPreAuth,
                "smart card credentials are not supported in Kerberos application server",
            ));
        }
    };

    let as_rep = client::as_exchange(server, yield_point, &kdc_req_body, pa_data_options).await?;

    debug!("AS exchange finished successfully.");

    server.realm = Some(as_rep.0.crealm.0.to_string());

    let (encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep)?;

    let encryption_type = CipherSuite::try_from(encryption_type as usize)?;
    server.encryption_params.encryption_type = Some(encryption_type);

    let mut session_key_extractor = AsRepSessionKeyExtractor::AuthIdentity {
        salt: &salt,
        password: &password,
        enc_params: &mut server.encryption_params,
    };

    let server_props = server.server.as_mut().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidHandle,
            "Kerberos server properties are not initialized",
        )
    })?;
    server_props.ticket_decryption_key = Some(session_key_extractor.session_key(&as_rep)?);

    Ok(as_rep.0.ticket.0)
}
