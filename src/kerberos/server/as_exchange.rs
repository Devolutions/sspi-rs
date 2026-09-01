use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{KrbResult, ResultExt, Ticket};
use picky_krb::messages::{AsRep, KdcReqBody, TgtReq};
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};

use crate::generator::YieldPointLocal;
use crate::kerberos::TGT_SERVICE_NAME;
use crate::kerberos::client::extractors::{extract_encryption_params_from_as_rep, extract_salt_from_krb_error};
use crate::kerberos::client::generators::{
    GenerateAsPaDataOptions, GenerateAsReqOptions, generate_as_req, generate_as_req_kdc_body,
};
use crate::kerberos::client::principal::{get_client_principal_name_type, get_client_principal_realm};
use crate::kerberos::pa_datas::{AsRepSessionKeyExtractor, AsReqPaDataOptions};
use crate::kerberos::utils::serialize_message;
use crate::{ClientRequestFlags, CredentialsBuffers, Error, ErrorKind, Kerberos, Result};

/// Requests the TGT ticket from KDC.
///
/// Basically, it performs the AS exchange, saves the session key, and returns the ticket.
pub(crate) async fn request_tgt(
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
            let username = auth_identity.user.to_string();
            let domain = auth_identity.domain.to_string();
            let password = auth_identity.password.as_ref().as_ref().to_string();

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
        CredentialsBuffers::Keytab(_) => {
            return Err(Error::new(
                ErrorKind::UnsupportedPreAuth,
                "keytab credentials are not supported in Kerberos application server",
            ));
        }
    };
    server.realm = Some(realm.clone());

    let mut rand = StdRng::try_from_rng(&mut SysRng)?;
    let nonce = rand.next_u32();
    let options = GenerateAsReqOptions {
        realm: &realm,
        username: &username,
        cname_type,
        snames: &[TGT_SERVICE_NAME, &realm],
        // 4 = size of u32
        nonce: &nonce.to_be_bytes(),
        hostname: &server.config.client_computer_name,
        context_requirements: ClientRequestFlags::empty(),
    };
    let kdc_req_body = generate_as_req_kdc_body(&options)?;

    let pa_data_options = match credentials {
        CredentialsBuffers::AuthIdentity(auth_identity) => {
            let domain = auth_identity.domain.to_string();
            let salt = format!("{domain}{username}").into_bytes();

            AsReqPaDataOptions::AuthIdentity(GenerateAsPaDataOptions {
                password: &password,
                salt,
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
        CredentialsBuffers::Keytab(_) => {
            return Err(Error::new(
                ErrorKind::UnsupportedPreAuth,
                "keytab credentials are not supported in Kerberos application server",
            ));
        }
    };

    let as_rep = as_exchange(server, yield_point, &kdc_req_body, pa_data_options).await?;

    debug!("AS exchange finished successfully.");

    server.realm = Some(as_rep.0.crealm.0.to_string());

    let (encryption_type, salt) = extract_encryption_params_from_as_rep(&as_rep)?;

    let encryption_type = CipherSuite::try_from(usize::from(encryption_type))?;
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

/// Performs AS exchange as specified in [RFC 4210: The Authentication Service Exchange](https://www.rfc-editor.org/rfc/rfc4120#section-3.1).
pub(crate) async fn as_exchange(
    client: &mut Kerberos,
    yield_point: &mut YieldPointLocal,
    kdc_req_body: &KdcReqBody,
    mut pa_data_options: AsReqPaDataOptions<'_>,
) -> Result<AsRep> {
    pa_data_options.with_pre_auth(false);
    let pa_datas = pa_data_options.generate()?;
    let as_req = generate_as_req(pa_datas, kdc_req_body.clone());

    let response = client.send(yield_point, &serialize_message(&as_req)?).await?;

    // first 4 bytes are message len. skipping them
    {
        if response.len() < 4 {
            return Err(Error::new(
                ErrorKind::InternalError,
                "the KDC reply message is too small: expected at least 4 bytes",
            ));
        }

        let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
        let as_rep: KrbResult<AsRep> = KrbResult::deserialize(&mut d)?;

        if as_rep.is_ok() {
            error!("KDC replied with AS_REP to the AS_REQ without the encrypted timestamp. The KRB_ERROR expected.");

            return Err(Error::new(
                ErrorKind::InvalidToken,
                "KDC server should not process AS_REQ without the pa-pac data",
            ));
        }

        if let Some(correct_salt) = extract_salt_from_krb_error(&as_rep.unwrap_err())? {
            debug!("salt extracted successfully from the KRB_ERROR");

            pa_data_options.with_salt(correct_salt.into_bytes());
        }
    }

    pa_data_options.with_pre_auth(true);
    let pa_datas = pa_data_options.generate()?;

    let as_req = generate_as_req(pa_datas, kdc_req_body.clone());

    let response = client.send(yield_point, &serialize_message(&as_req)?).await?;

    if response.len() < 4 {
        return Err(Error::new(
            ErrorKind::InternalError,
            "the KDC reply message is too small: expected at least 4 bytes",
        ));
    }

    // first 4 bytes are message len. skipping them
    let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);

    Ok(KrbResult::<AsRep>::deserialize(&mut d)?.inspect_err(|err| error!(?err, "AS exchange error"))?)
}
