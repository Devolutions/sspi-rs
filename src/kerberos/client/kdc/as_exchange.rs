use picky_krb::constants::error_codes::KRB_AP_ERR_SKEW;
use picky_krb::data_types::KrbResult;
use picky_krb::messages::{AsRep, AsReq, KdcReqBody, KrbError};
use time::{Duration, OffsetDateTime};

use crate::kerberos::EncryptionParams;
use crate::kerberos::client::extractors::extract_salt_from_krb_error;
use crate::kerberos::client::generators::{GenerateAsPaDataOptions, GenerateKeytabPaDataOptions, generate_as_req};
use crate::kerberos::client::kdc::decode_kdc_reply;
use crate::kerberos::pa_datas::AsReqPaDataOptions;
#[cfg(feature = "scard")]
use crate::pk_init::DhParameters;
use crate::{CredentialsBuffers, Error, ErrorKind, Kerberos, Result, Secret};

pub(crate) enum AsExchangeOutput {
    SendRequest(AsReq),
    Done(AsRep),
}

#[derive(Debug, Clone, PartialEq)]
enum AsExchangeState {
    Initial,
    PreauthRequiredErrorResponse,
    AsRequest,
    AsRepResponse,
}

/// Performs the AS exchange as specified in [RFC 4120, section 3.1](https://www.rfc-editor.org/rfc/rfc4120#section-3.1).
///
/// On a KDC clock-skew error, retries pre-authentication once using the server
/// time in the error. The offset is kept on the client context for subsequent
/// TGS and AP authenticators; other errors are returned without retrying.
#[derive(Debug, Clone, PartialEq)]
pub struct AsExchange {
    state: AsExchangeState,
    kdc_req_body: KdcReqBody,
    retried_skew: bool,
    // Instead of storing the `AsReqPaDataOptions` directly, we store its individual components (fields below).
    // This design avoids introducing lifetime requirement that would require huge refactoring.
    // The `AsReqPaDataOptions` is cheaply reconstructed at each step using the `build_pa_data_options` method.
    password: Secret<String>,
    salt: Vec<u8>,
    #[cfg(feature = "scard")]
    dh_parameters: DhParameters,
    #[cfg(feature = "scard")]
    authenticator_nonce: u32,
}

impl AsExchange {
    pub(crate) fn new(
        kdc_req_body: KdcReqBody,
        password: Secret<String>,
        salt: Vec<u8>,
        #[cfg(feature = "scard")] dh_parameters: DhParameters,
        #[cfg(feature = "scard")] authenticator_nonce: u32,
    ) -> Self {
        Self {
            state: AsExchangeState::Initial,
            kdc_req_body,
            retried_skew: false,
            password,
            salt,
            #[cfg(feature = "scard")]
            dh_parameters,
            #[cfg(feature = "scard")]
            authenticator_nonce,
        }
    }

    pub(crate) fn step(
        &mut self,
        client: &mut Kerberos,
        credentials: &CredentialsBuffers,
        response: &[u8],
    ) -> Result<AsExchangeOutput> {
        loop {
            match self.state {
                AsExchangeState::Initial => {
                    let mut pa_data_options = self.build_pa_data_options(credentials, &client.encryption_params)?;

                    pa_data_options.with_pre_auth(false);
                    let pa_datas = pa_data_options.generate(client.current_kdc_time()?)?;
                    let as_req = generate_as_req(pa_datas, self.kdc_req_body.clone());

                    self.state = AsExchangeState::PreauthRequiredErrorResponse;
                    return Ok(AsExchangeOutput::SendRequest(as_req));
                }
                AsExchangeState::PreauthRequiredErrorResponse => {
                    let as_rep: KrbResult<AsRep> = decode_kdc_reply(
                        response,
                        client.is_iakerb(),
                        &mut client.iakerb_cookie,
                        &mut client.iakerb_gss_transcript,
                    )?;

                    if as_rep.is_ok() {
                        error!(
                            "KDC replied with AS_REP to the AS_REQ without the encrypted timestamp. The KRB_ERROR expected."
                        );

                        return Err(Error::new(
                            ErrorKind::InvalidToken,
                            "KDC server should not process AS_REQ without the pa-pac data",
                        ));
                    }

                    if let Some(salt) = extract_salt_from_krb_error(&as_rep.unwrap_err())? {
                        debug!("salt extracted successfully from the KRB_ERROR");
                        self.salt = salt.into_bytes();
                    }

                    self.state = AsExchangeState::AsRequest;

                    continue;
                }
                AsExchangeState::AsRequest => {
                    let mut pa_data_options = self.build_pa_data_options(credentials, &client.encryption_params)?;

                    pa_data_options.with_pre_auth(true);
                    let pa_datas = pa_data_options.generate(client.current_kdc_time()?)?;

                    self.state = AsExchangeState::AsRepResponse;
                    return Ok(AsExchangeOutput::SendRequest(generate_as_req(
                        pa_datas,
                        self.kdc_req_body.clone(),
                    )));
                }
                AsExchangeState::AsRepResponse => {
                    let received_at = OffsetDateTime::now_utc();

                    let as_rep: KrbResult<AsRep> = decode_kdc_reply(
                        response,
                        client.is_iakerb(),
                        &mut client.iakerb_cookie,
                        &mut client.iakerb_gss_transcript,
                    )?;

                    match as_rep {
                        Ok(as_rep) => return Ok(AsExchangeOutput::Done(as_rep)),
                        Err(err) if !self.retried_skew && err.0.error_code.0 == KRB_AP_ERR_SKEW => {
                            client.clock_offset = clock_offset_from_error(&err, received_at)?;
                            self.retried_skew = true;
                            debug!(offset = ?client.clock_offset, "Retrying AS exchange with KDC clock offset");

                            self.state = AsExchangeState::AsRequest;
                            continue;
                        }
                        Err(err) => {
                            error!(?err, "AS exchange error");
                            return Err(err.into());
                        }
                    }
                }
            }
        }
    }

    fn build_pa_data_options<'a>(
        &'a mut self,
        credentials: &'a CredentialsBuffers,
        enc_params: &EncryptionParams,
    ) -> Result<AsReqPaDataOptions<'a>> {
        Ok(match credentials {
            CredentialsBuffers::AuthIdentity(_) => AsReqPaDataOptions::AuthIdentity(GenerateAsPaDataOptions {
                password: self.password.as_ref(),
                salt: self.salt.clone(),
                enc_params: enc_params.clone(),
                with_pre_auth: false,
            }),
            CredentialsBuffers::Keytab(keytab) => AsReqPaDataOptions::Keytab(GenerateKeytabPaDataOptions {
                key: keytab.key.clone(),
                key_enctype: keytab.key_enctype.clone(),
                with_pre_auth: false,
            }),
            #[cfg(feature = "scard")]
            CredentialsBuffers::SmartCard(scard_identity_buffer) => {
                use sha1::{Digest, Sha1};

                use crate::smartcard::SmartCard;
                use crate::{SmartCardIdentity, pk_init};

                let scard_identity = SmartCardIdentity::try_from(scard_identity_buffer)?;

                let mut smart_card = SmartCard::from_credentials(&scard_identity)?;
                let p2p_cert = scard_identity.certificate;

                AsReqPaDataOptions::SmartCard(Box::new(pk_init::GenerateAsPaDataOptions {
                    p2p_cert,
                    kdc_req_body: &self.kdc_req_body,
                    dh_parameters: self.dh_parameters.clone(),
                    sign_data: Box::new(move |data_to_sign| {
                        let mut sha1 = Sha1::new();
                        sha1.update(data_to_sign);
                        let digest = sha1.finalize().to_vec();

                        smart_card.sign(digest)
                    }),
                    with_pre_auth: false,
                    authenticator_nonce: self.authenticator_nonce,
                }))
            }
        })
    }
}

pub(crate) fn clock_offset_from_error(error: &KrbError, received_at: OffsetDateTime) -> Result<Duration> {
    let seconds = OffsetDateTime::try_from(error.0.stime.0.0.clone())
        .map_err(|_| Error::new(ErrorKind::InvalidToken, "KDC skew error has invalid server time"))?;
    let usec = error.0.susec.0.0.as_slice();
    if usec.len() > 4 {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "KDC skew error has invalid microseconds",
        ));
    }
    let microseconds = usec.iter().fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
    if microseconds > 999_999 {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            "KDC skew error has invalid microseconds",
        ));
    }
    let server_time = seconds
        .checked_add(Duration::microseconds(i64::from(microseconds)))
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "KDC skew error has invalid server time"))?;
    Ok(server_time - received_at)
}
