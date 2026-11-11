#[cfg(feature = "scard")]
use picky_krb::constants::error_codes::KDC_ERR_ETYPE_NOSUPP;
use picky_krb::constants::error_codes::KRB_AP_ERR_SKEW;
use picky_krb::data_types::KrbResult;
use picky_krb::messages::{AsRep, AsReq, KdcReqBody, KrbError};
use time::{Duration, OffsetDateTime};

use crate::kerberos::EncryptionParams;
use crate::kerberos::client::extractors::extract_preauth_salt;
use crate::kerberos::client::generators::{GenerateAsPaDataOptions, GenerateKeytabPaDataOptions, generate_as_req};
use crate::kerberos::client::kdc::decode_kdc_reply;
use crate::kerberos::pa_datas::{AsReqPaDataOptions, AsRequestNonces};
#[cfg(feature = "scard")]
use crate::pk_init::KeyAgreement;
use crate::{CredentialsBuffers, Error, ErrorKind, Kerberos, Result, Secret};

pub(crate) enum AsExchangeOutput {
    SendRequest(AsReq),
    Done(AsRep, String, AsRequestNonces),
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
    nonces: AsRequestNonces,
    retried_skew: bool,
    // Instead of storing the `AsReqPaDataOptions` directly, we store its individual components (fields below).
    // This design avoids introducing lifetime requirement that would require huge refactoring.
    // The `AsReqPaDataOptions` is cheaply reconstructed at each step using the `build_pa_data_options` method.
    password: Secret<String>,
    salt: Vec<u8>,
    #[cfg(feature = "scard")]
    key_agreement: KeyAgreement,
}

impl AsExchange {
    pub(crate) fn new(
        kdc_req_body: KdcReqBody,
        nonces: AsRequestNonces,
        password: Secret<String>,
        salt: Vec<u8>,
        #[cfg(feature = "scard")] key_agreement: KeyAgreement,
    ) -> Self {
        Self {
            state: AsExchangeState::Initial,
            kdc_req_body,
            nonces,
            retried_skew: false,
            password,
            salt,
            #[cfg(feature = "scard")]
            key_agreement,
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

                    let krb_error = match as_rep {
                        Ok(as_rep) => {
                            // [3.1.3.  Receipt of KRB_AS_REQ Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.1.3)
                            // If pre-authentication is not required, the KDC replies with the AS-REP right away.
                            // Active Directory does so for accounts that do not require Kerberos pre-authentication.
                            debug!("KDC replied with AS_REP to the AS_REQ without pre-authentication data");

                            return Ok(AsExchangeOutput::Done(
                                as_rep,
                                String::from_utf8_lossy(&self.salt).into_owned(),
                                self.nonces,
                            ));
                        }
                        Err(krb_error) => krb_error,
                    };

                    if is_smart_card_preauth_hint(credentials, &krb_error) {
                        debug!(
                            "KDC replied with KDC_ERR_ETYPE_NOSUPP to the smart card AS_REQ; continuing with PKINIT"
                        );
                    } else if let Some(salt) =
                        extract_preauth_salt(
                            &krb_error,
                            self.kdc_req_body.realm.0.0.as_utf8(),
                            self.kdc_req_body.cname.0.as_ref().ok_or_else(|| {
                                Error::new(ErrorKind::InvalidParameter, "missing client name in AS-REQ")
                            })?,
                        )?
                    {
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
                        Ok(as_rep) => {
                            return Ok(AsExchangeOutput::Done(
                                as_rep,
                                String::from_utf8_lossy(&self.salt).into_owned(),
                                self.nonces,
                            ));
                        }
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
                password: &self.password,
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
                use crate::smartcard::SmartCard;
                use crate::{SmartCardIdentity, pk_init};

                let scard_identity = SmartCardIdentity::try_from(scard_identity_buffer)?;

                let mut smart_card = SmartCard::from_credentials(&scard_identity)?;
                let p2p_cert = scard_identity.certificate;

                AsReqPaDataOptions::SmartCard(Box::new(pk_init::GenerateAsPaDataOptions {
                    p2p_cert,
                    kdc_req_body: &self.kdc_req_body,
                    key_agreement: self.key_agreement.clone(),
                    sign_data: Box::new(move |data_to_sign| smart_card.sign(data_to_sign)),
                    with_pre_auth: false,
                    authenticator_nonce: self.nonces.pk_authenticator,
                }))
            }
        })
    }
}

/// Returns `true` when the KDC reply to the AS-REQ without pre-authentication data should
/// be treated as `preauth required`.
///
/// The Windows Server 2016 KDC answers a smart card AS-REQ without pre-authentication data
/// with `KDC_ERR_ETYPE_NOSUPP` instead of `KDC_ERR_PREAUTH_REQUIRED`. The error is misleading,
/// since the subsequent AS-REQ offers the same encryption types along with pre-authentication
/// data and succeeds.
///
/// Note: this is workaround for the Windows Server 2016 KDC behavior, which is not compliant with RFC 4120.
#[cfg(feature = "scard")]
fn is_smart_card_preauth_hint(credentials: &CredentialsBuffers, error: &KrbError) -> bool {
    matches!(credentials, CredentialsBuffers::SmartCard(_)) && error.0.error_code.0 == KDC_ERR_ETYPE_NOSUPP
}

#[cfg(not(feature = "scard"))]
fn is_smart_card_preauth_hint(_credentials: &CredentialsBuffers, _error: &KrbError) -> bool {
    false
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

#[cfg(test)]
mod tests {
    use picky_krb::messages::AsRep;

    use super::{AsExchange, AsExchangeOutput};
    use crate::kerberos::client::generators::{GenerateAsReqOptions, generate_as_req_kdc_body};
    use crate::kerberos::client::kdc::tests::as_rep_raw;
    use crate::kerberos::pa_datas::AsRequestNonces;
    use crate::kerberos::test_data::fake_client;
    use crate::{ClientRequestFlags, Secret};

    /// The exchange of `myuser@EXAMPLE.COM` with the request nonce 1.
    fn as_exchange() -> AsExchange {
        let kdc_req_body = generate_as_req_kdc_body(&GenerateAsReqOptions {
            realm: "EXAMPLE.COM",
            username: "myuser",
            cname_type: 1,
            snames: &["krbtgt", "EXAMPLE.COM"],
            nonce: 1,
            hostname: "host",
            context_requirements: ClientRequestFlags::empty(),
        })
        .unwrap();

        AsExchange::new(
            kdc_req_body,
            AsRequestNonces {
                kdc_req: 1,
                #[cfg(feature = "scard")]
                pk_authenticator: 2,
            },
            Secret::new("password".to_owned()),
            b"EXAMPLE.COMmyuser".to_vec(),
            #[cfg(feature = "scard")]
            crate::pk_init::KeyAgreement::Dh(crate::pku2u::generate_client_dh_parameters(
                &mut <rand::rngs::StdRng as rand_core::SeedableRng>::seed_from_u64(1),
            )),
        )
    }

    // RFC 4120 §3.1.3: the KDC replies with the AS-REP right away if it does not require pre-authentication.
    // Active Directory does so for accounts with "Do not require Kerberos preauthentication".
    #[test]
    fn an_as_rep_to_the_request_without_pre_authentication_completes_the_exchange() {
        let mut client = fake_client();
        let credentials = client.auth_identity.clone().unwrap();
        let mut exchange = as_exchange();
        assert!(matches!(
            exchange.step(&mut client, &credentials, &[]).unwrap(),
            AsExchangeOutput::SendRequest(_)
        ));

        // The first four bytes are the length of the message.
        let mut reply = vec![0, 0, 0, 0];
        reply.extend_from_slice(&as_rep_raw());

        let AsExchangeOutput::Done(as_rep, _salt, nonces) = exchange.step(&mut client, &credentials, &reply).unwrap()
        else {
            panic!("the AS-REP must complete the exchange");
        };

        assert_eq!(as_rep, picky_asn1_der::from_bytes::<AsRep>(&as_rep_raw()).unwrap());
        assert_eq!(nonces.kdc_req, 1);
    }
}
