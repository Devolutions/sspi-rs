#[cfg(feature = "scard")]
use picky_krb::constants::error_codes::KDC_ERR_ETYPE_NOSUPP;
use picky_krb::constants::error_codes::KRB_AP_ERR_SKEW;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::KrbResult;
use picky_krb::messages::{AsRep, AsReq, KdcReqBody, KrbError};
use time::{Duration, OffsetDateTime};

use crate::kerberos::EncryptionParams;
use crate::kerberos::client::extractors::extract_preauth_hint;
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
    /// The encryption type of the password key that the KDC asks for in the pre-authentication error.
    preauth_cipher_suite: Option<CipherSuite>,
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
            preauth_cipher_suite: None,
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
                    } else if let Some(hint) =
                        extract_preauth_hint(
                            &krb_error,
                            self.kdc_req_body.realm.0.0.as_utf8(),
                            self.kdc_req_body.cname.0.as_ref().ok_or_else(|| {
                                Error::new(ErrorKind::InvalidParameter, "missing client name in AS-REQ")
                            })?,
                        )?
                    {
                        debug!("salt extracted successfully from the KRB_ERROR");
                        self.salt = hint.salt.into_bytes();
                        self.preauth_cipher_suite = hint.cipher_suite;
                    }

                    self.state = AsExchangeState::AsRequest;

                    continue;
                }
                AsExchangeState::AsRequest => {
                    let preauth_cipher_suite = self.preauth_cipher_suite.clone();
                    let mut pa_data_options = self.build_pa_data_options(credentials, &client.encryption_params)?;

                    if let Some(cipher_suite) = preauth_cipher_suite {
                        pa_data_options.with_encryption_type(cipher_suite);
                    }
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

    /// The KRB_ERROR of the KDC that requires pre-authentication, with an ETYPE-INFO2 of the given `(etype, salt)`.
    fn preauth_required_error(etype: u8, salt: &str) -> Vec<u8> {
        use picky_asn1::date::GeneralizedTime;
        use picky_asn1::restricted_string::IA5String;
        use picky_asn1::wrapper::{
            Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag4,
            ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag9, ExplicitContextTag10, ExplicitContextTag12,
            IntegerAsn1, OctetStringAsn1, Optional,
        };
        use picky_krb::constants::error_codes::KDC_ERR_PREAUTH_REQUIRED;
        use picky_krb::constants::types::PA_ETYPE_INFO2_TYPE;
        use picky_krb::data_types::{
            EtypeInfo2Entry, KerberosStringAsn1, KerberosTime, Microseconds, PaData, PrincipalName,
        };
        use picky_krb::messages::{KrbError, KrbErrorInner};
        use time::OffsetDateTime;

        let string = |value: &str| KerberosStringAsn1::from(IA5String::from_string(value.to_owned()).unwrap());
        let etype_info2 = Asn1SequenceOf::from(vec![PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_ETYPE_INFO2_TYPE.to_vec())),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
                picky_asn1_der::to_vec(&Asn1SequenceOf::from(vec![EtypeInfo2Entry {
                    etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![etype])),
                    salt: Optional::from(Some(ExplicitContextTag1::from(string(salt)))),
                    s2kparams: Optional::from(None),
                }]))
                .unwrap(),
            )),
        }]);
        let error = KrbError::from(KrbErrorInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![30])),
            ctime: Optional::from(None),
            cusec: Optional::from(None),
            stime: ExplicitContextTag4::from(KerberosTime::from(GeneralizedTime::from(OffsetDateTime::now_utc()))),
            susec: ExplicitContextTag5::from(Microseconds::from(vec![0])),
            error_code: ExplicitContextTag6::from(KDC_ERR_PREAUTH_REQUIRED),
            crealm: Optional::from(None),
            cname: Optional::from(None),
            realm: ExplicitContextTag9::from(string("EXAMPLE.COM")),
            sname: ExplicitContextTag10::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![2])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    string("krbtgt"),
                    string("EXAMPLE.COM"),
                ])),
            }),
            e_text: Optional::from(None),
            e_data: Optional::from(Some(ExplicitContextTag12::from(OctetStringAsn1::from(
                picky_asn1_der::to_vec(&etype_info2).unwrap(),
            )))),
        });

        // The first four bytes are the length of the message.
        let mut message = vec![0, 0, 0, 0];
        message.extend_from_slice(&picky_asn1_der::to_vec(&error).unwrap());

        message
    }

    // RFC 4120 §5.2.7.5: the ETYPE-INFO2 tells which key to use for the PA-ENC-TIMESTAMP.
    // A KDC that has only an AES128 key for the account cannot check a timestamp encrypted with AES256.
    #[test]
    fn the_pre_authentication_uses_the_encryption_type_from_the_kdc_hint() {
        use picky_krb::constants::types::{PA_ENC_TIMESTAMP, PA_ENC_TIMESTAMP_KEY_USAGE};
        use picky_krb::crypto::CipherSuite;
        use picky_krb::data_types::EncryptedData;

        let mut client = fake_client();
        let credentials = client.auth_identity.clone().unwrap();
        let mut exchange = as_exchange();
        exchange.step(&mut client, &credentials, &[]).unwrap();

        let AsExchangeOutput::SendRequest(as_req) = exchange
            .step(&mut client, &credentials, &preauth_required_error(17, "hint-salt"))
            .unwrap()
        else {
            panic!("the exchange must send the AS-REQ with the pre-authentication");
        };

        let pa_data = as_req
            .0
            .padata
            .0
            .unwrap()
            .0
            .0
            .into_iter()
            .find(|pa_data| pa_data.padata_type.0.0 == PA_ENC_TIMESTAMP)
            .expect("the AS-REQ carries PA-ENC-TIMESTAMP");
        let encrypted: EncryptedData = picky_asn1_der::from_bytes(&pa_data.padata_data.0.0).unwrap();
        assert_eq!(encrypted.etype.0.0, [17]);
        // The key is the AES128 key of the password and the salt of the hint.
        let cipher = CipherSuite::Aes128CtsHmacSha196.cipher();
        let key = cipher.generate_key_from_password(b"password", b"hint-salt").unwrap();
        cipher
            .decrypt(&key, PA_ENC_TIMESTAMP_KEY_USAGE, &encrypted.cipher.0.0)
            .expect("the timestamp is encrypted with the key of the hint");
    }
}
