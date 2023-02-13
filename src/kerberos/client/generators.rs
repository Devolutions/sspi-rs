use std::str::FromStr;

use chrono::{Duration, Utc};
use md5::{Digest, Md5};
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag11, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7,
    ExplicitContextTag8, ExplicitContextTag9, GeneralizedTimeAsn1, IntegerAsn1, ObjectIdentifierAsn1, OctetStringAsn1,
    Optional,
};
use picky_asn1_der::application_tag::ApplicationTag;
use picky_asn1_der::Asn1RawDer;
use picky_asn1_x509::oids;
use picky_krb::constants::gss_api::{
    ACCEPT_COMPLETE, ACCEPT_INCOMPLETE, AP_REQ_TOKEN_ID, AUTHENTICATOR_CHECKSUM_TYPE, TGT_REQ_TOKEN_ID,
};
use picky_krb::constants::key_usages::{AP_REQ_AUTHENTICATOR, KRB_PRIV_ENC_PART, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR};
use picky_krb::constants::types::{
    AD_AUTH_DATA_AP_OPTION_TYPE, AP_REQ_MSG_TYPE, AS_REQ_MSG_TYPE, KERB_AP_OPTIONS_CBT, KRB_PRIV, NET_BIOS_ADDR_TYPE,
    NT_ENTERPRISE, NT_PRINCIPAL, NT_SRV_INST, PA_ENC_TIMESTAMP, PA_ENC_TIMESTAMP_KEY_USAGE, PA_PAC_OPTIONS_TYPE,
    PA_PAC_REQUEST_TYPE, PA_TGS_REQ_TYPE, TGS_REQ_MSG_TYPE, TGT_REQ_MSG_TYPE,
};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    ApOptions, Authenticator, AuthenticatorInner, AuthorizationData, AuthorizationDataInner, Checksum, EncKrbPrivPart,
    EncKrbPrivPartInner, EncryptedData, EncryptionKey, HostAddress, KerbPaPacRequest, KerberosFlags,
    KerberosStringAsn1, KerberosTime, PaData, PaEncTsEnc, PaPacOptions, PrincipalName, Realm, Ticket,
};
use picky_krb::gss_api::{
    ApplicationTag0, GssApiNegInit, KrbMessage, MechType, MechTypeList, NegTokenInit, NegTokenTarg, NegTokenTarg1,
};
use picky_krb::messages::{
    ApMessage, ApReq, ApReqInner, AsReq, KdcRep, KdcReq, KdcReqBody, KrbPriv, KrbPrivInner, KrbPrivMessage, TgsReq,
    TgtReq,
};
use rand::rngs::OsRng;
use rand::Rng;
#[cfg(feature = "logging")]
use tracing::{instrument, trace};

use crate::channel_bindings::ChannelBindings;
use crate::crypto::compute_md5_channel_bindings_hash;
use crate::kerberos::flags::{ApOptions as ApOptionsFlags, KdcOptions};
use crate::kerberos::utils::parse_target_name;
use crate::kerberos::{EncryptionParams, DEFAULT_ENCRYPTION_TYPE, KERBEROS_VERSION};
use crate::{ClientRequestFlags, Error, ErrorKind, Result};

const TGT_TICKET_LIFETIME_DAYS: i64 = 3;
const NONCE_LEN: usize = 4;
pub const MAX_MICROSECONDS_IN_SECOND: u32 = 999_999;
const MD5_CHECKSUM_TYPE: [u8; 1] = [0x07];

// Renewable, Canonicalize, and Renewable-ok are on by default
// https://www.rfc-editor.org/rfc/rfc4120#section-5.4.1
pub const DEFAULT_AS_REQ_OPTIONS: [u8; 4] = [0x00, 0x81, 0x00, 0x10];

// Renewable, Canonicalize, Enc-tkt-in-skey are on by default
// https://www.rfc-editor.org/rfc/rfc4120#section-5.4.1
const DEFAULT_TGS_REQ_OPTIONS: [u8; 4] = [0x00, 0x81, 0x00, 0x08];

const DEFAULT_PA_PAC_OPTIONS: [u8; 4] = [0x40, 0x00, 0x00, 0x00];

/// [Authenticator Checksum](https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1)
pub const AUTHENTICATOR_DEFAULT_CHECKSUM: [u8; 24] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x3E, 0x00, 0x00, 0x00,
];

// [MS-KILE] 3.3.5.6.1 Client Principal Lookup
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6435d3fb-8cf6-4df5-a156-1277690ed59c
pub fn get_client_principal_name_type(username: &str, _domain: &str) -> u8 {
    if username.contains('@') {
        NT_ENTERPRISE
    } else {
        NT_PRINCIPAL
    }
}

pub fn get_client_principal_realm(username: &str, domain: &str) -> String {
    if domain.is_empty() {
        if let Some((_left, right)) = username.split_once('@') {
            return right.to_string();
        }
    }
    domain.to_string()
}

#[derive(Debug)]
pub struct GenerateAsPaDataOptions<'a> {
    pub password: &'a str,
    pub salt: Vec<u8>,
    pub enc_params: EncryptionParams,
    pub with_pre_auth: bool,
}

#[cfg_attr(feature = "logging", instrument(level = "trace", ret))]
pub fn generate_pa_datas_for_as_req(options: &GenerateAsPaDataOptions) -> Result<Vec<PaData>> {
    let GenerateAsPaDataOptions {
        password,
        salt,
        enc_params,
        with_pre_auth,
    } = options;

    let mut pa_datas = if *with_pre_auth {
        let current_date = Utc::now();
        let mut microseconds = current_date.timestamp_subsec_micros();
        if microseconds > MAX_MICROSECONDS_IN_SECOND {
            microseconds = MAX_MICROSECONDS_IN_SECOND;
        }

        let timestamp = PaEncTsEnc {
            patimestamp: ExplicitContextTag0::from(KerberosTime::from(GeneralizedTime::from(current_date))),
            pausec: Optional::from(Some(ExplicitContextTag1::from(IntegerAsn1::from(
                microseconds.to_be_bytes().to_vec(),
            )))),
        };
        let timestamp_bytes = picky_asn1_der::to_vec(&timestamp)?;

        let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
        let cipher = encryption_type.cipher();

        let key = cipher.generate_key_from_password(password.as_bytes(), salt)?;
        #[cfg(feature = "logging")]
        trace!(
            "AS timestamp encryption key: {:?}. Encryption type: {:?}",
            key,
            encryption_type
        );

        let encrypted_timestamp = cipher.encrypt(&key, PA_ENC_TIMESTAMP_KEY_USAGE, &timestamp_bytes)?;

        #[cfg(feature = "logging")]
        trace!(
            "Encrypted timestamp (for {:?}.{}): plain {:?}, encrypted {:?}",
            current_date,
            microseconds,
            timestamp_bytes,
            encrypted_timestamp
        );

        vec![PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_ENC_TIMESTAMP.to_vec())),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_timestamp)),
            })?)),
        }]
    } else {
        Vec::new()
    };

    pa_datas.push(PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_REQUEST_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&KerbPaPacRequest {
            include_pac: ExplicitContextTag0::from(true),
        })?)),
    });

    Ok(pa_datas)
}

#[derive(Debug)]
pub struct GenerateAsReqOptions<'a> {
    pub realm: &'a str,
    pub username: &'a str,
    pub cname_type: u8,
    pub snames: &'a [&'a str],
    pub nonce: &'a [u8],
    pub hostname: &'a str,
    pub context_requirements: ClientRequestFlags,
}

#[cfg_attr(feature = "logging", instrument(level = "trace", ret))]
pub fn generate_as_req_kdc_body(options: &GenerateAsReqOptions) -> Result<KdcReqBody> {
    let GenerateAsReqOptions {
        realm,
        username,
        cname_type,
        snames,
        nonce,
        hostname: address,
        context_requirements,
    } = options;

    let expiration_date = Utc::now()
        .checked_add_signed(Duration::days(TGT_TICKET_LIFETIME_DAYS))
        .unwrap();

    let host_address = HostAddress {
        addr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NET_BIOS_ADDR_TYPE])),
        address: ExplicitContextTag1::from(OctetStringAsn1::from(address.as_bytes().to_vec())),
    };

    let address = Some(ExplicitContextTag9::from(Asn1SequenceOf::from(vec![host_address])));

    let mut service_names = Vec::with_capacity(snames.len());
    for sname in *snames {
        service_names.push(KerberosStringAsn1::from(IA5String::from_string((*sname).to_owned())?));
    }

    let mut as_req_options = KdcOptions::from_bits(u32::from_be_bytes(DEFAULT_AS_REQ_OPTIONS)).unwrap();
    if context_requirements.contains(ClientRequestFlags::DELEGATE) {
        as_req_options |= KdcOptions::FORWARDABLE;
    }

    Ok(KdcReqBody {
        kdc_options: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
            as_req_options.bits().to_be_bytes().to_vec(),
        ))),
        cname: Optional::from(Some(ExplicitContextTag1::from(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![*cname_type])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![KerberosStringAsn1::from(
                IA5String::from_string((*username).into())?,
            )])),
        }))),
        realm: ExplicitContextTag2::from(Realm::from(IA5String::from_string((*realm).into())?)),
        sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(service_names)),
        }))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(expiration_date))),
        rtime: Optional::from(Some(ExplicitContextTag6::from(GeneralizedTimeAsn1::from(
            GeneralizedTime::from(expiration_date),
        )))),
        nonce: ExplicitContextTag7::from(IntegerAsn1::from(nonce.to_vec())),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
            IntegerAsn1::from(vec![CipherSuite::Aes256CtsHmacSha196.into()]),
            IntegerAsn1::from(vec![CipherSuite::Aes128CtsHmacSha196.into()]),
        ])),
        addresses: Optional::from(address),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    })
}

#[cfg_attr(feature = "logging", instrument(level = "debug", ret, skip_all))]
pub fn generate_as_req(pa_datas: &[PaData], kdc_req_body: KdcReqBody) -> AsReq {
    AsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1::from(vec![AS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(
            pa_datas.to_owned(),
        )))),
        req_body: ExplicitContextTag4::from(kdc_req_body),
    })
}

#[derive(Debug)]
pub struct GenerateTgsReqOptions<'a> {
    pub realm: &'a str,
    pub service_principal: &'a str,
    pub session_key: &'a [u8],
    pub ticket: Ticket,
    pub authenticator: &'a mut Authenticator,
    pub additional_tickets: Option<Vec<Ticket>>,
    pub enc_params: &'a EncryptionParams,
    pub context_requirements: ClientRequestFlags,
}

#[cfg_attr(feature = "logging", instrument(level = "debug", ret))]
pub fn generate_tgs_req(options: GenerateTgsReqOptions) -> Result<TgsReq> {
    let GenerateTgsReqOptions {
        realm,
        service_principal,
        session_key,
        ticket,
        authenticator,
        additional_tickets,
        enc_params,
        context_requirements,
    } = options;

    let (service_name, service_principal_name) = parse_target_name(service_principal)?;

    let expiration_date = Utc::now()
        .checked_add_signed(Duration::days(TGT_TICKET_LIFETIME_DAYS))
        .unwrap();

    let mut tgs_req_options = KdcOptions::from_bits(u32::from_be_bytes(DEFAULT_TGS_REQ_OPTIONS)).unwrap();
    if context_requirements.contains(ClientRequestFlags::DELEGATE) {
        tgs_req_options |= KdcOptions::FORWARDABLE;
    }

    let req_body = KdcReqBody {
        kdc_options: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
            tgs_req_options.bits().to_be_bytes().to_vec(),
        ))),
        cname: Optional::from(None),
        realm: ExplicitContextTag2::from(Realm::from(IA5String::from_str(realm)?)),
        sname: Optional::from(Some(ExplicitContextTag3::from(PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                KerberosStringAsn1::from(IA5String::from_string(service_name.into())?),
                KerberosStringAsn1::from(IA5String::from_string(service_principal_name.into())?),
            ])),
        }))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(GeneralizedTimeAsn1::from(GeneralizedTime::from(expiration_date))),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(IntegerAsn1::from(OsRng::default().gen::<[u8; NONCE_LEN]>().to_vec())),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![
            IntegerAsn1::from(vec![CipherSuite::Aes256CtsHmacSha196.into()]),
            IntegerAsn1::from(vec![CipherSuite::Aes128CtsHmacSha196.into()]),
        ])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(
            additional_tickets.map(|tickets| ExplicitContextTag11::from(Asn1SequenceOf::from(tickets))),
        ),
    };

    let mut md5 = Md5::new();
    md5.update(&picky_asn1_der::to_vec(&req_body)?);
    let checksum = md5.finalize();

    authenticator.0.cksum = Optional::from(Some(ExplicitContextTag3::from(Checksum {
        cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(MD5_CHECKSUM_TYPE.to_vec())),
        checksum: ExplicitContextTag1::from(OctetStringAsn1::from(checksum.to_vec())),
    })));

    let pa_tgs_req =
        PaData {
            padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_TGS_REQ_TYPE.to_vec())),
            padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(
                &generate_tgs_ap_req(ticket, session_key, authenticator, enc_params)?,
            )?)),
        };

    let pa_pac_options = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(PA_PAC_OPTIONS_TYPE.to_vec())),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(picky_asn1_der::to_vec(&PaPacOptions {
            flags: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(
                DEFAULT_PA_PAC_OPTIONS.to_vec(),
            ))),
        })?)),
    };

    Ok(TgsReq::from(KdcReq {
        pvno: ExplicitContextTag1::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag2::from(IntegerAsn1::from(vec![TGS_REQ_MSG_TYPE])),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa_tgs_req,
            pa_pac_options,
        ])))),
        req_body: ExplicitContextTag4::from(req_body),
    }))
}

#[derive(Debug)]
pub struct ChecksumOptions {
    pub checksum_type: Vec<u8>,
    pub checksum_value: Vec<u8>,
}

#[derive(Debug)]
pub struct AuthenticatorChecksumExtension {
    pub extension_type: u32,
    pub extension_value: Vec<u8>,
}

#[derive(Debug)]
pub struct EncKey {
    pub key_type: CipherSuite,
    pub key_value: Vec<u8>,
}

#[derive(Debug)]
pub struct GenerateAuthenticatorOptions<'a> {
    pub kdc_rep: &'a KdcRep,
    pub seq_num: Option<u32>,
    pub sub_key: Option<EncKey>,
    pub checksum: Option<ChecksumOptions>,
    pub channel_bindings: Option<&'a ChannelBindings>,
    pub extensions: Vec<AuthenticatorChecksumExtension>,
}

#[cfg_attr(feature = "logging", instrument(level = "trace", ret))]
pub fn generate_authenticator(options: GenerateAuthenticatorOptions) -> Result<Authenticator> {
    let GenerateAuthenticatorOptions {
        kdc_rep,
        seq_num,
        sub_key,
        checksum,
        channel_bindings,
        ..
    } = options;

    let current_date = Utc::now();
    let mut microseconds = current_date.timestamp_subsec_micros();
    if microseconds > MAX_MICROSECONDS_IN_SECOND {
        microseconds = MAX_MICROSECONDS_IN_SECOND;
    }

    let authorization_data = Optional::from(channel_bindings.as_ref().map(|_| {
        ExplicitContextTag8::from(AuthorizationData::from(vec![AuthorizationDataInner {
            ad_type: ExplicitContextTag0::from(IntegerAsn1::from(AD_AUTH_DATA_AP_OPTION_TYPE.to_vec())),
            ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(KERB_AP_OPTIONS_CBT.to_vec())),
        }]))
    }));

    let cksum = if let Some(ChecksumOptions {
        checksum_type,
        mut checksum_value,
    }) = checksum
    {
        if checksum_type == AUTHENTICATOR_CHECKSUM_TYPE && channel_bindings.is_some() {
            if checksum_value.len() < 20 {
                return Err(Error::new(
                    ErrorKind::InternalError,
                    format!(
                        "Invalid authenticator checksum length: expected >= 20 but got {}. ",
                        checksum_value.len()
                    ),
                ));
            }
            // [Authenticator Checksum](https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1)
            // 4..19 - Channel binding information (19 inclusive).
            checksum_value[4..20]
                .copy_from_slice(&compute_md5_channel_bindings_hash(channel_bindings.as_ref().unwrap()));
        }
        Optional::from(Some(ExplicitContextTag3::from(Checksum {
            cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(checksum_type)),
            checksum: ExplicitContextTag1::from(OctetStringAsn1::from(checksum_value)),
        })))
    } else {
        Optional::from(None)
    };

    Ok(Authenticator::from(AuthenticatorInner {
        authenticator_bno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        crealm: ExplicitContextTag1::from(kdc_rep.crealm.0.clone()),
        cname: ExplicitContextTag2::from(kdc_rep.cname.0.clone()),
        cksum,
        cusec: ExplicitContextTag4::from(IntegerAsn1::from(microseconds.to_be_bytes().to_vec())),
        ctime: ExplicitContextTag5::from(KerberosTime::from(GeneralizedTime::from(current_date))),
        subkey: Optional::from(sub_key.map(|EncKey { key_type, key_value }| {
            ExplicitContextTag6::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![key_type.into()])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(key_value)),
            })
        })),
        seq_number: Optional::from(seq_num.map(|seq_num| {
            ExplicitContextTag7::from(IntegerAsn1::from_bytes_be_unsigned(seq_num.to_be_bytes().to_vec()))
        })),
        authorization_data,
    }))
}

pub fn generate_tgs_ap_req(
    ticket: Ticket,
    session_key: &[u8],
    authenticator: &Authenticator,
    enc_params: &EncryptionParams,
) -> Result<ApReq> {
    let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
    let cipher = encryption_type.cipher();

    let encoded_authenticator = picky_asn1_der::to_vec(&authenticator)?;
    let encrypted_authenticator = cipher.encrypt(
        session_key,
        TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
        &encoded_authenticator,
    )?;

    #[cfg(feature = "logging")]
    trace!(
        "TGS AP_REQ authenticator encryption key: {:?}. Encryption type: {:?}",
        session_key,
        encryption_type
    );
    #[cfg(feature = "logging")]
    trace!(
        "TGS AP_REQ authenticator: plain {:?}, encrypted: {:?}",
        encoded_authenticator,
        encrypted_authenticator
    );

    Ok(ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(vec![
            // do not need any options when ap_req uses in tgs_req pa_data
            0x00, 0x00, 0x00, 0x00,
        ]))),
        ticket: ExplicitContextTag3::from(ticket),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
        }),
    }))
}

#[cfg_attr(feature = "logging", instrument(level = "trace", ret))]
pub fn generate_ap_req(
    ticket: Ticket,
    session_key: &[u8],
    authenticator: &Authenticator,
    enc_params: &EncryptionParams,
    options: ApOptionsFlags,
) -> Result<ApReq> {
    let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
    let cipher = encryption_type.cipher();

    let encoded_authenticator = picky_asn1_der::to_vec(&authenticator)?;
    let encrypted_authenticator = cipher.encrypt(session_key, AP_REQ_AUTHENTICATOR, &encoded_authenticator)?;

    #[cfg(feature = "logging")]
    trace!(
        "AP_REQ authenticator: plain {:?}, encrypted: {:?}",
        encoded_authenticator,
        encrypted_authenticator
    );

    Ok(ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![AP_REQ_MSG_TYPE])),
        ap_options: ExplicitContextTag2::from(ApOptions::from(BitString::with_bytes(
            options.bits().to_be_bytes().to_vec(),
        ))),
        ticket: ExplicitContextTag3::from(ticket),
        authenticator: ExplicitContextTag4::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(encrypted_authenticator)),
        }),
    }))
}

// returns supported authentication types
pub fn get_mech_list() -> MechTypeList {
    MechTypeList::from(vec![MechType::from(oids::ms_krb5()), MechType::from(oids::krb5())])
}

pub fn generate_neg_token_init(username: &str, service_name: &str) -> Result<ApplicationTag0<GssApiNegInit>> {
    let krb5_neg_token_init: ApplicationTag<_, 0> = ApplicationTag::from(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(oids::krb5_user_to_user()),
        krb5_token_id: TGT_REQ_TOKEN_ID,
        krb_msg: TgtReq {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![TGT_REQ_MSG_TYPE])),
            server_name: ExplicitContextTag2::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string(service_name.into())?),
                    KerberosStringAsn1::from(IA5String::from_string(username.into())?),
                ])),
            }),
        },
    });

    Ok(ApplicationTag0(GssApiNegInit {
        oid: ObjectIdentifierAsn1::from(oids::spnego()),
        neg_token_init: ExplicitContextTag0::from(NegTokenInit {
            mech_types: Optional::from(Some(ExplicitContextTag0::from(get_mech_list()))),
            req_flags: Optional::from(None),
            mech_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(
                picky_asn1_der::to_vec(&krb5_neg_token_init)?,
            )))),
            mech_list_mic: Optional::from(None),
        }),
    }))
}

pub fn generate_neg_ap_req(ap_req: ApReq) -> Result<ExplicitContextTag1<NegTokenTarg>> {
    let krb_blob: ApplicationTag<_, 0> = ApplicationTag(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(oids::krb5_user_to_user()),
        krb5_token_id: AP_REQ_TOKEN_ID,
        krb_msg: ap_req,
    });

    Ok(ExplicitContextTag1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(ACCEPT_INCOMPLETE.to_vec())))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&krb_blob)?,
        )))),
        mech_list_mic: Optional::from(None),
    }))
}

pub fn generate_final_neg_token_targ(mech_list_mic: Option<Vec<u8>>) -> NegTokenTarg1 {
    NegTokenTarg1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(ACCEPT_COMPLETE.to_vec())))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(None),
        mech_list_mic: Optional::from(mech_list_mic.map(|v| ExplicitContextTag3::from(OctetStringAsn1::from(v)))),
    })
}

#[cfg_attr(feature = "logging", instrument(level = "trace", ret))]
pub fn generate_krb_priv_request(
    ticket: Ticket,
    session_key: &[u8],
    new_password: &[u8],
    authenticator: &Authenticator,
    enc_params: &EncryptionParams,
    seq_num: u32,
    address: &str,
) -> Result<KrbPrivMessage> {
    let ap_req = generate_ap_req(ticket, session_key, authenticator, enc_params, ApOptionsFlags::empty())?;

    let enc_part = EncKrbPrivPart::from(EncKrbPrivPartInner {
        user_data: ExplicitContextTag0::from(OctetStringAsn1::from(new_password.to_vec())),
        timestamp: Optional::from(None),
        usec: Optional::from(None),
        seq_number: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from_bytes_be_unsigned(
            seq_num.to_be_bytes().to_vec(),
        )))),
        s_address: ExplicitContextTag4::from(HostAddress {
            addr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NET_BIOS_ADDR_TYPE])),
            address: ExplicitContextTag1::from(OctetStringAsn1::from(address.as_bytes().to_vec())),
        }),
        r_address: Optional::from(None),
    });

    let encryption_type = enc_params.encryption_type.as_ref().unwrap_or(&DEFAULT_ENCRYPTION_TYPE);
    let cipher = encryption_type.cipher();

    let encryption_key = &authenticator.0.subkey.0.as_ref().unwrap().key_value.0;
    let encoded_krb_priv = picky_asn1_der::to_vec(&enc_part)?;

    let enc_part = cipher.encrypt(encryption_key, KRB_PRIV_ENC_PART, &encoded_krb_priv)?;

    #[cfg(feature = "logging")]
    trace!(
        "KRB_PRIV encryption key: {:?}. Encryption type: {:?}",
        encryption_key,
        encryption_type
    );
    #[cfg(feature = "logging")]
    trace!(
        "KRB_PRIV encrypted part: plain {:?}, encrypted {:?}",
        encoded_krb_priv,
        enc_part
    );

    let krb_priv = KrbPriv::from(KrbPrivInner {
        pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
        msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![KRB_PRIV])),
        enc_part: ExplicitContextTag3::from(EncryptedData {
            etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![encryption_type.into()])),
            kvno: Optional::from(None),
            cipher: ExplicitContextTag2::from(OctetStringAsn1::from(enc_part)),
        }),
    });

    Ok(KrbPrivMessage {
        ap_message: ApMessage::ApReq(ap_req),
        krb_priv,
    })
}
