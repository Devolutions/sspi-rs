//! ASN.1 structures used by the Remote Credential Guard logon credential.
//!
//! `picky-krb` does not model `KRB-CRED`, so the RFC 4120 structures are defined here,
//! together with the MS-CSSP `TSRemoteGuardCreds` structures.

use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag8,
    ExplicitContextTag9, ExplicitContextTag10, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::application_tag::ApplicationTag;
use picky_krb::data_types::{
    EncryptedData, EncryptionKey, HostAddress, HostAddresses, KerberosFlags, KerberosTime, Microseconds, PrincipalName,
    Realm, Ticket,
};
use serde::{Deserialize, Serialize};

/// `KRB-CRED` message type (RFC 4120 [7.5.7 Kerberos Message Types]).
///
/// [7.5.7 Kerberos Message Types]: https://www.rfc-editor.org/rfc/rfc4120#section-7.5.7
pub(crate) const KRB_CRED_MSG_TYPE: u8 = 22;

/// Key usage of the `EncKrbCredPart` encryption (RFC 4120 [7.5.1 Key Usage Numbers]).
///
/// [7.5.1 Key Usage Numbers]: https://www.rfc-editor.org/rfc/rfc4120#section-7.5.1
pub(crate) const KRB_CRED_ENC_PART_KEY_USAGE: i32 = 14;

const KRB_CRED_APPLICATION_TAG: u8 = 22;
const ENC_KRB_CRED_PART_APPLICATION_TAG: u8 = 29;

/// RFC 4120 [5.8.1 KRB_CRED Definition]
///
/// ```not_rust
/// KrbCredInfo     ::= SEQUENCE {
///         key             [0] EncryptionKey,
///         prealm          [1] Realm OPTIONAL,
///         pname           [2] PrincipalName OPTIONAL,
///         flags           [3] TicketFlags OPTIONAL,
///         authtime        [4] KerberosTime OPTIONAL,
///         starttime       [5] KerberosTime OPTIONAL,
///         endtime         [6] KerberosTime OPTIONAL,
///         renew-till      [7] KerberosTime OPTIONAL,
///         srealm          [8] Realm OPTIONAL,
///         sname           [9] PrincipalName OPTIONAL,
///         caddr           [10] HostAddresses OPTIONAL
/// }
/// ```
///
/// [5.8.1 KRB_CRED Definition]: https://www.rfc-editor.org/rfc/rfc4120#section-5.8.1
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub(crate) struct KrbCredInfo {
    pub(crate) key: ExplicitContextTag0<EncryptionKey>,
    #[serde(default)]
    pub(crate) prealm: Optional<Option<ExplicitContextTag1<Realm>>>,
    #[serde(default)]
    pub(crate) pname: Optional<Option<ExplicitContextTag2<PrincipalName>>>,
    #[serde(default)]
    pub(crate) flags: Optional<Option<ExplicitContextTag3<KerberosFlags>>>,
    #[serde(default)]
    pub(crate) auth_time: Optional<Option<ExplicitContextTag4<KerberosTime>>>,
    #[serde(default)]
    pub(crate) start_time: Optional<Option<ExplicitContextTag5<KerberosTime>>>,
    #[serde(default)]
    pub(crate) end_time: Optional<Option<ExplicitContextTag6<KerberosTime>>>,
    #[serde(default)]
    pub(crate) renew_till: Optional<Option<ExplicitContextTag7<KerberosTime>>>,
    #[serde(default)]
    pub(crate) srealm: Optional<Option<ExplicitContextTag8<Realm>>>,
    #[serde(default)]
    pub(crate) sname: Optional<Option<ExplicitContextTag9<PrincipalName>>>,
    #[serde(default)]
    pub(crate) caddr: Optional<Option<ExplicitContextTag10<HostAddresses>>>,
}

/// RFC 4120 [5.8.1 KRB_CRED Definition]
///
/// ```not_rust
/// EncKrbCredPart  ::= [APPLICATION 29] SEQUENCE {
///         ticket-info     [0] SEQUENCE OF KrbCredInfo,
///         nonce           [1] UInt32 OPTIONAL,
///         timestamp       [2] KerberosTime OPTIONAL,
///         usec            [3] Microseconds OPTIONAL,
///         s-address       [4] HostAddress OPTIONAL,
///         r-address       [5] HostAddress OPTIONAL
/// }
/// ```
///
/// [5.8.1 KRB_CRED Definition]: https://www.rfc-editor.org/rfc/rfc4120#section-5.8.1
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub(crate) struct EncKrbCredPartInner {
    pub(crate) ticket_info: ExplicitContextTag0<Asn1SequenceOf<KrbCredInfo>>,
    #[serde(default)]
    pub(crate) nonce: Optional<Option<ExplicitContextTag1<IntegerAsn1>>>,
    #[serde(default)]
    pub(crate) timestamp: Optional<Option<ExplicitContextTag2<KerberosTime>>>,
    #[serde(default)]
    pub(crate) usec: Optional<Option<ExplicitContextTag3<Microseconds>>>,
    #[serde(default)]
    pub(crate) s_address: Optional<Option<ExplicitContextTag4<HostAddress>>>,
    #[serde(default)]
    pub(crate) r_address: Optional<Option<ExplicitContextTag5<HostAddress>>>,
}

pub(crate) type EncKrbCredPart = ApplicationTag<EncKrbCredPartInner, ENC_KRB_CRED_PART_APPLICATION_TAG>;

/// RFC 4120 [5.8.1 KRB_CRED Definition]
///
/// ```not_rust
/// KRB-CRED        ::= [APPLICATION 22] SEQUENCE {
///         pvno            [0] INTEGER (5),
///         msg-type        [1] INTEGER (22),
///         tickets         [2] SEQUENCE OF Ticket,
///         enc-part        [3] EncryptedData -- EncKrbCredPart
/// }
/// ```
///
/// [5.8.1 KRB_CRED Definition]: https://www.rfc-editor.org/rfc/rfc4120#section-5.8.1
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub(crate) struct KrbCredInner {
    pub(crate) pvno: ExplicitContextTag0<IntegerAsn1>,
    pub(crate) msg_type: ExplicitContextTag1<IntegerAsn1>,
    pub(crate) tickets: ExplicitContextTag2<Asn1SequenceOf<Ticket>>,
    pub(crate) enc_part: ExplicitContextTag3<EncryptedData>,
}

pub(crate) type KrbCred = ApplicationTag<KrbCredInner, KRB_CRED_APPLICATION_TAG>;

/// MS-CSSP [2.2.1.2.3.1 TSRemoteGuardPackageCred]
///
/// ```not_rust
/// TSRemoteGuardPackageCred ::= SEQUENCE{
///     packageName [0] OCTET STRING,
///     credBuffer  [1] OCTET STRING,
/// }
/// ```
///
/// [2.2.1.2.3.1 TSRemoteGuardPackageCred]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/173eee44-1a2c-463f-b909-c15db01e68d7
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub(crate) struct TsRemoteGuardPackageCred {
    pub(crate) package_name: ExplicitContextTag0<OctetStringAsn1>,
    pub(crate) cred_buffer: ExplicitContextTag1<OctetStringAsn1>,
}

/// MS-CSSP [2.2.1.2.3 TSRemoteGuardCreds]
///
/// ```not_rust
/// TSRemoteGuardCreds ::= SEQUENCE{
///     logonCred           [0] TSRemoteGuardPackageCred,
///     supplementalCreds   [1] SEQUENCE OF TSRemoteGuardPackageCred OPTIONAL,
/// }
/// ```
///
/// [2.2.1.2.3 TSRemoteGuardCreds]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/7ef8229c-44ea-4c1b-867f-00369b882b38
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub(crate) struct TsRemoteGuardCreds {
    pub(crate) logon_cred: ExplicitContextTag0<TsRemoteGuardPackageCred>,
    #[serde(default)]
    pub(crate) supplemental_creds: Optional<Option<ExplicitContextTag1<Asn1SequenceOf<TsRemoteGuardPackageCred>>>>,
}

#[cfg(test)]
mod tests {
    use picky_asn1::bit_string::BitString;
    use picky_asn1::restricted_string::IA5String;
    use picky_asn1::wrapper::BitStringAsn1;
    use picky_krb::data_types::KerberosStringAsn1;

    use super::*;

    fn principal(name_type: u8, names: &[&str]) -> PrincipalName {
        PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(
                names
                    .iter()
                    .map(|name| KerberosStringAsn1::from(IA5String::from_string((*name).to_owned()).unwrap()))
                    .collect::<Vec<_>>(),
            )),
        }
    }

    fn realm(name: &str) -> Realm {
        KerberosStringAsn1::from(IA5String::from_string(name.to_owned()).unwrap())
    }

    #[test]
    fn remote_guard_creds_encoding_matches_ms_cssp_layout() {
        let creds = TsRemoteGuardCreds {
            logon_cred: ExplicitContextTag0::from(TsRemoteGuardPackageCred {
                package_name: ExplicitContextTag0::from(OctetStringAsn1::from(vec![b'K', 0])),
                cred_buffer: ExplicitContextTag1::from(OctetStringAsn1::from(vec![1, 2, 3])),
            }),
            supplemental_creds: Optional::from(None),
        };

        let encoded = picky_asn1_der::to_vec(&creds).unwrap();

        assert_eq!(
            encoded,
            [
                0x30, 0x11, 0xa0, 0x0f, 0x30, 0x0d, 0xa0, 0x04, 0x04, 0x02, b'K', 0x00, 0xa1, 0x05, 0x04, 0x03, 0x01,
                0x02, 0x03,
            ]
        );
        let decoded: TsRemoteGuardCreds = picky_asn1_der::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, creds);
    }

    #[test]
    fn krb_cred_round_trip_keeps_optional_fields() {
        let info = KrbCredInfo {
            key: ExplicitContextTag0::from(EncryptionKey {
                key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
                key_value: ExplicitContextTag1::from(OctetStringAsn1::from(vec![0x42; 32])),
            }),
            prealm: Optional::from(Some(ExplicitContextTag1::from(realm("EXAMPLE.TEST")))),
            pname: Optional::from(Some(ExplicitContextTag2::from(principal(1, &["alice"])))),
            flags: Optional::from(Some(ExplicitContextTag3::from(BitStringAsn1::from(
                BitString::with_bytes(vec![0x60, 0, 0, 0]),
            )))),
            auth_time: Optional::from(None),
            start_time: Optional::from(None),
            end_time: Optional::from(None),
            renew_till: Optional::from(None),
            srealm: Optional::from(Some(ExplicitContextTag8::from(realm("EXAMPLE.TEST")))),
            sname: Optional::from(Some(ExplicitContextTag9::from(principal(
                2,
                &["krbtgt", "EXAMPLE.TEST"],
            )))),
            caddr: Optional::from(None),
        };
        let enc_part = EncKrbCredPart::from(EncKrbCredPartInner {
            ticket_info: ExplicitContextTag0::from(Asn1SequenceOf::from(vec![info])),
            nonce: Optional::from(None),
            timestamp: Optional::from(None),
            usec: Optional::from(Some(ExplicitContextTag3::from(IntegerAsn1::from(vec![0x01])))),
            s_address: Optional::from(None),
            r_address: Optional::from(None),
        });

        let encoded = picky_asn1_der::to_vec(&enc_part).unwrap();
        assert_eq!(encoded.first(), Some(&0x7d));
        let decoded: EncKrbCredPart = picky_asn1_der::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, enc_part);

        let krb_cred = KrbCred::from(KrbCredInner {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![KRB_CRED_MSG_TYPE])),
            tickets: ExplicitContextTag2::from(Asn1SequenceOf::from(Vec::new())),
            enc_part: ExplicitContextTag3::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![18])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(vec![0xAA; 4])),
            }),
        });

        let encoded = picky_asn1_der::to_vec(&krb_cred).unwrap();
        assert_eq!(encoded.first(), Some(&0x76));
        let decoded: KrbCred = picky_asn1_der::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, krb_cred);
    }
}
