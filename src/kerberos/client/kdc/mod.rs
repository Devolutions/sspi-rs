use crate::{Error, ErrorKind};
use picky_asn1_der::Asn1RawDer;
use picky_krb::data_types::{KrbResult, ResultExt};
use picky_krb::gss_api::IAKrbProxyMessage;
use picky_krb::messages::IAKerbCookie;
use serde::de::DeserializeOwned;

pub mod as_exchange;
pub mod tgs_exchange;

fn decode_kdc_reply<T: DeserializeOwned>(
    response: &[u8],
    iakerb: bool,
    iakerb_cookie: &mut IAKerbCookie,
    iakerb_gss_transcript: &mut Vec<u8>,
) -> crate::Result<KrbResult<T>> {
    if response.is_empty() {
        return Err(Error::new(ErrorKind::InternalError, "expected KDC reply message"));
    }

    let krb_result = if iakerb {
        let iakerb_proxy_msg = IAKrbProxyMessage::<Asn1RawDer>::decode_application_iakrb_proxy_message(response)?.0;
        *iakerb_cookie = iakerb_proxy_msg.header.cookie.0;
        iakerb_gss_transcript.extend_from_slice(response);

        let mut d = picky_asn1_der::Deserializer::new_from_bytes(&iakerb_proxy_msg.krb_msg.0);
        <KrbResult<T> as ResultExt<T>>::deserialize(&mut d)?
    } else {
        // first 4 bytes are message len. skipping them
        if response.len() < 4 {
            return Err(Error::new(
                ErrorKind::InternalError,
                "the KDC reply message is too small: expected at least 4 bytes",
            ));
        }

        let mut d = picky_asn1_der::Deserializer::new_from_bytes(&response[4..]);
        <KrbResult<T> as ResultExt<T>>::deserialize(&mut d)?
    };

    Ok(krb_result)
}

#[cfg(test)]
mod tests {
    use crate::kerberos::client::kdc::decode_kdc_reply;
    use crate::kerberos::messages::generate_iakrb_proxy_message;
    use picky_asn1::restricted_string::Ia5String;
    use picky_asn1::wrapper::{
        Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
        ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, GeneralStringAsn1, IntegerAsn1, OctetStringAsn1,
        Optional,
    };
    use picky_asn1_der::Asn1RawDer;
    use picky_krb::data_types::{
        EncryptedData, KerberosStringAsn1, KrbResult, PaData, PrincipalName, Ticket, TicketInner,
    };
    use picky_krb::messages::{AsRep, IAKerbCookie, KdcRep};

    fn as_rep_raw() -> Vec<u8> {
        vec![
            107, 130, 2, 192, 48, 130, 2, 188, 160, 3, 2, 1, 5, 161, 3, 2, 1, 11, 162, 43, 48, 41, 48, 39, 161, 3, 2,
            1, 19, 162, 32, 4, 30, 48, 28, 48, 26, 160, 3, 2, 1, 18, 161, 19, 27, 17, 69, 88, 65, 77, 80, 76, 69, 46,
            67, 79, 77, 109, 121, 117, 115, 101, 114, 163, 13, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 164,
            19, 48, 17, 160, 3, 2, 1, 1, 161, 10, 48, 8, 27, 6, 109, 121, 117, 115, 101, 114, 165, 130, 1, 64, 97, 130,
            1, 60, 48, 130, 1, 56, 160, 3, 2, 1, 5, 161, 13, 27, 11, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 162,
            32, 48, 30, 160, 3, 2, 1, 2, 161, 23, 48, 21, 27, 6, 107, 114, 98, 116, 103, 116, 27, 11, 69, 88, 65, 77,
            80, 76, 69, 46, 67, 79, 77, 163, 129, 255, 48, 129, 252, 160, 3, 2, 1, 18, 161, 3, 2, 1, 1, 162, 129, 239,
            4, 129, 236, 229, 108, 127, 175, 235, 22, 11, 195, 254, 62, 101, 153, 38, 64, 83, 27, 109, 35, 253, 196,
            59, 21, 69, 124, 36, 145, 117, 98, 146, 80, 179, 3, 37, 191, 32, 69, 182, 19, 45, 245, 225, 205, 40, 33,
            245, 64, 96, 250, 167, 233, 4, 72, 222, 172, 23, 0, 66, 223, 108, 229, 56, 177, 9, 85, 252, 15, 249, 242,
            189, 240, 4, 45, 235, 72, 169, 207, 81, 60, 129, 61, 66, 191, 142, 254, 11, 231, 111, 219, 21, 155, 126,
            70, 20, 99, 169, 235, 134, 171, 70, 71, 238, 136, 156, 165, 46, 170, 53, 25, 233, 107, 78, 36, 141, 183,
            78, 123, 45, 239, 14, 239, 119, 178, 115, 146, 115, 93, 240, 130, 198, 225, 13, 175, 99, 71, 193, 252, 183,
            41, 77, 109, 158, 237, 159, 185, 164, 103, 132, 248, 223, 55, 201, 44, 74, 25, 130, 188, 76, 255, 128, 199,
            71, 137, 1, 154, 144, 17, 237, 167, 157, 123, 253, 150, 129, 189, 10, 121, 148, 70, 137, 249, 133, 43, 223,
            160, 250, 202, 175, 15, 6, 199, 177, 181, 237, 224, 226, 26, 230, 123, 219, 223, 164, 249, 206, 41, 40, 32,
            190, 14, 3, 196, 163, 41, 56, 118, 157, 114, 87, 233, 89, 178, 246, 74, 224, 43, 207, 53, 131, 32, 78, 111,
            114, 246, 153, 100, 110, 7, 166, 130, 1, 25, 48, 130, 1, 21, 160, 3, 2, 1, 18, 162, 130, 1, 12, 4, 130, 1,
            8, 14, 180, 181, 83, 180, 223, 85, 143, 123, 246, 189, 59, 97, 51, 73, 198, 5, 147, 87, 42, 240, 94, 250,
            203, 240, 45, 46, 190, 32, 135, 13, 24, 123, 127, 223, 30, 53, 200, 226, 164, 80, 207, 227, 34, 63, 139, 3,
            129, 240, 10, 193, 222, 123, 0, 64, 28, 232, 140, 63, 22, 143, 211, 114, 182, 138, 233, 103, 39, 233, 158,
            119, 215, 73, 227, 197, 80, 98, 48, 60, 62, 71, 207, 233, 144, 160, 28, 203, 79, 242, 40, 197, 224, 246,
            84, 9, 184, 188, 250, 231, 190, 97, 255, 41, 234, 238, 213, 203, 3, 192, 160, 220, 78, 78, 197, 45, 255,
            176, 13, 190, 245, 35, 208, 12, 80, 93, 81, 65, 252, 199, 184, 202, 197, 95, 49, 179, 237, 64, 116, 52,
            220, 109, 123, 202, 78, 63, 146, 121, 178, 168, 157, 84, 80, 246, 250, 75, 69, 93, 184, 48, 115, 32, 139,
            4, 90, 164, 30, 208, 100, 37, 220, 168, 165, 2, 224, 124, 102, 164, 130, 34, 66, 134, 131, 16, 7, 206, 32,
            138, 30, 217, 225, 125, 69, 82, 78, 127, 73, 216, 235, 130, 159, 41, 23, 28, 197, 19, 39, 207, 144, 160,
            197, 11, 85, 39, 102, 167, 237, 83, 132, 78, 165, 215, 173, 61, 90, 113, 215, 201, 213, 158, 19, 190, 68,
            135, 94, 136, 63, 105, 119, 225, 127, 193, 148, 33, 74, 41, 154, 68, 104, 52, 227, 188, 19, 62, 26, 55, 15,
            20, 53, 221, 200, 137, 197, 2, 243,
        ]
    }

    fn as_rep() -> AsRep {
        AsRep::from(KdcRep {
            pvno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1(vec![11])),
            padata: Optional::from(Some(ExplicitContextTag2::from(Asn1SequenceOf::from(vec![PaData {
                padata_type: ExplicitContextTag1::from(IntegerAsn1(vec![19])),
                padata_data: ExplicitContextTag2::from(OctetStringAsn1(vec![
                    48, 28, 48, 26, 160, 3, 2, 1, 18, 161, 19, 27, 17, 69, 88, 65, 77, 80, 76, 69, 46, 67, 79, 77, 109,
                    121, 117, 115, 101, 114,
                ])),
            }])))),
            crealm: ExplicitContextTag3::from(GeneralStringAsn1::from(
                Ia5String::from_string("EXAMPLE.COM".to_owned()).unwrap(),
            )),
            cname: ExplicitContextTag4::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1(vec![1])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![GeneralStringAsn1::from(
                    Ia5String::from_string("myuser".to_owned()).unwrap(),
                )])),
            }),
            ticket: ExplicitContextTag5::from(Ticket::from(TicketInner {
                tkt_vno: ExplicitContextTag0::from(IntegerAsn1(vec![5])),
                realm: ExplicitContextTag1::from(GeneralStringAsn1::from(
                    Ia5String::from_string("EXAMPLE.COM".to_owned()).unwrap(),
                )),
                sname: ExplicitContextTag2::from(PrincipalName {
                    name_type: ExplicitContextTag0::from(IntegerAsn1(vec![2])),
                    name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                        KerberosStringAsn1::from(Ia5String::from_string("krbtgt".to_owned()).unwrap()),
                        KerberosStringAsn1::from(Ia5String::from_string("EXAMPLE.COM".to_owned()).unwrap()),
                    ])),
                }),
                enc_part: ExplicitContextTag3::from(EncryptedData {
                    etype: ExplicitContextTag0::from(IntegerAsn1(vec![18])),
                    kvno: Optional::from(Some(ExplicitContextTag1::from(IntegerAsn1(vec![1])))),
                    cipher: ExplicitContextTag2::from(OctetStringAsn1::from(vec![
                        229, 108, 127, 175, 235, 22, 11, 195, 254, 62, 101, 153, 38, 64, 83, 27, 109, 35, 253, 196, 59,
                        21, 69, 124, 36, 145, 117, 98, 146, 80, 179, 3, 37, 191, 32, 69, 182, 19, 45, 245, 225, 205,
                        40, 33, 245, 64, 96, 250, 167, 233, 4, 72, 222, 172, 23, 0, 66, 223, 108, 229, 56, 177, 9, 85,
                        252, 15, 249, 242, 189, 240, 4, 45, 235, 72, 169, 207, 81, 60, 129, 61, 66, 191, 142, 254, 11,
                        231, 111, 219, 21, 155, 126, 70, 20, 99, 169, 235, 134, 171, 70, 71, 238, 136, 156, 165, 46,
                        170, 53, 25, 233, 107, 78, 36, 141, 183, 78, 123, 45, 239, 14, 239, 119, 178, 115, 146, 115,
                        93, 240, 130, 198, 225, 13, 175, 99, 71, 193, 252, 183, 41, 77, 109, 158, 237, 159, 185, 164,
                        103, 132, 248, 223, 55, 201, 44, 74, 25, 130, 188, 76, 255, 128, 199, 71, 137, 1, 154, 144, 17,
                        237, 167, 157, 123, 253, 150, 129, 189, 10, 121, 148, 70, 137, 249, 133, 43, 223, 160, 250,
                        202, 175, 15, 6, 199, 177, 181, 237, 224, 226, 26, 230, 123, 219, 223, 164, 249, 206, 41, 40,
                        32, 190, 14, 3, 196, 163, 41, 56, 118, 157, 114, 87, 233, 89, 178, 246, 74, 224, 43, 207, 53,
                        131, 32, 78, 111, 114, 246, 153, 100, 110, 7,
                    ])),
                }),
            })),
            enc_part: ExplicitContextTag6::from(EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1(vec![18])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(vec![
                    14, 180, 181, 83, 180, 223, 85, 143, 123, 246, 189, 59, 97, 51, 73, 198, 5, 147, 87, 42, 240, 94,
                    250, 203, 240, 45, 46, 190, 32, 135, 13, 24, 123, 127, 223, 30, 53, 200, 226, 164, 80, 207, 227,
                    34, 63, 139, 3, 129, 240, 10, 193, 222, 123, 0, 64, 28, 232, 140, 63, 22, 143, 211, 114, 182, 138,
                    233, 103, 39, 233, 158, 119, 215, 73, 227, 197, 80, 98, 48, 60, 62, 71, 207, 233, 144, 160, 28,
                    203, 79, 242, 40, 197, 224, 246, 84, 9, 184, 188, 250, 231, 190, 97, 255, 41, 234, 238, 213, 203,
                    3, 192, 160, 220, 78, 78, 197, 45, 255, 176, 13, 190, 245, 35, 208, 12, 80, 93, 81, 65, 252, 199,
                    184, 202, 197, 95, 49, 179, 237, 64, 116, 52, 220, 109, 123, 202, 78, 63, 146, 121, 178, 168, 157,
                    84, 80, 246, 250, 75, 69, 93, 184, 48, 115, 32, 139, 4, 90, 164, 30, 208, 100, 37, 220, 168, 165,
                    2, 224, 124, 102, 164, 130, 34, 66, 134, 131, 16, 7, 206, 32, 138, 30, 217, 225, 125, 69, 82, 78,
                    127, 73, 216, 235, 130, 159, 41, 23, 28, 197, 19, 39, 207, 144, 160, 197, 11, 85, 39, 102, 167,
                    237, 83, 132, 78, 165, 215, 173, 61, 90, 113, 215, 201, 213, 158, 19, 190, 68, 135, 94, 136, 63,
                    105, 119, 225, 127, 193, 148, 33, 74, 41, 154, 68, 104, 52, 227, 188, 19, 62, 26, 55, 15, 20, 53,
                    221, 200, 137, 197, 2, 243,
                ])),
            }),
        })
    }

    #[test]
    fn decode_kdc_reply_from_iakerb_proxy() {
        let iakerb = true;
        let mut iakerb_cookie = IAKerbCookie::default();
        let mut iakerb_gss_transcript = Vec::new();

        let expected_cookie = Some(ExplicitContextTag2::from(OctetStringAsn1::from(vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        ])));
        let kdc_reply_raw = generate_iakrb_proxy_message(expected_cookie.clone(), Asn1RawDer(as_rep_raw())).unwrap();

        let kdc_reply: KrbResult<AsRep> =
            decode_kdc_reply(&kdc_reply_raw, iakerb, &mut iakerb_cookie, &mut iakerb_gss_transcript).unwrap();

        assert_eq!(kdc_reply, Ok(as_rep()));
        assert_eq!(iakerb_cookie, expected_cookie);
        assert_eq!(iakerb_gss_transcript, kdc_reply_raw);
    }

    #[test]
    fn decode_kdc_reply_from_external_kdc() {
        let iakerb = false;
        let iakerb_cookie = IAKerbCookie::default();
        let iakerb_gss_transcript = Vec::new();

        // Placeholder for message length. It is not validated, so it can be any value.
        let mut kdc_reply_raw = vec![0; 4];
        kdc_reply_raw.extend_from_slice(&as_rep_raw());

        let kdc_reply: KrbResult<AsRep> = decode_kdc_reply(
            &kdc_reply_raw,
            iakerb,
            &mut iakerb_cookie.clone(),
            &mut iakerb_gss_transcript.clone(),
        )
        .unwrap();

        assert_eq!(kdc_reply, Ok(as_rep()));
        assert_eq!(iakerb_cookie, None);
        assert_eq!(iakerb_gss_transcript, Vec::new());
    }
}
