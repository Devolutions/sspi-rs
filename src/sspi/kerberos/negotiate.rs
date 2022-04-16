use std::{
    convert::TryFrom,
    fmt::Debug,
    io,
    io::{Cursor, Read, Write},
};

use oid::ObjectIdentifier;
use picky_asn1::{
    restricted_string::IA5String,
    wrapper::{
        Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1,
        ExplicitContextTag2, ExplicitContextTag3, IntegerAsn1, ObjectIdentifierAsn1,
        OctetStringAsn1, Optional,
    },
};
use picky_asn1_der::{application_tag::ApplicationTag, Asn1RawDer};
use picky_krb::{
    constants::{
        oids::{KRB5, KRB5_USER_TO_USER, MS_KRB5, SPNEGO},
        types::TGT_REQ_MSG_TYPE,
    },
    data_types::{KerberosStringAsn1, PrincipalName, Ticket},
    messages::ApReq,
};
use serde::{ser, Deserialize, Serialize};

use crate::sspi::kerberos::KERBEROS_VERSION;

const AP_REQ_TOKEN_ID: [u8; 2] = [0x01, 0x00];
const TGT_REQ_TOKEN_ID: [u8; 2] = [0x04, 0x00];

pub type MechType = ObjectIdentifierAsn1;

pub type MechTypeList = Asn1SequenceOf<MechType>;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct NegTokenInit {
    #[serde(default)]
    pub mech_types: Optional<Option<ExplicitContextTag0<MechTypeList>>>,
    #[serde(default)]
    pub req_flags: Optional<Option<ExplicitContextTag1<BitStringAsn1>>>,
    #[serde(default)]
    pub mech_token: Optional<Option<ExplicitContextTag2<OctetStringAsn1>>>,
    #[serde(default)]
    pub mech_list_mic: Optional<Option<ExplicitContextTag3<OctetStringAsn1>>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct NegTokenTarg {
    #[serde(default)]
    neg_result: Optional<Option<ExplicitContextTag0<Asn1RawDer>>>,
    #[serde(default)]
    supported_mech: Optional<Option<ExplicitContextTag1<MechType>>>,
    #[serde(default)]
    response_token: Optional<Option<ExplicitContextTag2<OctetStringAsn1>>>,
    #[serde(default)]
    mech_list_mic: Optional<Option<ExplicitContextTag3<OctetStringAsn1>>>,
}

pub type NegTokenTarg1 = ExplicitContextTag1<NegTokenTarg>;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TgtReq {
    pub pvno: ExplicitContextTag0<IntegerAsn1>,
    pub msg_type: ExplicitContextTag1<IntegerAsn1>,
    pub server_name: ExplicitContextTag2<PrincipalName>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TgtRep {
    pub pvno: ExplicitContextTag0<IntegerAsn1>,
    pub msg_type: ExplicitContextTag1<IntegerAsn1>,
    pub ticket: ExplicitContextTag2<Ticket>,
}

#[derive(Debug, PartialEq)]
struct KrbMessage<T> {
    pub krb5_oid: ObjectIdentifierAsn1,
    pub krb5_token_id: [u8; 2],
    pub krb_msg: T,
}

impl<T: Serialize> KrbMessage<T> {
    pub fn im(&self, mut data: impl Write) -> Result<(), io::Error> {
        let mut oid = Vec::new();

        {
            let mut s = picky_asn1_der::Serializer::new_to_byte_buf(&mut oid);
            self.krb5_oid.serialize(&mut s).unwrap();
        }

        data.write_all(&oid).unwrap();
        data.write_all(&self.krb5_token_id).unwrap();
        data.write_all(&picky_asn1_der::to_vec(&self.krb_msg).unwrap())
            .unwrap();

        Ok(())
    }
}

// impl<'a, T: Deserialize<'a>> KrbMessage<T> {
//     pub fn deserialize(data: &'a [u8]) -> Self {
//         let mut cursor = Cursor::new(data);

//         let oid: ObjectIdentifierAsn1 = picky_asn1_der::from_reader(data).unwrap();

//         let mut token_id = [0, 0];
//         cursor.read_exact(&mut token_id).unwrap();

//         let msg: T = picky_asn1_der::from_reader(&data[(cursor.position() as usize)..]).unwrap();

//         Self {
//             krb5_oid: oid,
//             krb5_token_id: token_id,
//             krb_msg: msg,
//         }
//     }
// }

impl<T: ser::Serialize + Debug + PartialEq> ser::Serialize for KrbMessage<T> {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use serde::ser::Error;

        let mut buff = Vec::new();
        self.im(&mut buff).map_err(|e| {
            S::Error::custom(format!(
                "Cannot serialize GssApiMessage inner value: {:?}",
                e
            ))
        })?;

        Asn1RawDer(buff).serialize(serializer)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct GssApiNegInit {
    pub oid: ObjectIdentifierAsn1,
    pub neg_token_init: ExplicitContextTag0<NegTokenInit>,
}

#[derive(Debug, PartialEq)]
pub struct ApplicationTag0<T>(pub T);

impl<T: ser::Serialize + Debug + PartialEq> ser::Serialize for ApplicationTag0<T> {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use serde::ser::Error;

        let mut buff = Vec::new();
        {
            let mut s = picky_asn1_der::Serializer::new_to_byte_buf(&mut buff);
            self.0.serialize(&mut s).map_err(|e| {
                S::Error::custom(format!(
                    "Cannot serialize GssApiMessage inner value: {:?}",
                    e
                ))
            })?;
        }

        buff[0] = 0x60;

        Asn1RawDer(buff).serialize(serializer)
    }
}

pub fn generate_neg_ap_req(ap_req: ApReq) -> ExplicitContextTag1<NegTokenTarg> {
    let krb_blob: ApplicationTag<_, 0> = ApplicationTag(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(
            ObjectIdentifier::try_from(KRB5_USER_TO_USER).unwrap(),
        ),
        krb5_token_id: AP_REQ_TOKEN_ID,
        krb_msg: ap_req,
    });

    ExplicitContextTag1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(vec![
            // accept incomplete (1)
            0x0a, 0x01, 0x01,
        ])))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&krb_blob).unwrap(),
        )))),
        mech_list_mic: Optional::from(None),
    })
}

pub fn generate_neg_token_init(username: &str) -> ApplicationTag0<GssApiNegInit> {
    let krb5_neg_token_init: ApplicationTag<_, 0> = ApplicationTag::from(KrbMessage {
        krb5_oid: ObjectIdentifierAsn1::from(
            ObjectIdentifier::try_from(KRB5_USER_TO_USER).unwrap(),
        ),
        krb5_token_id: TGT_REQ_TOKEN_ID,
        krb_msg: TgtReq {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![KERBEROS_VERSION])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![TGT_REQ_MSG_TYPE])),
            server_name: ExplicitContextTag2::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![2])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    KerberosStringAsn1::from(IA5String::from_string("TERMSRV".into()).unwrap()),
                    KerberosStringAsn1::from(IA5String::from_string(username.into()).unwrap()),
                ])),
            }),
        },
    });

    ApplicationTag0(GssApiNegInit {
        oid: ObjectIdentifierAsn1::from(ObjectIdentifier::try_from(SPNEGO).unwrap()),
        neg_token_init: ExplicitContextTag0::from(NegTokenInit {
            mech_types: Optional::from(Some(ExplicitContextTag0::from(get_mech_list()))),
            req_flags: Optional::from(None),
            mech_token: Optional::from(Some(ExplicitContextTag2::from(OctetStringAsn1::from(
                picky_asn1_der::to_vec(&krb5_neg_token_init).unwrap(),
            )))),
            mech_list_mic: Optional::from(None),
        }),
    })
}

pub fn get_mech_list() -> MechTypeList {
    MechTypeList::from(vec![
        MechType::from(ObjectIdentifier::try_from(MS_KRB5).unwrap()),
        MechType::from(ObjectIdentifier::try_from(KRB5).unwrap()),
        // MechType::from(ObjectIdentifier::try_from("1.3.6.1.4.1.311.2.2.30").unwrap()),
        // MechType::from(ObjectIdentifier::try_from("1.3.6.1.4.1.311.2.2.10").unwrap()),
    ])
}

pub fn extract_tgt_ticket(data: &[u8]) -> Ticket {
    let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&data).unwrap();

    let resp_token = neg_token_targ.0.response_token.0.unwrap().0 .0;
    let mut c = Cursor::new(resp_token);

    let _oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut c).unwrap();

    let mut t = [0, 0];

    c.read_exact(&mut t).unwrap();

    let tgt_rep: TgtRep = picky_asn1_der::from_reader(&mut c).unwrap();

    tgt_rep.ticket.0
}

pub fn generate_final_neg_token_targ(mech_list_mic: Option<Vec<u8>>) -> NegTokenTarg1 {
    NegTokenTarg1::from(NegTokenTarg {
        neg_result: Optional::from(Some(ExplicitContextTag0::from(Asn1RawDer(vec![
            // accept complete (0)
            0x0a, 0x01, 0x00,
        ])))),
        supported_mech: Optional::from(None),
        response_token: Optional::from(None),
        mech_list_mic: Optional::from(
            mech_list_mic.map(|v| ExplicitContextTag3::from(OctetStringAsn1::from(v))),
        ),
    })
}

#[cfg(test)]
mod tests {
    use std::{
        convert::TryFrom,
        io::{Cursor, Read},
    };

    use super::{generate_neg_token_init, KrbMessage, TgtRep};
    use crate::sspi::{internal::credssp::TsRequest, kerberos::negotiate::NegTokenTarg1};
    use oid::ObjectIdentifier;
    use picky_asn1::wrapper::ObjectIdentifierAsn1;
    use picky_asn1_der::{application_tag::ApplicationTag, Asn1RawDer};

    #[test]
    fn test_neg_token_init() {
        let expected_data = vec![
            48, 129, 155, 160, 3, 2, 1, 6, 161, 129, 147, 48, 129, 144, 48, 129, 141, 160, 129,
            138, 4, 129, 135, 96, 129, 132, 6, 6, 43, 6, 1, 5, 5, 2, 160, 122, 48, 120, 160, 48,
            48, 46, 6, 9, 42, 134, 72, 130, 247, 18, 1, 2, 2, 6, 9, 42, 134, 72, 134, 247, 18, 1,
            2, 2, 6, 10, 43, 6, 1, 4, 1, 130, 55, 2, 2, 30, 6, 10, 43, 6, 1, 4, 1, 130, 55, 2, 2,
            10, 162, 68, 4, 66, 96, 64, 6, 10, 42, 134, 72, 134, 247, 18, 1, 2, 2, 3, 4, 0, 48, 48,
            160, 3, 2, 1, 5, 161, 3, 2, 1, 16, 162, 36, 48, 34, 160, 3, 2, 1, 2, 161, 27, 48, 25,
            27, 7, 84, 69, 82, 77, 83, 82, 86, 27, 14, 112, 51, 46, 113, 107, 97, 116, 105, 111,
            110, 46, 99, 111, 109,
        ];

        let mut ts_request = TsRequest::default();
        ts_request.nego_tokens =
            Some(picky_asn1_der::to_vec(&generate_neg_token_init("p3.qkation.com")).unwrap());

        let mut encoded_ts_request = Vec::new();
        ts_request
            .encode_ts_request(&mut encoded_ts_request)
            .unwrap();

        assert_eq!(expected_data, encoded_ts_request);
    }

    #[test]
    fn test_neg_token_targ() {
        let expected_data = vec![
            161, 130, 4, 53, 48, 130, 4, 49, 160, 3, 10, 1, 1, 161, 11, 6, 9, 42, 134, 72, 130,
            247, 18, 1, 2, 2, 162, 130, 4, 27, 4, 130, 4, 23, 96, 130, 4, 19, 6, 10, 42, 134, 72,
            134, 247, 18, 1, 2, 2, 3, 4, 1, 48, 130, 4, 1, 160, 3, 2, 1, 5, 161, 3, 2, 1, 17, 162,
            130, 3, 243, 97, 130, 3, 239, 48, 130, 3, 235, 160, 3, 2, 1, 5, 161, 13, 27, 11, 81,
            75, 65, 84, 73, 79, 78, 46, 67, 79, 77, 162, 32, 48, 30, 160, 3, 2, 1, 2, 161, 23, 48,
            21, 27, 6, 107, 114, 98, 116, 103, 116, 27, 11, 81, 75, 65, 84, 73, 79, 78, 46, 67, 79,
            77, 163, 130, 3, 177, 48, 130, 3, 173, 160, 3, 2, 1, 18, 161, 3, 2, 1, 2, 162, 130, 3,
            159, 4, 130, 3, 155, 136, 37, 252, 76, 19, 169, 78, 152, 85, 3, 21, 143, 36, 103, 252,
            166, 172, 192, 18, 171, 83, 225, 80, 62, 169, 23, 191, 125, 47, 67, 234, 215, 132, 246,
            183, 156, 127, 173, 220, 253, 27, 120, 232, 200, 82, 229, 33, 99, 197, 74, 167, 87,
            194, 247, 2, 124, 92, 24, 138, 136, 254, 251, 238, 122, 80, 237, 119, 91, 165, 123,
            253, 223, 178, 42, 190, 79, 254, 9, 121, 251, 245, 198, 64, 143, 164, 197, 74, 162,
            240, 179, 233, 40, 138, 66, 141, 111, 151, 164, 123, 124, 146, 180, 134, 220, 57, 39,
            224, 255, 164, 78, 243, 239, 238, 48, 46, 49, 201, 86, 234, 141, 71, 177, 59, 248, 148,
            108, 205, 129, 96, 146, 202, 114, 25, 68, 221, 86, 189, 31, 10, 204, 119, 27, 68, 139,
            200, 252, 187, 140, 62, 88, 43, 157, 86, 59, 48, 18, 5, 255, 162, 158, 174, 159, 108,
            178, 126, 189, 96, 128, 72, 184, 199, 5, 44, 154, 168, 63, 245, 95, 227, 222, 67, 73,
            196, 29, 80, 73, 111, 228, 43, 8, 61, 89, 204, 93, 133, 152, 245, 219, 113, 219, 247,
            242, 54, 129, 150, 25, 77, 92, 201, 146, 229, 10, 44, 175, 254, 186, 178, 147, 26, 253,
            20, 234, 59, 230, 134, 181, 151, 250, 167, 23, 224, 51, 242, 62, 103, 214, 95, 0, 160,
            134, 92, 139, 50, 29, 230, 165, 248, 141, 151, 117, 18, 80, 213, 111, 55, 244, 223, 40,
            238, 190, 253, 167, 31, 67, 106, 70, 4, 109, 117, 238, 88, 172, 249, 83, 204, 151, 254,
            129, 236, 130, 24, 151, 231, 145, 165, 28, 100, 181, 135, 57, 255, 224, 98, 17, 39,
            133, 223, 14, 58, 25, 16, 30, 129, 152, 185, 255, 127, 229, 0, 239, 39, 118, 45, 9,
            210, 213, 224, 210, 93, 79, 203, 81, 30, 251, 242, 101, 103, 63, 220, 53, 119, 161,
            250, 125, 59, 162, 47, 63, 31, 85, 175, 38, 250, 156, 136, 80, 166, 26, 10, 205, 181,
            47, 73, 15, 203, 216, 155, 238, 254, 18, 131, 25, 201, 126, 202, 80, 197, 222, 204, 14,
            43, 3, 177, 150, 103, 82, 160, 107, 179, 106, 126, 147, 107, 143, 160, 109, 186, 217,
            251, 22, 156, 162, 115, 208, 116, 36, 68, 147, 75, 191, 28, 121, 233, 26, 35, 145, 24,
            215, 138, 131, 166, 242, 105, 1, 200, 232, 117, 58, 194, 208, 118, 34, 81, 174, 103,
            225, 112, 223, 12, 21, 138, 229, 152, 220, 246, 235, 18, 105, 230, 91, 165, 254, 33,
            222, 26, 71, 77, 21, 223, 104, 245, 144, 11, 143, 96, 126, 241, 162, 238, 32, 241, 169,
            169, 207, 54, 8, 192, 246, 157, 152, 194, 26, 34, 116, 77, 68, 131, 236, 153, 59, 163,
            190, 21, 254, 100, 147, 215, 113, 231, 90, 145, 239, 92, 180, 156, 178, 188, 189, 2,
            174, 209, 111, 36, 4, 161, 31, 144, 112, 65, 147, 172, 8, 168, 218, 13, 253, 96, 110,
            63, 11, 5, 247, 207, 179, 31, 2, 94, 94, 11, 134, 210, 22, 63, 229, 132, 200, 108, 234,
            242, 93, 74, 165, 77, 34, 180, 204, 188, 61, 160, 89, 106, 62, 140, 81, 2, 104, 165,
            220, 116, 148, 60, 12, 126, 107, 253, 134, 99, 114, 137, 94, 160, 245, 151, 246, 215,
            200, 253, 168, 160, 188, 103, 7, 224, 134, 85, 101, 220, 118, 23, 81, 186, 43, 38, 146,
            64, 184, 13, 135, 124, 26, 1, 144, 129, 67, 191, 92, 118, 93, 232, 64, 208, 8, 164,
            173, 98, 169, 148, 0, 42, 134, 65, 41, 84, 243, 5, 164, 7, 50, 204, 92, 23, 63, 188,
            170, 60, 112, 191, 99, 118, 91, 100, 248, 54, 183, 78, 142, 88, 43, 77, 138, 58, 5,
            184, 181, 54, 223, 4, 85, 44, 110, 158, 31, 189, 30, 79, 72, 183, 97, 205, 84, 128, 70,
            87, 112, 133, 246, 129, 25, 252, 241, 183, 40, 201, 196, 97, 161, 68, 122, 30, 50, 124,
            84, 185, 71, 35, 60, 170, 144, 19, 191, 71, 91, 90, 233, 118, 130, 64, 240, 139, 222,
            17, 247, 214, 0, 71, 171, 222, 10, 220, 254, 179, 88, 107, 86, 247, 61, 70, 152, 83,
            148, 169, 59, 99, 96, 165, 176, 82, 63, 27, 107, 166, 237, 157, 234, 50, 242, 33, 239,
            137, 59, 99, 172, 2, 168, 161, 208, 149, 8, 99, 163, 73, 254, 252, 110, 2, 88, 66, 159,
            232, 77, 19, 91, 101, 42, 213, 88, 235, 84, 27, 156, 223, 213, 182, 58, 90, 49, 244,
            145, 233, 234, 248, 163, 167, 68, 100, 198, 174, 127, 250, 64, 174, 188, 121, 61, 159,
            63, 135, 37, 59, 34, 80, 27, 147, 75, 12, 71, 81, 169, 249, 67, 73, 79, 54, 44, 173,
            143, 193, 55, 64, 82, 123, 104, 37, 22, 102, 110, 85, 53, 53, 194, 228, 193, 249, 68,
            38, 49, 251, 7, 47, 239, 80, 136, 75, 217, 191, 220, 88, 73, 184, 236, 212, 91, 109,
            183, 190, 106, 141, 194, 125, 16, 133, 212, 122, 253, 204, 235, 165, 147, 107, 250,
            193, 66, 55, 99, 239, 20, 217, 121, 138, 170, 254, 66, 153, 50, 3, 101, 205, 219, 22,
            113, 208, 3, 175, 20, 4, 158, 124, 222, 209, 36, 73, 14, 211, 22, 146, 71, 17, 89, 80,
            92, 160, 65, 81,
        ];

        let neg_token_targ: NegTokenTarg1 = picky_asn1_der::from_bytes(&expected_data).unwrap();
        println!("{:?}", neg_token_targ);

        let mut resp_token = neg_token_targ.0.response_token.0.unwrap().0 .0;
        println!("{:?}", resp_token);
        let mut c = Cursor::new(resp_token);
        // let tgt_rep: ApplicationTag<KrbMessage<TgtRep>, 0> = picky_asn1_der::from_bytes(&resp_token).unwrap();
        let oid: ApplicationTag<Asn1RawDer, 0> = picky_asn1_der::from_reader(&mut c).unwrap();

        println!("{:?}", oid);

        let mut t = [0, 0];
        c.read_exact(&mut t);
        println!("t: {:?}", t);

        let tgt_rep: TgtRep = picky_asn1_der::from_reader(&mut c).unwrap();
        println!("{:?}", tgt_rep);

        let krb_message: ApplicationTag<_, 0> = ApplicationTag(KrbMessage {
            krb5_oid: ObjectIdentifierAsn1(ObjectIdentifier::try_from(oid.0 .0).unwrap()),
            krb5_token_id: t,
            krb_msg: tgt_rep,
        });

        println!("{:?}", picky_asn1_der::to_vec(&krb_message).unwrap());
    }
}
