use alloc::borrow::{Cow, ToOwned};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

use picky::key::PrivateKey;

use crate::scard::SmartCard;
use crate::winscard::{DeviceTypeId, Icon, Protocol, ShareMode, WinScard, WinScardContext};
use crate::{Error, ErrorKind, WinScardResult};

/// Describes a smart card reader.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    pub name: Cow<'a, str>,
    pub icon: Icon<'a>,
    pub device_type_id: DeviceTypeId,
}

/// Describes smart card info used for the smart card creation
pub struct SmartCardInfo<'a> {
    pub pin: Vec<u8>,
    pub auth_cert_der: Vec<u8>,
    pub auth_pk: PrivateKey,
    pub reader: Reader<'a>,
}

impl<'a> SmartCardInfo<'a> {
    pub fn new(pin: Vec<u8>, auth_cert_der: Vec<u8>, auth_pk: PrivateKey) -> Self {
        // Value from captured API calls
        let icon = vec![0x50];
        let reader: Reader<'_> = Reader {
            name: Cow::Borrowed("Microsoft Virtual Smart Card 0"),
            icon: Icon::from(icon),
            device_type_id: DeviceTypeId::Tpm,
        };
        SmartCardInfo {
            pin,
            auth_cert_der,
            auth_pk,
            reader,
        }
    }
}

/// Represents the resource manager context (the scope).
pub struct ScardContext<'a> {
    smart_cards_info: Vec<SmartCardInfo<'a>>,
}

impl<'a> ScardContext<'a> {
    /// Creates a new smart card based on the list of smart card readers
    pub fn new(smart_cards_info: Vec<SmartCardInfo<'a>>) -> Self {
        let mut cache = BTreeMap::new();
        cache.insert(
            "Cached_CardProperty_Read Only Mode_0".into(),
            vec![1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0],
        );
        cache.insert(
            "Cached_CardProperty_Cache Mode_0".into(),
            vec![1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0],
        );
        cache.insert(
            "Cached_CardProperty_Supports Windows x.509 Enrollment_0".into(),
            vec![1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0],
        );
        cache.insert(
            "Cached_GeneralFile/mscp/cmapfile".into(),
            vec![
                1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 86, 0, 0, 0, 116, 0, 101, 0, 45, 0, 82, 0, 68, 0, 80, 0, 115, 0,
                109, 0, 97, 0, 114, 0, 116, 0, 99, 0, 97, 0, 114, 0, 100, 0, 108, 0, 111, 0, 103, 0, 111, 0, 110, 0,
                53, 0, 45, 0, 102, 0, 99, 0, 51, 0, 54, 0, 102, 0, 99, 0, 49, 0, 56, 0, 45, 0, 101, 0, 48, 0, 45, 0,
                50, 0, 53, 0, 56, 0, 57, 0, 53, 0, 0, 0, 3, 0, 0, 0, 0, 8,
            ],
        );
        cache.insert(
            "Cached_ContainerProperty_PIN Identifier_0".into(),
            vec![1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0],
        );
        cache.insert("Cached_ContainerInfo_00".into(), {
            let mut cache_file_data = Vec::new();
            cache_file_data.extend_from_slice(&[1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0x24, 0x01, 0, 0]); // header

            cache_file_data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0x01, 0x00, 0x00]); // container info header

            // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-publickeystruc
            // PUBLICKEYSTRUC
            cache_file_data.push(0x6); // bType = PUBLICKEYBLOB
            cache_file_data.push(0x2); // bVersion = 0x2
            cache_file_data.extend_from_slice(&[0x00, 0x00]); // reserved
            cache_file_data.extend_from_slice(&[0x00, 0xa4, 0x00, 0x00]); // aiKeyAlg = CALG_RSA_KEYX

            // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey
            // RSAPUBKEY
            cache_file_data.extend_from_slice(b"RSA1"); // magic = RSA1
            cache_file_data.extend_from_slice(&2048_u32.to_le_bytes()); // bitlen = 2048
            cache_file_data.extend_from_slice(&[0x01, 0x00, 0x01, 0x00]); // pubexp

            cache_file_data.extend_from_slice(&[
                239, 147, 212, 173, 94, 5, 89, 121, 113, 28, 111, 205, 164, 223, 203, 19, 167, 194, 4, 253, 62, 6, 96,
                11, 212, 10, 27, 155, 14, 184, 33, 153, 251, 227, 18, 129, 212, 185, 13, 212, 196, 188, 26, 124, 183,
                169, 205, 212, 93, 129, 19, 15, 198, 246, 216, 208, 0, 26, 107, 76, 158, 130, 105, 217, 252, 96, 64,
                176, 115, 190, 197, 126, 83, 92, 32, 14, 150, 24, 61, 215, 181, 10, 118, 143, 131, 113, 79, 235, 35,
                71, 5, 74, 155, 212, 94, 111, 147, 174, 23, 22, 49, 94, 75, 149, 177, 170, 36, 189, 206, 5, 185, 194,
                214, 124, 216, 30, 33, 106, 250, 188, 81, 248, 140, 155, 202, 17, 21, 101, 115, 123, 34, 154, 48, 98,
                169, 43, 252, 53, 186, 160, 249, 154, 185, 112, 246, 34, 149, 116, 237, 221, 36, 165, 59, 208, 203, 49,
                194, 104, 93, 145, 16, 173, 31, 120, 5, 243, 197, 48, 242, 50, 108, 134, 110, 239, 21, 9, 151, 40, 110,
                149, 213, 252, 117, 62, 200, 168, 238, 204, 240, 16, 101, 66, 135, 164, 39, 204, 216, 143, 81, 44, 210,
                48, 240, 204, 162, 184, 53, 133, 2, 122, 74, 63, 25, 40, 36, 190, 215, 121, 0, 73, 178, 213, 114, 116,
                165, 152, 226, 205, 52, 98, 39, 139, 15, 53, 213, 205, 226, 48, 110, 249, 76, 110, 215, 201, 216, 90,
                73, 228, 203, 140, 69, 4, 190, 53, 216, 168,
            ]); // public key

            cache_file_data
        });
        cache.insert("Cached_GeneralFile/mscp/kxc00".into(), {
            let mut cache_file_data = Vec::new();

            cache_file_data.extend_from_slice(&[1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0x91, 0x04, 0, 0]); // header
            cache_file_data.extend_from_slice(&[0x01, 0x00]); // purpose of this 2 bytes is unknown
            cache_file_data.extend_from_slice(&[0xF0, 0x05]); // uncompressed certificate data len
            let compressed_key_exchange_certificate = &[
                120, 218, 51, 104, 98, 125, 99, 208, 196, 114, 101, 1, 51, 19, 35, 19, 147, 112, 29, 3, 3, 131, 136,
                59, 107, 249, 46, 9, 193, 121, 59, 24, 64, 64, 196, 128, 151, 141, 83, 171, 205, 163, 237, 59, 47, 35,
                35, 55, 43, 131, 65, 176, 161, 176, 129, 32, 27, 23, 231, 36, 181, 206, 201, 159, 116, 82, 24, 37, 197,
                152, 147, 243, 115, 13, 197, 13, 68, 81, 4, 217, 83, 43, 18, 115, 11, 114, 82, 13, 149, 13, 20, 217,
                152, 67, 89, 152, 133, 165, 160, 34, 186, 225, 158, 126, 186, 158, 97, 206, 110, 38, 22, 102, 254, 6,
                198, 193, 186, 206, 142, 6, 114, 226, 188, 70, 198, 134, 134, 134, 166, 134, 166, 6, 166, 134, 198, 81,
                64, 174, 41, 132, 107, 8, 226, 26, 248, 146, 104, 41, 159, 1, 15, 196, 82, 214, 208, 226, 212, 162, 98,
                67, 94, 3, 110, 8, 159, 165, 160, 220, 208, 196, 160, 137, 81, 9, 217, 91, 140, 172, 12, 204, 77, 140,
                252, 12, 64, 113, 46, 166, 38, 70, 70, 134, 21, 55, 76, 247, 177, 184, 246, 156, 126, 226, 25, 117,
                227, 228, 245, 60, 159, 159, 121, 6, 143, 206, 94, 53, 229, 239, 86, 79, 50, 57, 251, 104, 198, 210,
                146, 162, 171, 155, 60, 25, 42, 175, 239, 83, 209, 144, 180, 247, 170, 98, 106, 53, 221, 177, 232, 204,
                7, 131, 75, 58, 129, 253, 55, 206, 168, 47, 105, 119, 74, 21, 248, 112, 230, 221, 138, 19, 118, 165,
                127, 174, 78, 205, 211, 152, 206, 41, 250, 62, 175, 45, 199, 232, 147, 193, 209, 207, 172, 21, 242,
                107, 5, 38, 198, 102, 28, 50, 60, 125, 193, 122, 169, 202, 221, 183, 37, 83, 149, 190, 21, 236, 156,
                245, 115, 193, 46, 211, 63, 218, 43, 147, 12, 102, 41, 85, 23, 167, 138, 10, 158, 154, 221, 243, 35,
                112, 207, 175, 44, 69, 185, 27, 53, 215, 14, 237, 100, 61, 183, 87, 101, 213, 198, 169, 222, 113, 134,
                98, 226, 235, 38, 231, 199, 93, 153, 237, 197, 234, 174, 252, 218, 191, 176, 185, 191, 140, 107, 235,
                117, 91, 137, 105, 124, 10, 49, 193, 117, 71, 247, 21, 111, 112, 72, 248, 115, 51, 179, 105, 158, 79,
                182, 20, 195, 133, 27, 223, 142, 241, 11, 55, 198, 94, 57, 187, 114, 123, 141, 212, 158, 35, 87, 120,
                119, 94, 105, 20, 122, 252, 123, 166, 226, 14, 190, 217, 210, 92, 87, 184, 19, 216, 236, 254, 178, 28,
                90, 46, 124, 250, 254, 146, 179, 249, 50, 133, 149, 145, 172, 113, 107, 175, 76, 126, 207, 196, 204,
                200, 192, 184, 184, 137, 105, 175, 65, 19, 211, 78, 3, 27, 54, 78, 109, 54, 70, 22, 198, 38, 115, 81,
                118, 22, 125, 3, 93, 54, 85, 24, 151, 163, 229, 224, 158, 228, 230, 47, 211, 21, 218, 183, 78, 21, 109,
                249, 240, 196, 174, 125, 231, 244, 32, 191, 230, 185, 175, 66, 231, 236, 205, 99, 98, 76, 1, 166, 41,
                3, 121, 96, 192, 203, 170, 178, 72, 24, 136, 177, 113, 65, 245, 137, 48, 49, 177, 113, 0, 217, 172,
                172, 236, 204, 76, 6, 124, 32, 5, 252, 140, 140, 255, 89, 88, 152, 153, 88, 23, 24, 104, 34, 172, 227,
                98, 145, 49, 144, 2, 70, 37, 146, 70, 3, 46, 36, 173, 178, 32, 173, 124, 44, 98, 44, 34, 85, 174, 159,
                46, 28, 95, 192, 193, 94, 224, 173, 125, 252, 93, 93, 214, 163, 105, 143, 188, 37, 33, 86, 43, 131,
                172, 110, 16, 241, 60, 29, 119, 195, 141, 65, 75, 167, 172, 192, 203, 55, 237, 215, 250, 182, 234, 103,
                59, 211, 13, 26, 31, 128, 84, 200, 179, 52, 222, 48, 104, 188, 106, 208, 120, 105, 65, 227, 249, 5,
                141, 103, 218, 26, 79, 230, 164, 36, 22, 88, 233, 235, 235, 59, 251, 217, 226, 78, 181, 58, 64, 89, 52,
                81, 144, 144, 179, 75, 0, 136, 10, 40, 77, 202, 201, 76, 86, 53, 50, 240, 78, 173, 4, 146, 193, 169,
                69, 101, 153, 201, 169, 197, 32, 41, 100, 182, 115, 126, 94, 90, 102, 122, 105, 81, 98, 73, 102, 126,
                158, 142, 139, 51, 204, 62, 16, 19, 152, 196, 237, 147, 83, 139, 74, 50, 211, 50, 147, 19, 75, 82, 131,
                82, 203, 242, 147, 193, 234, 124, 50, 139, 75, 236, 147, 18, 139, 83, 237, 243, 147, 178, 82, 147, 75,
                156, 115, 18, 139, 139, 109, 147, 131, 124, 92, 128, 18, 69, 153, 73, 165, 32, 69, 1, 249, 153, 121,
                37, 6, 141, 103, 96, 225, 197, 200, 200, 210, 184, 223, 160, 113, 143, 65, 227, 78, 152, 144, 1, 83,
                91, 227, 26, 162, 253, 234, 232, 233, 72, 77, 143, 57, 58, 35, 188, 134, 197, 51, 112, 73, 160, 118,
                199, 210, 146, 140, 252, 162, 204, 146, 74, 3, 109, 80, 132, 9, 178, 168, 24, 40, 45, 80, 64, 74, 22,
                204, 11, 132, 120, 4, 64, 89, 219, 1, 106, 139, 30, 208, 10, 180, 146, 139, 25, 148, 179, 179, 21, 252,
                217, 23, 206, 219, 248, 234, 197, 26, 254, 99, 119, 191, 207, 209, 157, 33, 239, 38, 117, 131, 131, 35,
                227, 111, 142, 109, 250, 202, 124, 185, 76, 185, 163, 247, 242, 63, 231, 221, 233, 83, 141, 190, 231,
                226, 190, 115, 114, 245, 196, 104, 137, 208, 83, 147, 56, 42, 110, 181, 212, 117, 30, 97, 109, 249, 29,
                181, 215, 234, 201, 130, 45, 95, 79, 231, 123, 104, 253, 141, 59, 238, 117, 101, 101, 238, 15, 67, 193,
                112, 177, 9, 234, 21, 73, 139, 178, 255, 60, 57, 82, 254, 60, 136, 101, 241, 20, 25, 209, 204, 95, 12,
                199, 22, 78, 203, 17, 158, 195, 248, 38, 139, 103, 73, 226, 91, 239, 151, 187, 13, 52, 158, 237, 177,
                113, 239, 124, 97, 243, 97, 198, 213, 217, 79, 195, 245, 86, 30, 177, 95, 127, 169, 174, 60, 104, 109,
                97, 90, 117, 209, 151, 6, 46, 245, 227, 203, 231, 76, 91, 252, 80, 49, 229, 137, 44, 95, 208, 115, 245,
                183, 59, 125, 46, 118, 52, 37, 179, 175, 117, 158, 112, 106, 18, 99, 203, 61, 118, 183, 89, 81, 190,
                251, 86, 215, 204, 62, 61, 33, 187, 60, 45, 101, 135, 159, 180, 230, 39, 158, 151, 175, 22, 221, 235,
                104, 189, 191, 118, 183, 75, 196, 174, 37, 58, 188, 101, 165, 43, 102, 177, 62, 149, 77, 101, 42, 244,
                249, 38, 233, 88, 122, 137, 35, 176, 82, 205, 96, 121, 196, 122, 127, 206, 202, 196, 139, 125, 213,
                154, 79, 4, 1, 218, 252, 20, 1,
            ];
            cache_file_data.extend_from_slice(compressed_key_exchange_certificate); // flate2 compressed der encoded user key exchange certificate

            cache_file_data
        });
        cache.insert(
            "Cached_CardProperty_Capabilities_0".into(),
            vec![
                1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            ],
        );

        cache.insert("Cached_CardmodFile\\Cached_Pin_Freshness".into(), vec![0, 0]);
        cache.insert("Cached_CardmodFile\\Cached_File_Freshness".into(), vec![7, 0]);
        cache.insert("Cached_CardmodFile\\Cached_Container_Freshness".into(), vec![1, 0]);

        // cache.insert("Cached_CardmodFile\\Cached_PIV_Authentication_Key".into(), vec![1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0]);
        // cache.insert("Cached_CardmodFile\\Cached_PIV_Signature_Key".into(), vec![1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0]);
        // cache.insert("Cached_CardmodFile\\Cached_PIV_Key_Management_Key".into(), vec![1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0]);
        // cache.insert("Cached_CardmodFile\\Cached_PIV_Card_Authentication_Key".into(), vec![1, 0, 1, 0, 7, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0]);

        Self {
            smart_cards_info,
            cache,
        }
    }
}

impl<'a> WinScardContext for ScardContext<'a> {
    fn connect(
        &self,
        reader_name: &str,
        _share_mode: ShareMode,
        _protocol: Option<Protocol>,
    ) -> WinScardResult<Box<dyn WinScard>> {
        let smart_card_info = self
            .smart_cards_info
            .iter()
            .find(|card_info| card_info.reader.name == reader_name)
            .ok_or_else(|| Error::new(ErrorKind::UnknownReader, format!("reader {:?} not found", reader_name)))?;

        Ok(Box::new(SmartCard::new(
            Cow::Owned(reader_name.to_owned()),
            smart_card_info.pin.clone(),
            smart_card_info.auth_cert_der.clone(),
            smart_card_info.auth_pk.clone(),
        )?))
    }

    fn list_readers(&self) -> Vec<Cow<str>> {
        self.smart_cards_info
            .iter()
            .map(|card_info| card_info.reader.name.clone())
            .collect()
    }

    fn device_type_id(&self, reader_name: &str) -> WinScardResult<DeviceTypeId> {
        self.smart_cards_info
            .iter()
            .find(|card_info| card_info.reader.name == reader_name)
            .ok_or_else(|| Error::new(ErrorKind::UnknownReader, format!("reader {:?} not found", reader_name)))
            .map(|card_info| card_info.reader.device_type_id)
    }

    fn reader_icon(&self, reader_name: &str) -> WinScardResult<Icon> {
        self.smart_cards_info
            .iter()
            .find(|card_info| card_info.reader.name == reader_name)
            .ok_or_else(|| Error::new(ErrorKind::UnknownReader, format!("reader {:?} not found", reader_name)))
            .map(|card_info| card_info.reader.icon.clone())
    }

    fn is_valid(&self) -> bool {
        !self.smart_cards_info.is_empty()
    }
}
