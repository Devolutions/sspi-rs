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
            name: Cow::Borrowed("Microsoft Virtual Smart Card 2"),
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
            vec![1, 0, 2, 0, 0x0c, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0],
        );
        cache.insert(
            "Cached_CardProperty_Cache Mode_0".into(),
            vec![1, 0, 2, 0, 0x0c, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0],
        );
        cache.insert(
            "Cached_CardProperty_Supports Windows x.509 Enrollment_0".into(),
            vec![1, 0, 2, 0, 0x0c, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0],
        );
        cache.insert(
            "Cached_GeneralFile/mscp/cmapfile".into(),
            vec![
                1, 0, 2, 0, 12, 0, 0, 0, 0, 0, 0, 0, 86, 0, 0, 0, 112, 0, 119, 0, 49, 0, 52, 0, 64, 0, 101, 0, 120, 0,
                97, 0, 109, 0, 112, 0, 108, 0, 101, 0, 46, 0, 99, 0, 111, 0, 109, 0, 45, 0, 53, 0, 56, 0, 54, 0, 57, 0,
                50, 0, 49, 0, 51, 0, 55, 0, 45, 0, 53, 0, 51, 0, 50, 0, 50, 0, 45, 0, 52, 0, 51, 0, 45, 0, 54, 0, 53,
                0, 49, 0, 50, 0, 52, 0, 0, 0, 3, 0, 0, 0, 0, 8,
            ],
        );
        cache.insert(
            "Cached_ContainerProperty_PIN Identifier_0".into(),
            vec![1, 0, 2, 0, 0x0c, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0],
        );
        cache.insert("Cached_ContainerInfo_00".into(), {
            let mut cache_file_data = Vec::new();
            cache_file_data.extend_from_slice(&[1, 0, 2, 0, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0x24, 0x01, 0, 0]); // header

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
                141, 123, 164, 223, 244, 154, 247, 150, 34, 172, 97, 100, 193, 27, 228, 62, 223, 134, 124, 135, 115,
                26, 202, 190, 58, 146, 197, 110, 49, 43, 73, 189, 32, 50, 166, 25, 90, 203, 60, 97, 115, 48, 145, 227,
                66, 16, 141, 241, 190, 239, 144, 146, 160, 26, 36, 171, 58, 92, 136, 236, 23, 232, 79, 103, 119, 194,
                245, 69, 25, 122, 102, 79, 183, 115, 167, 123, 140, 90, 53, 95, 80, 151, 134, 94, 234, 1, 196, 101, 56,
                146, 40, 195, 115, 82, 7, 2, 226, 35, 250, 140, 208, 24, 52, 241, 65, 172, 161, 15, 135, 95, 70, 9, 2,
                199, 68, 51, 243, 224, 249, 31, 143, 6, 122, 240, 223, 11, 18, 156, 191, 23, 139, 53, 135, 24, 242, 67,
                59, 162, 117, 181, 32, 228, 11, 123, 116, 58, 114, 5, 155, 65, 148, 113, 114, 35, 248, 212, 101, 210,
                177, 73, 77, 20, 41, 152, 96, 79, 208, 246, 117, 97, 34, 6, 13, 226, 244, 107, 167, 211, 14, 159, 93,
                2, 172, 73, 127, 162, 163, 2, 158, 227, 239, 226, 3, 55, 65, 120, 132, 192, 69, 37, 53, 239, 25, 176,
                64, 183, 138, 213, 114, 71, 63, 138, 159, 246, 85, 136, 251, 85, 200, 138, 178, 76, 247, 22, 131, 104,
                244, 5, 245, 246, 38, 94, 191, 160, 248, 137, 121, 33, 10, 133, 123, 12, 102, 105, 32, 193, 144, 33,
                239, 7, 121, 197, 54, 254, 26, 173,
            ]); // public key

            cache_file_data
        });
        cache.insert("Cached_GeneralFile/mscp/kxc00".into(), {
            let mut cache_file_data = Vec::new();

            cache_file_data.extend_from_slice(&[1, 0, 2, 0, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0x78, 0x04, 0, 0]); // header
            cache_file_data.extend_from_slice(&[0x01, 0x00]); // purpose of this 2 bytes is unknown
            cache_file_data.extend_from_slice(&[0xa7, 0x05]); // uncompressed certificate data len
            let compressed_key_exchange_certificate = &[
                120, 218, 51, 104, 98, 93, 108, 208, 196, 210, 189, 128, 153, 137, 145, 137, 73, 184, 142, 129, 129,
                65, 212, 242, 253, 46, 249, 136, 164, 47, 70, 12, 32, 32, 106, 192, 203, 198, 169, 213, 230, 209, 246,
                157, 151, 145, 145, 155, 149, 193, 32, 216, 80, 216, 64, 144, 141, 139, 115, 146, 90, 231, 228, 79, 58,
                41, 140, 146, 98, 204, 201, 249, 185, 134, 226, 6, 162, 40, 130, 236, 169, 21, 137, 185, 5, 57, 169,
                134, 202, 6, 138, 108, 204, 161, 44, 204, 194, 82, 80, 17, 221, 112, 79, 63, 93, 207, 48, 103, 55, 19,
                11, 51, 127, 3, 227, 96, 93, 103, 71, 3, 57, 113, 94, 35, 99, 67, 35, 67, 67, 67, 83, 67, 11, 67, 227,
                40, 32, 215, 20, 200, 53, 128, 114, 13, 24, 12, 154, 24, 149, 144, 93, 194, 200, 202, 192, 220, 196,
                200, 15, 18, 231, 98, 106, 98, 100, 100, 88, 43, 245, 207, 236, 104, 37, 251, 123, 197, 9, 7, 21, 50,
                211, 120, 170, 91, 185, 20, 43, 59, 127, 44, 216, 31, 167, 246, 237, 43, 235, 151, 140, 102, 177, 239,
                62, 155, 186, 78, 132, 254, 238, 8, 253, 54, 191, 203, 222, 189, 232, 106, 215, 118, 135, 13, 146, 239,
                77, 85, 93, 15, 180, 84, 56, 154, 51, 63, 122, 255, 120, 30, 211, 226, 69, 245, 158, 107, 152, 98, 231,
                243, 93, 94, 158, 253, 229, 17, 47, 155, 82, 98, 233, 183, 11, 254, 9, 51, 52, 69, 124, 61, 55, 94, 74,
                189, 242, 67, 185, 168, 112, 138, 227, 108, 214, 34, 171, 146, 106, 238, 39, 10, 91, 75, 23, 89, 59,
                127, 146, 104, 55, 237, 22, 223, 63, 71, 136, 251, 254, 135, 42, 182, 126, 249, 159, 15, 62, 27, 187,
                28, 103, 226, 116, 139, 111, 231, 95, 184, 198, 241, 163, 137, 196, 133, 158, 95, 202, 143, 152, 216,
                131, 138, 15, 107, 76, 178, 72, 61, 194, 248, 42, 174, 109, 122, 64, 188, 105, 84, 79, 245, 242, 226,
                237, 254, 105, 85, 146, 174, 95, 15, 149, 167, 251, 191, 16, 127, 211, 17, 99, 181, 90, 69, 106, 193,
                164, 9, 239, 247, 125, 236, 21, 112, 122, 60, 209, 160, 56, 209, 230, 116, 148, 228, 50, 35, 133, 189,
                158, 218, 134, 121, 71, 39, 89, 237, 59, 37, 85, 220, 94, 211, 118, 223, 238, 137, 244, 193, 148, 196,
                53, 74, 211, 190, 207, 250, 114, 127, 73, 117, 47, 19, 51, 35, 3, 227, 226, 38, 166, 131, 6, 77, 76,
                123, 13, 108, 217, 56, 181, 217, 24, 89, 24, 155, 204, 69, 217, 89, 12, 12, 244, 216, 212, 96, 92, 142,
                150, 131, 123, 146, 155, 191, 76, 87, 104, 223, 58, 85, 180, 229, 195, 19, 187, 246, 157, 211, 131,
                252, 154, 238, 78, 137, 106, 125, 56, 133, 145, 137, 49, 5, 152, 14, 12, 228, 129, 49, 38, 171, 202,
                34, 97, 32, 198, 198, 5, 213, 40, 194, 196, 196, 198, 1, 100, 179, 178, 178, 51, 51, 25, 240, 129, 20,
                240, 51, 50, 254, 103, 97, 97, 102, 98, 93, 96, 160, 137, 176, 143, 139, 69, 198, 64, 202, 128, 7, 89,
                163, 1, 23, 146, 86, 89, 144, 86, 62, 22, 49, 22, 145, 223, 19, 166, 31, 17, 15, 250, 124, 52, 45, 109,
                182, 240, 151, 185, 223, 75, 101, 149, 190, 205, 0, 58, 21, 40, 45, 8, 50, 89, 197, 64, 105, 129, 2,
                146, 49, 204, 11, 132, 120, 4, 10, 202, 13, 77, 28, 160, 9, 73, 15, 152, 238, 32, 78, 85, 6, 57, 181,
                65, 196, 243, 116, 220, 13, 55, 6, 45, 157, 178, 2, 47, 223, 180, 95, 235, 219, 170, 159, 237, 76, 55,
                104, 124, 0, 82, 33, 207, 210, 120, 195, 160, 241, 170, 65, 227, 165, 5, 141, 231, 23, 52, 158, 105,
                107, 60, 153, 147, 146, 88, 96, 165, 175, 175, 239, 236, 103, 139, 59, 101, 234, 0, 101, 209, 68, 65,
                66, 206, 46, 1, 32, 42, 160, 52, 41, 39, 51, 89, 213, 200, 192, 59, 181, 18, 72, 6, 167, 22, 149, 101,
                38, 167, 22, 131, 164, 144, 217, 206, 249, 121, 105, 153, 233, 165, 69, 137, 37, 153, 249, 121, 58, 46,
                206, 48, 251, 64, 76, 160, 31, 236, 147, 83, 139, 74, 50, 211, 50, 147, 19, 75, 82, 131, 82, 203, 242,
                147, 193, 234, 124, 50, 139, 75, 236, 147, 18, 139, 83, 237, 243, 147, 178, 82, 147, 75, 156, 115, 18,
                139, 139, 109, 147, 131, 124, 92, 128, 18, 69, 153, 73, 165, 32, 69, 1, 249, 153, 121, 37, 6, 141, 103,
                96, 225, 203, 200, 200, 210, 184, 223, 160, 113, 143, 65, 227, 78, 152, 144, 1, 83, 91, 227, 26, 162,
                253, 234, 232, 233, 72, 77, 143, 57, 58, 35, 188, 134, 197, 51, 112, 73, 160, 118, 199, 210, 146, 140,
                252, 162, 204, 146, 74, 180, 2, 135, 25, 148, 187, 213, 189, 58, 95, 84, 253, 91, 107, 63, 233, 102,
                68, 107, 239, 22, 149, 190, 216, 164, 162, 233, 26, 51, 57, 139, 76, 170, 46, 220, 190, 26, 191, 88,
                36, 217, 252, 132, 64, 45, 79, 166, 58, 203, 82, 119, 46, 239, 235, 14, 255, 186, 50, 222, 112, 120,
                102, 26, 29, 227, 125, 208, 168, 147, 201, 232, 209, 37, 158, 87, 121, 90, 239, 75, 202, 1, 131, 107,
                135, 142, 73, 22, 94, 159, 29, 103, 62, 137, 83, 210, 197, 192, 73, 254, 193, 183, 141, 87, 103, 10,
                176, 174, 212, 13, 151, 142, 150, 173, 170, 122, 153, 41, 235, 30, 25, 80, 120, 99, 95, 67, 194, 99,
                126, 105, 9, 221, 153, 158, 63, 139, 13, 204, 126, 240, 22, 255, 214, 191, 126, 46, 67, 213, 164, 254,
                235, 51, 239, 211, 175, 44, 239, 221, 12, 123, 119, 162, 233, 8, 223, 37, 165, 119, 185, 98, 169, 106,
                46, 231, 94, 229, 244, 40, 63, 10, 248, 29, 57, 223, 238, 240, 42, 166, 39, 215, 31, 53, 233, 159, 115,
                218, 31, 187, 187, 191, 183, 192, 103, 203, 185, 216, 135, 37, 79, 142, 60, 90, 39, 250, 54, 165, 52,
                173, 44, 247, 96, 117, 199, 133, 223, 74, 45, 155, 4, 26, 62, 76, 119, 84, 155, 16, 233, 117, 66, 217,
                121, 239, 49, 215, 7, 109, 202, 151, 4, 151, 31, 122, 234, 160, 53, 127, 242, 175, 166, 219, 243, 255,
                89, 94, 45, 49, 200, 41, 120, 244, 221, 241, 179, 216, 132, 5, 0, 231, 66, 255, 33,
            ];
            cache_file_data.extend_from_slice(compressed_key_exchange_certificate); // flate2 compressed der encoded user key exchange certificate

            cache_file_data
        });
        cache.insert(
            "Cached_CardProperty_Capabilities_0".into(),
            vec![
                1, 0, 2, 0, 0x0c, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            ],
        );

        cache.insert("Cached_CardmodFile\\Cached_Pin_Freshness".into(), vec![0, 0]);
        cache.insert("Cached_CardmodFile\\Cached_File_Freshness".into(), vec![0x0c, 0]);
        cache.insert("Cached_CardmodFile\\Cached_Container_Freshness".into(), vec![2, 0]);

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
