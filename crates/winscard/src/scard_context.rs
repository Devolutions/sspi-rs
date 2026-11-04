use alloc::borrow::{Cow, ToOwned};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

use picky::key::{KeyKind, PrivateKey};
use picky_asn1_x509::{PublicKey, SubjectPublicKeyInfo};
use secret::{Secret, SecretPrivateKey};
use uuid::Uuid;

use crate::cache::Cache;
use crate::scard::{CardIdentity, SUPPORTED_CONNECTION_PROTOCOL, SmartCard, card_identity};
use crate::winscard::{
    CurrentState, DeviceTypeId, Icon, Protocol, ProviderId, ReaderState, ScardConnectData, ShareMode, WinScardContext,
};
use crate::{Error, ErrorKind, WinScardResult};

/// https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetstatuschangew
/// To be notified of the arrival of a new smart card reader,
/// set the szReader member of a SCARD_READERSTATE structure to "\\?PnP?\Notification",
const NEW_READER_NOTIFICATION: &str = "\\\\?PnP?\\Notification";

/// Cache item that marks the emulated smart card cache as initialized.
///
/// The cache is global and shared by every established resource manager context, so the items
/// that describe the emulated smart card must be written only once: the values the smart card
/// minidriver writes afterwards must survive the next context creation. The smart card minidriver
/// has no reason to write an item with such a name, so it is safe to use it as a marker.
const CARD_CACHE_INITIALIZED: &str = "is_card_initialized";

/// The maximal key container name length in UTF-16 code units, without the terminating null character.
///
/// The `wszGuid` field of the `CONTAINER_MAP_RECORD` structure has a fixed size.
const MAX_CONTAINER_NAME_LEN: usize = 39;

/// Encodes the key container name into the fixed-size `wszGuid` field of the `CONTAINER_MAP_RECORD` structure.
///
/// Fails if the name is too long. Truncating it would break the logon: the target machine looks for
/// the key container using the full name.
pub(crate) fn encode_container_name(container_name: &str) -> WinScardResult<Vec<u8>> {
    let mut encoded = container_name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();

    if encoded.len() > MAX_CONTAINER_NAME_LEN * 2 {
        return Err(Error::new(
            ErrorKind::InvalidParameter,
            format!("key container name is too long: the maximum is {MAX_CONTAINER_NAME_LEN} UTF-16 code units"),
        ));
    }

    encoded.resize((MAX_CONTAINER_NAME_LEN + 1) * 2, 0);

    Ok(encoded)
}

/// The size of the P-256 curve coordinate (and private key) in bytes.
const EC_P256_COORDINATE_SIZE: usize = 32;

/// Default name of the emulated smart card.
pub const DEFAULT_CARD_NAME: &str = "Sspi-rs emulated smart card";
/// The card type name the YubiKey Smart Card Minidriver registers for the emulated YubiKey ATR.
pub const YUBIKEY_CARD_NAME: &str = "YubiKey Smart Card";
/// The YubiKey Smart Card Minidriver location.
pub const YUBIKEY_SCARD_DRIVER_LOCATION: &str = "ykmd.dll\0";
/// Default CSP name.
pub const MICROSOFT_DEFAULT_CSP: &str = "Microsoft Base Smart Card Crypto Provider";
/// Default KSP name.
pub const MICROSOFT_DEFAULT_KSP: &str = "Microsoft Smart Card Key Storage Provider";
/// Default smart card driver location.
pub const MICROSOFT_SCARD_DRIVER_LOCATION: &str = "msclmd.dll\0";

/// Describes a smart card reader.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    /// Reader name.
    pub name: Cow<'a, str>,
    /// Reader icon buff.
    pub icon: Icon<'a>,
    /// Device Type Id.
    pub device_type_id: DeviceTypeId,
}

/// Describes smart card info used for the smart card creation.
#[derive(Debug, Clone)]
pub struct SmartCardInfo<'a> {
    /// Container name which stores the certificate along with its private key.
    pub container_name: Cow<'a, str>,
    /// Smart card PIN code.
    pub pin: Secret<Vec<u8>>,
    /// DER-encoded smart card certificate.
    pub auth_cert_der: Vec<u8>,
    /// Encoded private key (pem).
    pub auth_pk_pem: Secret<String>,
    /// Private key.
    pub auth_pk: SecretPrivateKey,
    /// Information about smart card reader.
    pub reader: Reader<'a>,
}

impl<'a> SmartCardInfo<'a> {
    /// Returns image bytes (BMP encoded) of the stadard Windowss Reader Icon.
    pub fn reader_icon() -> &'static [u8] {
        include_bytes!("../assets/reader_icon.bmp")
    }

    /// Tries to create [SmartCardInfo] structure based on environment variables.
    /// Required environment variables are listed in the `env` module of this crate.
    #[cfg(feature = "std")]
    pub fn try_from_env() -> WinScardResult<Self> {
        use crate::env::{
            WINSCARD_PIN_ENV, WINSCARD_READER_NAME_ENV, auth_cert_from_env, container_name, private_key_from_env,
        };

        let container_name = container_name()?.into();
        let reader_name: Cow<'_, str> = env!(WINSCARD_READER_NAME_ENV)?.into();
        let pin: Vec<u8> = env!(WINSCARD_PIN_ENV)?.into();

        let auth_cert_der = auth_cert_from_env()?.to_der()?;
        let (raw_private_key, private_key) = private_key_from_env()?;

        // Standard Windows Reader Icon
        let icon: &[u8] = Self::reader_icon();
        let reader: Reader<'_> = Reader {
            name: reader_name,
            icon: Icon::from(icon),
            device_type_id: DeviceTypeId::Tpm,
        };

        Ok(Self {
            container_name,
            pin: pin.into(),
            auth_cert_der,
            auth_pk_pem: raw_private_key.to_string().into(),
            auth_pk: private_key.into(),
            reader,
        })
    }

    /// Creates a new [ScardContext] based on the provided data.
    pub fn new(
        container_name: Cow<'a, str>,
        reader_name: Cow<'a, str>,
        pin: Vec<u8>,
        auth_cert_der: Vec<u8>,
        auth_pk_pem: Cow<'a, str>,
        auth_pk: PrivateKey,
    ) -> Self {
        // Standard Windows Reader Icon
        let icon: &[u8] = Self::reader_icon();
        let reader: Reader<'_> = Reader {
            name: reader_name,
            icon: Icon::from(icon),
            device_type_id: DeviceTypeId::Tpm,
        };
        SmartCardInfo {
            container_name,
            pin: pin.into(),
            auth_cert_der,
            auth_pk_pem: auth_pk_pem.into_owned().into(),
            auth_pk: auth_pk.into(),
            reader,
        }
    }
}

/// Represents the resource manager context (the scope).
///
/// Currently, we support only one smart card per smart card context.
#[derive(Debug)]
pub struct ScardContext<'a> {
    smart_card_info: SmartCardInfo<'a>,
    /// Identifier of the smart card this context represents.
    ///
    /// The emulated smart card reports it in the CHUID, and all the cache items of this card are
    /// scoped by it.
    card_id: Uuid,
    cache: Box<dyn Cache>,
    /// How the smart card of this context presents itself.
    identity: CardIdentity,
}

impl<'a> ScardContext<'a> {
    /// Creates a new smart card based on the list of smart card readers.
    ///
    /// On the first call, the provided [Cache] is filled with the items that describe the emulated
    /// smart card. The subsequent calls leave the cache as is: see [CARD_CACHE_INITIALIZED].
    pub fn new(smart_card_info: SmartCardInfo<'a>, card_id: Uuid, mut cache: Box<dyn Cache>) -> WinScardResult<Self> {
        let identity = card_identity(smart_card_info.auth_pk.as_ref())?;
        let container = encode_container_name(smart_card_info.container_name.as_ref())?;

        // The zero freshness counter means that any cached item revision suits us.
        if cache.read(card_id, 0, CARD_CACHE_INITIALIZED).is_ok() {
            return Ok(Self {
                smart_card_info,
                card_id,
                cache,
                identity,
            });
        }

        // The cache items written below describe the card we emulate, so nothing the caller can
        // learn from the card invalidates them. They are written with the maximal freshness
        // counter value and thus never become stale.

        // Freshness values may vary at different points in time.
        // We do not need to change them in runtime, so we hardcode them here.
        // Those values do not mean anything special. They are just extracted from the real TPM smart card.
        const PIN_FRESHNESS: [u8; 2] = [0x00, 0x00];
        const CONTAINER_FRESHNESS: [u8; 2] = [0x01, 0x00];
        const FILE_FRESHNESS: [u8; 2] = [0x0b, 0x00];

        // The following header is formed based on the extracted information from the Windows Smart Card Minidriver (`msclmd.dll`).
        // Do not change it unless you know what you are doing.
        // A broken cache will break the entire authentication.
        const CACHE_ITEM_HEADER: [u8; 6] = {
            let mut header = [0; 6];

            // reference: msclmd!I_GetPIVCache
            header[0] = 1;
            header[1] = PIN_FRESHNESS[1];
            header[2] = CONTAINER_FRESHNESS[0] + 1;
            header[3] = CONTAINER_FRESHNESS[1];
            header[4] = FILE_FRESHNESS[0] + 1;
            header[5] = FILE_FRESHNESS[1];

            header
        };

        cache.write(card_id, u32::MAX, "Cached_CardProperty_Read Only Mode_0".into(), {
            let mut value = CACHE_ITEM_HEADER.to_vec();
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            // actual data len
            value.extend_from_slice(&4_u32.to_le_bytes());
            // false
            value.extend_from_slice(&0_u32.to_le_bytes());

            value
        });
        cache.write(card_id, u32::MAX, "Cached_CardProperty_Cache Mode_0".into(), {
            let mut value = CACHE_ITEM_HEADER.to_vec();
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            // actual data len
            value.extend_from_slice(&4_u32.to_le_bytes());
            // true
            value.extend_from_slice(&1_u32.to_le_bytes());

            value
        });
        cache.write(
            card_id,
            u32::MAX,
            "Cached_CardProperty_Supports Windows x.509 Enrollment_0".into(),
            {
                let mut value = CACHE_ITEM_HEADER.to_vec();
                // unkown flags
                value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
                // actual data len
                value.extend_from_slice(&4_u32.to_le_bytes());
                // true
                value.extend_from_slice(&1_u32.to_le_bytes());

                value
            },
        );
        // The key exchange key size in bits. The emulated smart card key is registered as the key exchange key,
        // the same as the Windows PIV minidriver does for the PIV authentication key.
        let key_exchange_key_size_bits: [u8; 2] = match smart_card_info.auth_pk.as_ref().kind() {
            // 2048 bits.
            KeyKind::Rsa => [0, 8],
            // 256 bits: the P-256 curve.
            KeyKind::Ec => [0, 1],
            _ => {
                return Err(Error::new(
                    ErrorKind::UnsupportedFeature,
                    "only RSA 2048 and EC P-256 keys are supported",
                ));
            }
        };

        cache.write(card_id, u32::MAX, "Cached_GeneralFile/mscp/cmapfile".into(), {
            let mut value = CACHE_ITEM_HEADER.to_vec();
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            // actual data len: size_of<CONTAINER_MAP_RECORD>()
            // https://github.com/selfrender/Windows-Server-2003/blob/5c6fe3db626b63a384230a1aa6b92ac416b0765f/ds/security/csps/wfsccsp/inc/basecsp.h#L104-L110
            value.extend_from_slice(&86_u32.to_le_bytes());
            // CONTAINER_MAP_RECORD:
            value.extend_from_slice(&container); // wszGuid
            value.extend_from_slice(&[3, 0]); // bFlags
            value.extend_from_slice(&[0, 0]); // wSigKeySizeBits
            value.extend_from_slice(&key_exchange_key_size_bits); // wKeyExchangeKeySizeBits

            value
        });
        cache.write(card_id, u32::MAX, "Cached_CardmodFile\\Cached_CMAPFile".into(), {
            // CONTAINER_MAP_RECORD:
            let mut value = container.clone(); // wszGuid
            value.extend_from_slice(&[3, 0]); // bFlags
            value.extend_from_slice(&[0, 0]); // wSigKeySizeBits
            value.extend_from_slice(&key_exchange_key_size_bits); // wKeyExchangeKeySizeBits

            value
        });
        cache.write(card_id, u32::MAX, "Cached_ContainerProperty_PIN Identifier_0".into(), {
            let mut value = CACHE_ITEM_HEADER.to_vec();
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            // actual data len
            value.extend_from_slice(&4_u32.to_le_bytes());
            // PIN identifier
            value.extend_from_slice(&1_u32.to_le_bytes());

            value
        });
        cache.write(card_id, u32::MAX, "Cached_ContainerInfo_00".into(), {
            // Note. We can hardcode lengths values in this cache item because we support only 2048 RSA keys and P-256 EC keys.
            // RSA 4096 is not defined in the specification so we don't support it.
            // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=34
            // 5.3 Cryptographic Mechanism Identifiers
            // '07' - RSA 2048
            // '11' - ECC: Curve P-256

            let mut value = CACHE_ITEM_HEADER.to_vec();
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

            let public_key = smart_card_info
                .auth_pk
                .as_ref()
                .to_public_key()
                .expect("private key to public key");
            let public_key: &SubjectPublicKeyInfo = public_key.as_ref();

            // The key is always registered as the key exchange key (the signature key is empty).
            // CONTAINER_INFO: dwVersion, dwReserved, cbSigPublicKey, cbKeyExPublicKey, pbSigPublicKey, pbKeyExPublicKey.
            let key_blob = match &public_key.subject_public_key {
                PublicKey::Rsa(rsa) => {
                    let mut key_blob = Vec::with_capacity(276);

                    // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-publickeystruc
                    // PUBLICKEYSTRUC
                    key_blob.push(0x06); // bType = PUBLICKEYBLOB
                    key_blob.push(0x02); // bVersion = 0x2
                    key_blob.extend_from_slice(&[0x00, 0x00]); // reserved
                    key_blob.extend_from_slice(&[0x00, 0xa4, 0x00, 0x00]); // aiKeyAlg = CALG_RSA_KEYX

                    // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey
                    // RSAPUBKEY
                    key_blob.extend_from_slice(b"RSA1"); // magic = RSA1
                    key_blob.extend_from_slice(&2048_u32.to_le_bytes()); // bitlen = 2048

                    let mut modulus = rsa.0.modulus.to_vec();
                    modulus.reverse();
                    modulus.resize(256, 0);

                    let mut pub_exp = rsa.0.public_exponent.to_vec();
                    pub_exp.reverse();
                    pub_exp.resize(4, 0);

                    key_blob.extend_from_slice(&pub_exp); // pubexp
                    key_blob.extend_from_slice(&modulus); // public key

                    key_blob
                }
                PublicKey::Ec(point) => {
                    // The uncompressed point: `0x04 || X || Y`.
                    // https://www.secg.org/sec1-v2.pdf#page=17
                    let point = point.0.payload_view();
                    let (x, y) = match point.split_first() {
                        Some((0x04, coordinates)) if coordinates.len() == 2 * EC_P256_COORDINATE_SIZE => {
                            coordinates.split_at(EC_P256_COORDINATE_SIZE)
                        }
                        _ => {
                            return Err(Error::new(
                                ErrorKind::UnsupportedFeature,
                                "only uncompressed EC P-256 public keys are supported",
                            ));
                        }
                    };

                    let mut key_blob = Vec::with_capacity(8 + 2 * EC_P256_COORDINATE_SIZE);

                    // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
                    // BCRYPT_ECCKEY_BLOB
                    key_blob.extend_from_slice(b"ECK1"); // dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC
                    key_blob.extend_from_slice(&32_u32.to_le_bytes()); // cbKey = the P-256 coordinate size
                    key_blob.extend_from_slice(x);
                    key_blob.extend_from_slice(y);

                    key_blob
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::UnsupportedFeature,
                        "only RSA 2048 and EC P-256 keys are supported",
                    ));
                }
            };

            // actual data len: the container info header + the key blob
            let data_len = u32::try_from(16 + key_blob.len())
                .map_err(|_| Error::new(ErrorKind::InternalError, "container info is too large for u32"))?;
            value.extend_from_slice(&data_len.to_le_bytes());

            let key_blob_len = u32::try_from(key_blob.len())
                .map_err(|_| Error::new(ErrorKind::InternalError, "public key blob is too large for u32"))?;
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // dwVersion, dwReserved, cbSigPublicKey
            value.extend_from_slice(&key_blob_len.to_le_bytes()); // cbKeyExPublicKey
            value.extend_from_slice(&key_blob);

            value
        });
        cache.write(card_id, u32::MAX, "Cached_GeneralFile/mscp/kxc00".into(), {
            let mut value = CACHE_ITEM_HEADER.to_vec();
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

            let mut compressed_cert = vec![0; smart_card_info.auth_cert_der.len()];
            let compressed = crate::compression::compress_cert(&smart_card_info.auth_cert_der, &mut compressed_cert)?;

            let total_value_len = u32::try_from(
                compressed.len() + 2 /* unknown flags */ + 2, /* uncompressed certificate len */
            )
            .map_err(|_| Error::new(ErrorKind::InternalError, "compressed cert too large for u32"))?;
            value.extend_from_slice(&total_value_len.to_le_bytes());

            value.extend_from_slice(&[0x01, 0x00]); // flags that specify that the certificate is compressed
            let cert_len = u16::try_from(smart_card_info.auth_cert_der.len())
                .map_err(|_| Error::new(ErrorKind::InternalError, "cert too large for u16"))?;
            value.extend_from_slice(&cert_len.to_le_bytes()); // uncompressed certificate data len
            value.extend_from_slice(&compressed_cert);

            value
        });
        cache.write(card_id, u32::MAX, "Cached_CardProperty_Capabilities_0".into(), {
            let mut value = CACHE_ITEM_HEADER.to_vec();
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            // actual data len
            value.extend_from_slice(&12_u32.to_le_bytes());
            // Here should be the CARD_CAPABILITIES struct but the actual extracted data is different.
            // So, we just insert the extracted data from a real smart card.
            // Card capabilities:
            value.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]);

            value
        });

        cache.write(card_id, u32::MAX, "Cached_CardProperty_Key Sizes_2".into(), {
            let mut value = CACHE_ITEM_HEADER.to_vec();
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            // actual data len
            value.extend_from_slice(&20_u32.to_le_bytes());
            // https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secsmart/card-key-sizes
            value.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]);
            value.extend_from_slice(&[
                1, 0, 0, 0, // dwVersion = 1
                0, 4, 0, 0, // dwMinimumBitlen = 1024
                0, 4, 0, 0, // dwDefaultBitlen = 1048
                0, 8, 0, 0, // dwMaximumBitlen = 2048
                0, 4, 0, 0, // dwIncrementalBitlen = 1024
            ]);

            value
        });

        cache.write(card_id, u32::MAX, "Cached_CardProperty_Key Sizes_1".into(), {
            let mut value = CACHE_ITEM_HEADER.to_vec();
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            // actual data len
            value.extend_from_slice(&20_u32.to_le_bytes());
            // https://learn.microsoft.com/en-us/previous-versions/windows/desktop/secsmart/card-key-sizes
            value.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]);
            value.extend_from_slice(&[
                1, 0, 0, 0, // dwVersion = 1
                0, 4, 0, 0, // dwMinimumBitlen = 1024
                0, 4, 0, 0, // dwDefaultBitlen = 1048
                0, 8, 0, 0, // dwMaximumBitlen = 2048
                0, 4, 0, 0, // dwIncrementalBitlen = 1024
            ]);

            value
        });

        cache.write(
            card_id,
            u32::MAX,
            "Cached_CardmodFile\\Cached_Pin_Freshness".into(),
            PIN_FRESHNESS.to_vec(),
        );
        cache.write(
            card_id,
            u32::MAX,
            "Cached_CardmodFile\\Cached_File_Freshness".into(),
            FILE_FRESHNESS.to_vec(),
        );
        cache.write(
            card_id,
            u32::MAX,
            "Cached_CardmodFile\\Cached_Container_Freshness".into(),
            CONTAINER_FRESHNESS.to_vec(),
        );

        // The marker is written last: if any of the writes above is skipped because of an error,
        // the next context creation will perform the initialization again.
        cache.write(card_id, u32::MAX, CARD_CACHE_INITIALIZED.into(), vec![1]);

        Ok(Self {
            smart_card_info,
            card_id,
            cache,
            identity,
        })
    }

    /// Returns available smart card reader name.
    pub fn reader_name(&self) -> &str {
        self.smart_card_info.reader.name.as_ref()
    }
}

impl WinScardContext for ScardContext<'_> {
    fn connect(
        &self,
        reader_name: &str,
        _share_mode: ShareMode,
        _protocol: Option<Protocol>,
    ) -> WinScardResult<ScardConnectData> {
        if self.smart_card_info.reader.name != reader_name {
            return Err(Error::new(
                ErrorKind::UnknownReader,
                format!("reader {reader_name:?} not found"),
            ));
        }

        Ok(ScardConnectData {
            handle: Box::new(
                SmartCard::new(
                    Cow::Owned(reader_name.to_owned()),
                    self.card_id,
                    self.smart_card_info.pin.as_ref().clone(),
                    self.smart_card_info.auth_cert_der.clone(),
                    self.smart_card_info.auth_pk.as_ref().clone(),
                )?
                .with_container_name(self.smart_card_info.container_name.as_ref())?,
            ),
            protocol: SUPPORTED_CONNECTION_PROTOCOL,
        })
    }

    fn list_readers(&self) -> WinScardResult<Vec<Cow<'_, str>>> {
        Ok(vec![self.smart_card_info.reader.name.clone()])
    }

    fn device_type_id(&self, reader_name: &str) -> WinScardResult<DeviceTypeId> {
        if self.smart_card_info.reader.name != reader_name {
            return Err(Error::new(
                ErrorKind::UnknownReader,
                format!("reader {reader_name:?} not found"),
            ));
        }

        Ok(self.smart_card_info.reader.device_type_id)
    }

    fn reader_icon(&self, reader_name: &str) -> WinScardResult<Icon<'_>> {
        if self.smart_card_info.reader.name != reader_name {
            return Err(Error::new(
                ErrorKind::UnknownReader,
                format!("reader {reader_name:?} not found"),
            ));
        }

        Ok(self.smart_card_info.reader.icon.clone())
    }

    fn is_valid(&self) -> bool {
        true
    }

    // The caller-provided card id is ignored on purpose: we always use the id of the card this
    // context represents. The values must be the same, because the emulated smart card reports
    // the same id in its CHUID, but using our own one guarantees that the cache items written
    // during the context creation are always reachable.
    fn read_cache(&self, _card_id: Uuid, freshness_counter: u32, key: &str) -> WinScardResult<Cow<'_, [u8]>> {
        Ok(Cow::Owned(self.cache.read(self.card_id, freshness_counter, key)?))
    }

    fn write_cache(
        &mut self,
        _card_id: Uuid,
        freshness_counter: u32,
        key: String,
        value: Vec<u8>,
    ) -> WinScardResult<()> {
        self.cache.write(self.card_id, freshness_counter, key, value);

        Ok(())
    }

    fn list_reader_groups(&self) -> WinScardResult<Vec<Cow<'_, str>>> {
        // We don't support configuring or introducing reader groups. So, we just return hardcoded values.
        //
        // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardlistreadergroupsw
        // SCARD_DEFAULT_READERS: TEXT("SCard$DefaultReaders\000")
        // Default group to which all readers are added when introduced into the system.
        Ok(vec![Cow::Borrowed("SCard$DefaultReaders\u{0}00")])
    }

    fn cancel(&mut self) -> WinScardResult<()> {
        // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardcancel
        // The only requests that you can cancel are those that require waiting for external action by the smart card or user.
        //
        // We don't have any external actions, so we just return success.
        Ok(())
    }

    fn get_status_change(&mut self, _timeout: u32, reader_states: &mut [ReaderState<'_>]) -> WinScardResult<()> {
        let atr = self.identity.atr;
        let supported_readers = self.list_readers()?;

        for reader_state in reader_states {
            if supported_readers.contains(&reader_state.reader_name) {
                reader_state.event_state = CurrentState::SCARD_STATE_UNNAMED_CONSTANT
                    | CurrentState::SCARD_STATE_INUSE
                    | CurrentState::SCARD_STATE_PRESENT
                    | CurrentState::SCARD_STATE_CHANGED;
                reader_state.atr[0..atr.len()].copy_from_slice(atr);
                reader_state.atr_len = atr.len();
            } else if reader_state.reader_name.as_ref() == NEW_READER_NOTIFICATION {
                reader_state.event_state = CurrentState::SCARD_STATE_UNNAMED_CONSTANT;
            } else {
                error!(?reader_state.reader_name, "Unsupported reader");
            }
        }

        Ok(())
    }

    fn list_cards(
        &self,
        _atr: Option<&[u8]>,
        _required_interfaces: Option<&[Uuid]>,
    ) -> WinScardResult<Vec<Cow<'_, str>>> {
        // we have only one smart card with only one name
        Ok(vec![self.identity.name.into()])
    }

    fn get_card_type_provider_name(&self, _card_name: &str, provider_id: ProviderId) -> WinScardResult<Cow<'_, str>> {
        Ok(match provider_id {
            ProviderId::Primary => {
                return Err(Error::new(
                    ErrorKind::UnsupportedFeature,
                    "ProviderId::Primary is not supported for emulated smart card",
                ));
            }
            ProviderId::Csp => MICROSOFT_DEFAULT_CSP.into(),
            ProviderId::Ksp => MICROSOFT_DEFAULT_KSP.into(),
            ProviderId::CardModule => self.identity.card_module.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::rc::Rc;
    use core::cell::RefCell;

    use super::*;
    use crate::test_keys::{EC_P256_PRIVATE_KEY, EC_P256_PUBLIC_POINT, EC_P384_PRIVATE_KEY, RSA_2048_PRIVATE_KEY};

    /// The cache that can be inspected after it is moved into the context.
    #[derive(Debug, Clone, Default)]
    struct SharedCache(Rc<RefCell<BTreeMap<String, Vec<u8>>>>);

    impl Cache for SharedCache {
        fn read(&self, _card_id: Uuid, _freshness_counter: u32, key: &str) -> WinScardResult<Vec<u8>> {
            self.0
                .borrow()
                .get(key)
                .cloned()
                .ok_or_else(|| Error::new(ErrorKind::CacheItemNotFound, format!("item {key} not found")))
        }

        fn write(&mut self, _card_id: Uuid, _freshness_counter: u32, key: String, value: Vec<u8>) {
            self.0.borrow_mut().insert(key, value);
        }
    }

    /// Initializes the cache of the emulated smart card with the provided key.
    fn init_cache(private_key_pem: &str) -> WinScardResult<SharedCache> {
        let cache = SharedCache::default();
        let info = SmartCardInfo::new(
            "test-container".into(),
            "Reader 0".into(),
            b"123456".to_vec(),
            vec![0xff; 1024],
            private_key_pem.into(),
            PrivateKey::from_pem_str(private_key_pem).unwrap(),
        );

        ScardContext::new(info, Uuid::from_u128(1), Box::new(cache.clone()))?;

        Ok(cache)
    }

    /// Returns the value of the cache item without the common item header (6 bytes), the unknown flags (6 bytes)
    /// and the data length (4 bytes). The data length is returned separately.
    fn item_data(cache: &SharedCache, key: &str) -> (u32, Vec<u8>) {
        let item = cache
            .0
            .borrow()
            .get(key)
            .cloned()
            .unwrap_or_else(|| panic!("item {key} is missing"));
        let data_len = u32::from_le_bytes(item[12..16].try_into().unwrap());

        (data_len, item[16..].to_vec())
    }

    fn container_name_utf16() -> Vec<u8> {
        let mut name = "test-container"
            .encode_utf16()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>();
        // The `wszGuid` field has a fixed size.
        name.resize(80, 0);

        name
    }

    #[test]
    fn container_name_is_padded_to_the_record_field_size() {
        assert_eq!(container_name_utf16(), encode_container_name("test-container").unwrap());
        assert_eq!(80, encode_container_name(&"a".repeat(39)).unwrap().len());
    }

    #[test]
    fn too_long_container_name_is_rejected() {
        let error = encode_container_name(&"a".repeat(40)).unwrap_err();

        assert_eq!(ErrorKind::InvalidParameter, error.error_kind);
    }

    #[test]
    fn cmapfile_keeps_its_declared_size_with_a_short_container_name() {
        let cache = init_cache(RSA_2048_PRIVATE_KEY).unwrap();

        let (data_len, data) = item_data(&cache, "Cached_GeneralFile/mscp/cmapfile");

        assert_eq!(86, data_len);
        assert_eq!(86, data.len());
    }

    #[test]
    fn ec_container_info_matches_the_real_card_layout() {
        let cache = init_cache(EC_P256_PRIVATE_KEY).unwrap();

        let (data_len, data) = item_data(&cache, "Cached_ContainerInfo_00");

        // The layout is taken from the real YubiKey (P-256) RDP smart card logon capture:
        // 12 zero bytes (dwVersion, dwReserved, cbSigPublicKey), cbKeyExPublicKey = 0x48, then the BCRYPT_ECCKEY_BLOB.
        let mut expected = vec![0; 12];
        expected.extend_from_slice(&0x48_u32.to_le_bytes());
        expected.extend_from_slice(b"ECK1");
        expected.extend_from_slice(&32_u32.to_le_bytes());
        // X and Y coordinates (without the 0x04 point tag).
        expected.extend_from_slice(&EC_P256_PUBLIC_POINT[1..]);

        assert_eq!(0x58, data_len);
        assert_eq!(expected, data);
    }

    #[test]
    fn rsa_container_info_is_unchanged() {
        let cache = init_cache(RSA_2048_PRIVATE_KEY).unwrap();

        let (data_len, data) = item_data(&cache, "Cached_ContainerInfo_00");

        assert_eq!(292, data_len);
        assert_eq!(292, data.len());
        // dwVersion, dwReserved, cbSigPublicKey = 0, cbKeyExPublicKey = 276.
        assert_eq!([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0x01, 0, 0], data[..16]);
        // PUBLICKEYSTRUC (PUBLICKEYBLOB, CALG_RSA_KEYX) and RSAPUBKEY (RSA1, 2048).
        assert_eq!([0x06, 0x02, 0, 0, 0x00, 0xa4, 0, 0], data[16..24]);
        assert_eq!(b"RSA1", &data[24..28]);
        assert_eq!(2048_u32.to_le_bytes(), data[28..32]);
    }

    #[test]
    fn container_map_records_have_the_key_size_of_the_key() {
        for (key, key_exchange_key_size_bits) in [(EC_P256_PRIVATE_KEY, [0, 1]), (RSA_2048_PRIVATE_KEY, [0, 8])] {
            let cache = init_cache(key).unwrap();

            // CONTAINER_MAP_RECORD: wszGuid, bFlags, wSigKeySizeBits, wKeyExchangeKeySizeBits.
            let mut record = container_name_utf16();
            record.extend_from_slice(&[3, 0]);
            record.extend_from_slice(&[0, 0]);
            record.extend_from_slice(&key_exchange_key_size_bits);

            assert_eq!(
                record,
                cache
                    .read(Uuid::from_u128(1), 0, "Cached_CardmodFile\\Cached_CMAPFile")
                    .unwrap()
            );

            let (data_len, data) = item_data(&cache, "Cached_GeneralFile/mscp/cmapfile");
            assert_eq!(86, data_len);
            assert_eq!(record, data);
        }
    }

    #[test]
    fn unsupported_keys_do_not_initialize_the_cache() {
        let error = init_cache(EC_P384_PRIVATE_KEY).unwrap_err();

        assert_eq!(ErrorKind::UnsupportedFeature, error.error_kind);
    }
}
