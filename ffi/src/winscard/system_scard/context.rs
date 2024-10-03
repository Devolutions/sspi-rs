use std::borrow::Cow;
#[cfg(not(target_os = "windows"))]
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fmt;
use std::ptr::{null, null_mut};
#[cfg(target_os = "windows")]
use std::slice::from_raw_parts;

#[cfg(target_os = "windows")]
use ffi_types::winscard::functions::SCardApiFunctionTable;
#[cfg(target_os = "windows")]
use ffi_types::winscard::{ScardContext, ScardHandle};
use uuid::Uuid;
use winscard::winscard::{
    DeviceTypeId, Icon, Protocol, ProviderId, ReaderState, ScardConnectData, ScardScope, ShareMode, WinScardContext,
};
use winscard::{Error, ErrorKind, WinScardResult};

use super::{parse_multi_string_owned, SystemScard};
#[cfg(not(target_os = "windows"))]
use crate::winscard::pcsc_lite::functions::PcscLiteApiFunctionTable;
#[cfg(not(target_os = "windows"))]
use crate::winscard::pcsc_lite::{initialize_pcsc_lite_api, ScardContext, ScardHandle};

/// Default name of the system provided smart card.
/// pcsc-lite and PC/SC framework don't have method for querying scard name, so we use predefined value. It doesn't affect the auth process.
#[cfg(not(target_os = "windows"))]
const DEFAULT_CARD_NAME: &str = "Sspi-rs system provided scard";

pub struct SystemScardContext {
    h_context: ScardContext,

    #[cfg(target_os = "windows")]
    api: SCardApiFunctionTable,
    #[cfg(not(target_os = "windows"))]
    api: PcscLiteApiFunctionTable,

    // pcsc-lite API does not have function for the cache reading/writing. So, we emulate the smart card cache by ourselves.
    #[cfg(not(target_os = "windows"))]
    cache: BTreeMap<String, Vec<u8>>,
}

impl fmt::Debug for SystemScardContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemScardContext")
            .field("h_context", &self.h_context)
            .finish()
    }
}

impl SystemScardContext {
    #[instrument(ret)]
    pub fn establish(scope: ScardScope) -> WinScardResult<Self> {
        let mut h_context = 0;

        #[cfg(target_os = "windows")]
        let api = super::init_scard_api_table()?;
        #[cfg(not(target_os = "windows"))]
        let api = initialize_pcsc_lite_api()?;

        debug!("h_context size: {}", std::mem::size_of_val(&h_context));

        try_execute!(
            // SAFETY: This function is safe to call because the `scope` parameter value is type checked
            // and `*mut h_context` can't be `null`.
            unsafe { (api.SCardEstablishContext)(scope.into(), null_mut(), null_mut(), &mut h_context) },
            "SCardEstablishContext failed :("
        )?;

        if h_context == 0 {
            return Err(Error::new(
                ErrorKind::InternalError,
                "can not establish context: SCardEstablishContext did not set the context handle",
            ));
        }

        Ok(Self {
            h_context,
            api,
            #[cfg(not(target_os = "windows"))]
            cache: {
                let auth_cert = winscard::env::auth_cert_from_env()?;
                let auth_cert_der = auth_cert.to_der()?;

                init_scard_cache(&winscard::env::container_name()?, auth_cert, &auth_cert_der)?
            },
        })
    }
}

#[cfg(not(target_os = "windows"))]
fn init_scard_cache(
    container_name: &str,
    auth_cert: picky::x509::Cert,
    auth_cert_der: &[u8],
) -> WinScardResult<BTreeMap<String, Vec<u8>>> {
    use picky_asn1_x509::{PublicKey, SubjectPublicKeyInfo};

    // https://github.com/selfrender/Windows-Server-2003/blob/5c6fe3db626b63a384230a1aa6b92ac416b0765f/ds/security/csps/wfsccsp/inc/basecsp.h#L86-L93
    const MAX_CONTAINER_NAME_LEN: usize = 40;

    let mut cache = BTreeMap::new();

    // Freshness values are not supported, so we set all values to zero.
    const PIN_FRESHNESS: [u8; 2] = [0x00, 0x00];
    const CONTAINER_FRESHNESS: [u8; 2] = [0x00, 0x00];
    const FILE_FRESHNESS: [u8; 2] = [0x00, 0x00];

    // The following header is formed based on the extracted information during the debugging and troubleshooting.
    // Do not change it unless you know what you are doing. A broken cache will break the entire authentication.
    const CACHE_ITEM_HEADER: [u8; 6] = {
        let mut header = [0; 6];

        header[0] = 1;
        header[1] = PIN_FRESHNESS[1];
        header[2] = CONTAINER_FRESHNESS[0] + 1;
        header[3] = CONTAINER_FRESHNESS[1];
        header[4] = FILE_FRESHNESS[0] + 1;
        header[5] = FILE_FRESHNESS[1];

        header
    };

    cache.insert("Cached_CardProperty_Read Only Mode_0".into(), {
        let mut value = CACHE_ITEM_HEADER.to_vec();
        // unkown flags
        value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // actual data len
        value.extend_from_slice(&4_u32.to_le_bytes());
        // true
        value.extend_from_slice(&1_u32.to_le_bytes());

        value
    });
    cache.insert("Cached_CardProperty_Cache Mode_0".into(), {
        let mut value = CACHE_ITEM_HEADER.to_vec();
        // unkown flags
        value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // actual data len
        value.extend_from_slice(&4_u32.to_le_bytes());
        // true
        value.extend_from_slice(&1_u32.to_le_bytes());

        value
    });
    cache.insert("Cached_CardProperty_Supports Windows x.509 Enrollment_0".into(), {
        let mut value = CACHE_ITEM_HEADER.to_vec();
        // unkown flags
        value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // actual data len
        value.extend_from_slice(&4_u32.to_le_bytes());
        // false
        value.extend_from_slice(&0_u32.to_le_bytes());

        value
    });
    cache.insert("Cached_GeneralFile/mscp/cmapfile".into(), {
        use std::mem::size_of;

        use ffi_types::WChar;

        let mut value = CACHE_ITEM_HEADER.to_vec();
        // unkown flags
        value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // actual data len: size_of<CONTAINER_MAP_RECORD>()
        // https://github.com/selfrender/Windows-Server-2003/blob/5c6fe3db626b63a384230a1aa6b92ac416b0765f/ds/security/csps/wfsccsp/inc/basecsp.h#L104-L110
        value.extend_from_slice(&86_u32.to_le_bytes());
        // CONTAINER_MAP_RECORD:
        let mut wsz_guid = container_name
            .encode_utf16()
            .chain(core::iter::once(0))
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>();
        // `wszGuid` has type `WCHAR [MAX_CONTAINER_NAME_LEN]`,
        // so we need to resize the data if it contains less then `size_of() * MAX_CONTAINER_NAME_LEN` bytes.
        let container_name_bytes_len = size_of::<WChar>() * MAX_CONTAINER_NAME_LEN;
        debug_assert_eq!(container_name_bytes_len, 80);

        wsz_guid.resize(container_name_bytes_len, 0);
        debug!(?wsz_guid);

        value.extend_from_slice(&wsz_guid); // wszGuid
        value.extend_from_slice(&[3, 0]); // bFlags
        value.extend_from_slice(&[0, 0]); // wSigKeySizeBits
        value.extend_from_slice(&[0, 8]); // wKeyExchangeKeySizeBits

        value
    });
    cache.insert("Cached_ContainerProperty_PIN Identifier_0".into(), {
        let mut value = CACHE_ITEM_HEADER.to_vec();
        // unkown flags
        value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // actual data len
        value.extend_from_slice(&4_u32.to_le_bytes());
        // PIN identifier
        value.extend_from_slice(&1_u32.to_le_bytes());

        value
    });
    cache.insert("Cached_ContainerInfo_00".into(), {
        // Note. We can hardcode lengths values in this cache item because we support only 2048 RSA keys.
        // RSA 4096 is not defined in the specification so we don't support it.
        // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf#page=34
        // 5.3 Cryptographic Mechanism Identifiers
        // '07' - RSA 2048

        let mut value = CACHE_ITEM_HEADER.to_vec();
        // unkown flags
        value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // actual data len (precalculated)
        value.extend_from_slice(&292_u32.to_le_bytes());

        value.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0x01, 0x00, 0x00]); // container info header

        // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-publickeystruc
        // PUBLICKEYSTRUC
        value.push(0x06); // bType = PUBLICKEYBLOB
        value.push(0x02); // bVersion = 0x2
        value.extend_from_slice(&[0x00, 0x00]); // reserved
        value.extend_from_slice(&[0x00, 0xa4, 0x00, 0x00]); // aiKeyAlg = CALG_RSA_KEYX

        // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey
        // RSAPUBKEY
        value.extend_from_slice(b"RSA1"); // magic = RSA1
        value.extend_from_slice(&2048_u32.to_le_bytes()); // bitlen = 2048

        let public_key = auth_cert.public_key();
        let public_key: &SubjectPublicKeyInfo = public_key.as_ref();
        let (modulus, public_exponent) = match &public_key.subject_public_key {
            PublicKey::Rsa(rsa) => (
                {
                    let mut modulus = rsa.0.modulus.to_vec();
                    modulus.reverse();
                    modulus.resize(256, 0);
                    modulus
                },
                {
                    let mut pub_exp = rsa.0.public_exponent.to_vec();
                    pub_exp.reverse();
                    pub_exp.resize(4, 0);
                    pub_exp
                },
            ),
            _ => {
                return Err(Error::new(
                    ErrorKind::UnsupportedFeature,
                    "only RSA 2048 keys are supported",
                ))
            }
        };

        value.extend_from_slice(&public_exponent); // pubexp
        value.extend_from_slice(&modulus); // public key

        value
    });
    cache.insert("Cached_GeneralFile/mscp/kxc00".into(), {
        let mut value = CACHE_ITEM_HEADER.to_vec();
        // unkown flags
        value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

        value.extend_from_slice(&(u16::try_from(auth_cert_der.len())?.to_le_bytes())); // uncompressed certificate data len
        value.extend_from_slice(&[0x00, 0x00]); // flags that specify that the certificate is not compressed
        value.extend_from_slice(&auth_cert_der);

        value
    });
    cache.insert("Cached_CardProperty_Capabilities_0".into(), {
        let mut value = CACHE_ITEM_HEADER.to_vec();
        // unkown flags
        value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // actual data len
        value.extend_from_slice(&12_u32.to_le_bytes());
        // Here should be the CARD_CAPABILITIES struct but the actual extracted data is different.
        // So, we just insert the extracted data from a real smart card.
        // Card capabilities:
        value.extend_from_slice(&[1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);

        value
    });

    Ok(cache)
}

impl Drop for SystemScardContext {
    fn drop(&mut self) {
        if let Err(err) = try_execute!(
            // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle.
            unsafe { (self.api.SCardReleaseContext)(self.h_context) },
            "SCardReleaseContext failed"
        ) {
            error!(?err, "Can not release the scard context");
        }
    }
}

impl WinScardContext for SystemScardContext {
    #[instrument]
    fn connect(
        &self,
        reader_name: &str,
        share_mode: ShareMode,
        protocol: Option<Protocol>,
    ) -> WinScardResult<ScardConnectData> {
        let c_string = CString::new(reader_name)?;

        let mut scard: ScardHandle = 0;
        let mut active_protocol = 0;

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardConnect)(
                        self.h_context,
                        c_string.as_ptr() as *const _,
                        share_mode.into(),
                        protocol.unwrap_or_default().bits().into(),
                        &mut scard,
                        &mut active_protocol,
                    )
                },
                "SCardConnect failed"
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardConnectA)(
                        self.h_context,
                        c_string.as_ptr() as *const _,
                        share_mode.into(),
                        protocol.unwrap_or_default().bits(),
                        &mut scard,
                        &mut active_protocol,
                    )
                },
                "SCardConnectA failed"
            )?;
        }

        let handle = Box::new(SystemScard::new(scard, self.h_context)?);

        Ok(ScardConnectData {
            handle,
            protocol: Protocol::from_bits(active_protocol.try_into()?).unwrap_or_default(),
        })
    }

    fn list_readers(&self) -> WinScardResult<Vec<Cow<str>>> {
        let mut readers_buf_len = 0;

        #[cfg(not(target_os = "windows"))]
        {
            // https://pcsclite.apdu.fr/api/group__API.html#ga93b07815789b3cf2629d439ecf20f0d9
            //
            // If the application sends mszGroups and mszReaders as NULL then this function will return the size of the buffer needed to allocate in pcchReaders.
            // `mszGroups`: List of groups to list readers (not used).
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe { (self.api.SCardListReaders)(self.h_context, null(), null_mut(), &mut readers_buf_len) },
                "SCardListReaders failed 1"
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardlistreadersa
            //
            //  If this value is NULL, SCardListReaders ignores the buffer length supplied in pcchReaders,
            //  writes the length of the buffer that would have been returned if this parameter
            //  had not been NULL to pcchReaders, and returns a success code.
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe { (self.api.SCardListReadersA)(self.h_context, null(), null_mut(), &mut readers_buf_len) },
                "SCardListReadersA failed"
            )?;
        }

        let mut readers = vec![0; readers_buf_len.try_into()?];

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardListReaders)(self.h_context, null(), readers.as_mut_ptr(), &mut readers_buf_len)
                },
                "SCardListReaders failed 2"
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardListReadersA)(self.h_context, null(), readers.as_mut_ptr(), &mut readers_buf_len)
                },
                "SCardListReadersA failed"
            )?;
        }

        parse_multi_string_owned(&readers)
    }

    fn device_type_id(&self, _reader_name: &str) -> WinScardResult<DeviceTypeId> {
        #[cfg(not(target_os = "windows"))]
        {
            Ok(DeviceTypeId::Usb)
        }
        #[cfg(target_os = "windows")]
        {
            use num_traits::FromPrimitive;

            let mut device_type_id = 0;

            let c_reader_name = CString::new(_reader_name)?;

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardGetDeviceTypeIdA)(
                        self.h_context,
                        c_reader_name.as_ptr() as *const _,
                        &mut device_type_id,
                    )
                },
                "SCardGetDeviceTypeIdA failed"
            )?;

            DeviceTypeId::from_u32(device_type_id).ok_or_else(|| {
                Error::new(
                    ErrorKind::InternalError,
                    format!("WinSCard has returned invalid device type id: {}", device_type_id),
                )
            })
        }
    }

    fn reader_icon(&self, _reader_name: &str) -> WinScardResult<Icon> {
        #[cfg(not(target_os = "windows"))]
        {
            use winscard::SmartCardInfo;

            Ok(Icon::from(SmartCardInfo::reader_icon()))
        }
        #[cfg(target_os = "windows")]
        {
            let c_reader_name = CString::new(_reader_name)?;

            let mut icon_buf_len = 0;

            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardgetreadericona
            //
            // If this value is NULL, the function ignores the buffer length supplied in the pcbIcon parameter,
            // writes the length of the buffer that would have been returned to pcbIcon if this parameter
            // had not been NULL, and returns a success code.
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardGetReaderIconA)(
                        self.h_context,
                        c_reader_name.as_ptr() as *const _,
                        null_mut(),
                        &mut icon_buf_len,
                    )
                },
                "SCardGetReaderIconA failed"
            )?;

            let mut icon_buf = vec![0; icon_buf_len.try_into()?];

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardGetReaderIconA)(
                        self.h_context,
                        c_reader_name.as_ptr() as *const _,
                        icon_buf.as_mut_ptr(),
                        &mut icon_buf_len,
                    )
                },
                "SCardGetReaderIconA failed"
            )?;

            Ok(icon_buf.into())
        }
    }

    fn is_valid(&self) -> bool {
        try_execute!(
            // SAFETY: This function is safe to call because we are allowed to pass any value.
            unsafe { (self.api.SCardIsValidContext)(self.h_context) },
            "SCardIsValidContext failed"
        )
        .is_ok()
    }

    #[instrument(ret)]
    fn read_cache(&self, _card_id: Uuid, _freshness_counter: u32, key: &str) -> WinScardResult<Cow<[u8]>> {
        #[cfg(not(target_os = "windows"))]
        {
            self.cache
                .get(key)
                .map(|item| Cow::Borrowed(item.as_slice()))
                .ok_or_else(|| Error::new(ErrorKind::CacheItemNotFound, format!("Cache item '{}' not found", key)))
        }
        #[cfg(target_os = "windows")]
        {
            use super::uuid_to_c_guid;
            use crate::winscard::buf_alloc::SCARD_AUTOALLOCATE;

            let mut data_len = SCARD_AUTOALLOCATE;

            let c_cache_key = CString::new(key)?;
            let mut card_id = uuid_to_c_guid(_card_id);

            let mut data: *mut u8 = null_mut();

            // It's not specified in the `SCardReadCacheA` function documentation, but after some
            // `msclmd.dll` reversing, we found out that this function supports the `SCARD_AUTOALLOCATE`.
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardReadCacheA)(
                        self.h_context,
                        &mut card_id,
                        _freshness_counter,
                        c_cache_key.into_raw() as *mut _,
                        ((&mut data) as *mut *mut u8) as *mut _,
                        &mut data_len,
                    )
                },
                "SCardReadCacheA failed"
            )?;

            let data_len: usize = if let Ok(len) = data_len.try_into() {
                len
            } else {
                try_execute!(
                    // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle.
                    unsafe { (self.api.SCardFreeMemory)(self.h_context, data as *const _) },
                    "SCardFreeMemory failed"
                )?;

                return Err(Error::new(ErrorKind::InternalError, "u32 to usize conversion error"));
            };

            let mut cache_item = vec![0; data_len];
            cache_item.copy_from_slice(
                // SAFETY: A slice creation is safe here because the `data` pointer is a local pointer and
                // was initialized by `SCardReadCacheA` function.
                unsafe { from_raw_parts(data, data_len) },
            );

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle.
                unsafe { (self.api.SCardFreeMemory)(self.h_context, data as *const _) },
                "SCardFreeMemory failed"
            )?;

            Ok(Cow::Owned(cache_item))
        }
    }

    #[instrument(ret)]
    fn write_cache(
        &mut self,
        _card_id: Uuid,
        _freshness_counter: u32,
        key: String,
        value: Vec<u8>,
    ) -> WinScardResult<()> {
        #[cfg(not(target_os = "windows"))]
        {
            self.cache.insert(key, value);

            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            use super::uuid_to_c_guid;

            let c_cache_key = CString::new(key.as_str())?;
            let mut card_id = uuid_to_c_guid(_card_id);

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardWriteCacheA)(
                        self.h_context,
                        &mut card_id,
                        _freshness_counter,
                        c_cache_key.into_raw() as *mut _,
                        value.as_ptr(),
                        value.len().try_into()?,
                    )
                },
                "SCardWriteCacheA failed"
            )
        }
    }

    fn list_reader_groups(&self) -> WinScardResult<Vec<Cow<str>>> {
        let mut reader_groups_buf_len = 0;

        #[cfg(not(target_os = "windows"))]
        {
            // https://pcsclite.apdu.fr/api/group__API.html#ga9d970d086d5218e080d0079d63f9d496
            //
            // If the application sends mszGroups as NULL then this function will return the size of the buffer needed to allocate in pcchGroups.
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe { (self.api.SCardListReaderGroups)(self.h_context, null_mut(), &mut reader_groups_buf_len) },
                "SCardListReaderGroups failed"
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardlistreadergroupsw
            //
            // If this value is NULL, SCardListReaderGroups ignores the buffer length supplied in pcchGroups,
            // writes the length of the buffer that would have been returned if this parameter had not been
            // NULL to pcchGroups, and returns a success code.
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe { (self.api.SCardListReaderGroupsA)(self.h_context, null_mut(), &mut reader_groups_buf_len) },
                "SCardListReaderGroupsA failed"
            )?;
        }

        let mut reader_groups = vec![0; reader_groups_buf_len.try_into()?];

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardListReaderGroups)(
                        self.h_context,
                        reader_groups.as_mut_ptr(),
                        &mut reader_groups_buf_len,
                    )
                },
                "SCardListReaderGroups failed"
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardListReaderGroupsA)(
                        self.h_context,
                        reader_groups.as_mut_ptr(),
                        &mut reader_groups_buf_len,
                    )
                },
                "SCardListReaderGroupsA failed"
            )?;
        }

        parse_multi_string_owned(&reader_groups)
    }

    fn cancel(&mut self) -> WinScardResult<()> {
        // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle.
        try_execute!(unsafe { (self.api.SCardCancel)(self.h_context) }, "SCardCancel failed")
    }

    #[instrument(ret)]
    fn get_status_change(&mut self, timeout: u32, reader_states: &mut [ReaderState]) -> WinScardResult<()> {
        use std::ffi::NulError;

        #[cfg(not(target_os = "macos"))]
        use ffi_types::winscard::ScardReaderStateA as ScardReaderState;
        use winscard::winscard::CurrentState;

        #[cfg(target_os = "macos")]
        use crate::winscard::pcsc_lite::ScardReaderState;

        let mut states = Vec::with_capacity(reader_states.len());
        let c_readers = reader_states
            .iter()
            .map(|reader_state| CString::new(reader_state.reader_name.as_ref()))
            .collect::<Result<Vec<CString>, NulError>>()?;

        for (reader_state, c_reader) in reader_states.iter_mut().zip(c_readers.iter()) {
            states.push(ScardReaderState {
                sz_reader: c_reader.as_ptr() as *const _,
                pv_user_data: reader_state.user_data as _,
                dw_current_state: reader_state.current_state.bits(),
                dw_event_state: reader_state.event_state.bits(),
                cb_atr: reader_state.atr_len.try_into()?,
                rgb_atr: reader_state.atr,
            });
        }

        #[cfg(not(target_os = "windows"))]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardGetStatusChange)(
                        self.h_context,
                        timeout,
                        states.as_mut_ptr(),
                        reader_states.len().try_into()?,
                    )
                },
                "SCardGetStatusChange failed"
            )?;
        }
        #[cfg(target_os = "windows")]
        {
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardGetStatusChangeA)(
                        self.h_context,
                        timeout,
                        states.as_mut_ptr(),
                        reader_states.len().try_into()?,
                    )
                },
                "SCardGetStatusChangeA failed"
            )?;
        }

        // We do not need to change all fields. Only event state and atr values can be changed.
        for (state, reader_state) in states.iter().zip(reader_states.iter_mut()) {
            reader_state.event_state = CurrentState::from_bits(state.dw_event_state)
                .ok_or_else(|| Error::new(ErrorKind::InternalError, "invalid dwEventState"))?;
            reader_state.atr_len = state.cb_atr.try_into()?;
            reader_state.atr = state.rgb_atr;
        }

        Ok(())
    }

    fn list_cards(&self, _atr: Option<&[u8]>, _required_interfaces: Option<&[Uuid]>) -> WinScardResult<Vec<Cow<str>>> {
        #[cfg(not(target_os = "windows"))]
        {
            Ok(vec![Cow::Borrowed(DEFAULT_CARD_NAME)])
        }
        #[cfg(target_os = "windows")]
        {
            use crate::winscard::system_scard::uuid_to_c_guid;

            let mut cards_buf_len = 0;
            let atr = _atr.map(|a| a.as_ptr()).unwrap_or(null());
            let uuids = _required_interfaces
                .into_iter()
                .flatten()
                .cloned()
                .map(uuid_to_c_guid)
                .collect::<Vec<ffi_types::Uuid>>();
            let uuids_len = uuids.len().try_into()?;
            let c_uuids = if uuids.is_empty() { null() } else { uuids.as_ptr() };

            // https://learn.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardlistcardsw
            //
            // mszCards: If this value is NULL, SCardListCards ignores the buffer length supplied in
            // pcchCards, returning the length of the buffer that would have been returned if this
            // parameter had not been NULL to pcchCards and a success code.
            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardListCardsA)(self.h_context, atr, c_uuids, uuids_len, null_mut(), &mut cards_buf_len)
                },
                "SCardListCardsA failed"
            )?;

            let mut cards = vec![0; cards_buf_len.try_into()?];

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardListCardsA)(
                        self.h_context,
                        atr,
                        c_uuids,
                        uuids_len,
                        cards.as_mut_ptr(),
                        &mut cards_buf_len,
                    )
                },
                "SCardListCardsA failed"
            )?;

            parse_multi_string_owned(&cards)
        }
    }

    fn get_card_type_provider_name(&self, _card_name: &str, provider_id: ProviderId) -> WinScardResult<Cow<str>> {
        #[cfg(not(target_os = "windows"))]
        {
            Ok(match provider_id {
                ProviderId::Primary => {
                    return Err(Error::new(
                        ErrorKind::UnsupportedFeature,
                        "ProviderId::Primary is not supported for emulated smart card",
                    ))
                }
                ProviderId::Csp => winscard::MICROSOFT_DEFAULT_CSP.into(),
                ProviderId::Ksp => winscard::MICROSOFT_DEFAULT_KSP.into(),
                ProviderId::CardModule => winscard::MICROSOFT_SCARD_DRIVER_LOCATION.into(),
            })
        }
        #[cfg(target_os = "windows")]
        {
            use crate::winscard::buf_alloc::SCARD_AUTOALLOCATE;

            let mut data_len = SCARD_AUTOALLOCATE;
            let mut data: *mut u8 = null_mut();

            let c_card_name = CString::new(_card_name)?;

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardGetCardTypeProviderNameA)(
                        self.h_context,
                        c_card_name.as_ptr() as *const _,
                        provider_id.into(),
                        ((&mut data) as *mut *mut u8) as *mut _,
                        &mut data_len,
                    )
                },
                "SCardGetCardTypeProviderNameA failed"
            )?;

            let data_len: usize = if let Ok(len) = data_len.try_into() {
                len
            } else {
                try_execute!(
                    // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle.
                    unsafe { (self.api.SCardFreeMemory)(self.h_context, data as *const _) },
                    "SCardFreeMemory failed"
                )?;

                return Err(Error::new(ErrorKind::InternalError, "u32 to usize conversion error"));
            };

            let name = if let Ok(name) = String::from_utf8(
                // SAFETY: A slice create is safe because the `data` pointer is a local pointer and
                // was initialized by `SCardGetCardTypeProviderNameA` function.
                unsafe { from_raw_parts(data, data_len) }.to_vec(),
            ) {
                name
            } else {
                try_execute!(
                    // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle.
                    unsafe { (self.api.SCardFreeMemory)(self.h_context, data as *const _) },
                    "SCardFreeMemory failed"
                )?;

                return Err(Error::new(ErrorKind::InternalError, "u32 to usize conversion error"));
            };

            Ok(Cow::Owned(name))
        }
    }
}
