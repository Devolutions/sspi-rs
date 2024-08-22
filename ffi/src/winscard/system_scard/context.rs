use std::borrow::Cow;
use std::ffi::CString;
use std::ptr::{null, null_mut};
#[cfg(target_os = "windows")]
use std::slice::from_raw_parts;
#[cfg(not(target_os = "windows"))]
use std::collections::BTreeMap;
use picky_asn1_x509::{PublicKey, SubjectPublicKeyInfo};

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

pub struct SystemScardContext {
    h_context: ScardContext,
    #[cfg(target_os = "windows")]
    api: SCardApiFunctionTable,
    #[cfg(not(target_os = "windows"))]
    api: PcscLiteApiFunctionTable,
    #[cfg(not(target_os = "windows"))]
    cache: BTreeMap<String, Vec<u8>>,
}

use std::fmt;

impl fmt::Debug for SystemScardContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemScardContext")
            .field("h_context", &self.h_context)
            .finish()
    }
}

impl SystemScardContext {
    #[allow(dead_code)]
    pub fn establish(scope: ScardScope) -> WinScardResult<Self> {
        let mut h_context = 0;

        #[cfg(target_os = "windows")]
        let api = super::init_scard_api_table()?;
        #[cfg(not(target_os = "windows"))]
        let api = initialize_pcsc_lite_api()?;

        try_execute!(
            // SAFETY: This function is safe to call because the `scope` parameter value is type checked
            // and `*mut h_context` can't be `null`.
            unsafe { (api.SCardEstablishContext)(scope.into(), null_mut(), null_mut(), &mut h_context) },
            "SCardEstablishContext failed"
        )?;

        if h_context == 0 {
            return Err(Error::new(
                ErrorKind::InternalError,
                "can not establish context: SCardEstablishContext did not set the context handle",
            ));
        }

        debug!("foierjfoirefj: {} - {}", h_context, std::mem::size_of::<ScardContext>());

        // initialize scard cache
        use picky::x509::Cert;

        let auth_cert = {
            let cert_path = std::env::var("WINSCARD_CERTIFICATE_FILE_PATH").unwrap();
            let raw_certificate = std::fs::read_to_string(cert_path).unwrap();
            Cert::from_pem_str(&raw_certificate).unwrap()
        };
        let auth_cert_der = auth_cert.to_der().unwrap();

        let mut cache = BTreeMap::new();
        cache.insert("Cached_CardProperty_Read Only Mode_0".into(), {
            let mut value = [1, 0, 1, 0, 1, 0].to_vec();
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            // actual data len
            value.extend_from_slice(&4_u32.to_le_bytes());
            // true
            value.extend_from_slice(&1_u32.to_le_bytes());

            value
        });
        cache.insert("Cached_CardProperty_Cache Mode_0".into(), {
            let mut value = [1, 0, 1, 0, 1, 0].to_vec();
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            // actual data len
            value.extend_from_slice(&4_u32.to_le_bytes());
            // true
            value.extend_from_slice(&1_u32.to_le_bytes());

            value
        });
        cache.insert("Cached_CardProperty_Supports Windows x.509 Enrollment_0".into(), {
            let mut value = [1, 0, 1, 0, 1, 0].to_vec();
            // unkown flags
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            // actual data len
            value.extend_from_slice(&4_u32.to_le_bytes());
            // false
            value.extend_from_slice(&0_u32.to_le_bytes());

            value
        });
        cache.insert("Cached_GeneralFile/mscp/cmapfile".into(), {
            let mut value = [1, 0, 1, 0, 1, 0].to_vec();
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            // actual data len: size_of<CONTAINER_MAP_RECORD>()
            // https://github.com/selfrender/Windows-Server-2003/blob/5c6fe3db626b63a384230a1aa6b92ac416b0765f/ds/security/csps/wfsccsp/inc/basecsp.h#L104-L110
            value.extend_from_slice(&86_u32.to_le_bytes());
            // CONTAINER_MAP_RECORD:
            // let container = smart_card_info
            //     .container_name
            //     .as_ref()
            //     .encode_utf16()
            //     .chain(core::iter::once(0))
            //     .flat_map(|v| v.to_le_bytes())
            //     .collect::<Vec<_>>();
            let container = [49, 0, 100, 0, 56, 0, 97, 0, 99, 0, 54, 0, 53, 0, 56, 0, 45, 0, 101, 0, 48, 0, 54, 0, 53, 0, 45, 0, 57, 0, 50, 0, 97, 0, 48, 0, 45, 0, 56, 0, 53, 0, 97, 0, 102, 0, 45, 0, 48, 0, 57, 0, 48, 0, 98, 0, 48, 0, 55, 0, 53, 0, 102, 0, 99, 0, 49, 0, 48, 0, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            value.extend_from_slice(&container); // wszGuid
            value.extend_from_slice(&[3, 0]); // bFlags
            value.extend_from_slice(&[0, 0]); // wSigKeySizeBits
            value.extend_from_slice(&[0, 8]); // wKeyExchangeKeySizeBits

            value
        });
        cache.insert("Cached_ContainerProperty_PIN Identifier_0".into(), {
            let mut value = [1, 0, 1, 0, 1, 0].to_vec();
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

            let mut value = [1_u8, 0, 1, 0, 1, 0].to_vec();
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

            let public_key = auth_cert
                .public_key();
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
            let mut value = [1_u8, 0, 1, 0, 1, 0].to_vec();
            // unkown flags
            value.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

            value.extend_from_slice(&(auth_cert_der.len() as u16).to_le_bytes()); // uncompressed certificate data len
            value.extend_from_slice(&[0x00, 0x00]); // unknown flags
            value.extend_from_slice(&auth_cert_der);

            value
        });
        cache.insert("Cached_CardProperty_Capabilities_0".into(), {
            let mut value = [1_u8, 0, 1, 0, 1, 0].to_vec();
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

        Ok(Self {
            h_context,
            api,
            #[cfg(not(target_os = "windows"))]
            cache,
        })
    }
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
    fn connect(
        &self,
        reader_name: &str,
        share_mode: ShareMode,
        protocol: Option<Protocol>,
    ) -> WinScardResult<ScardConnectData> {
        debug!(reader_name, ?share_mode, ?protocol);

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

        debug!("eoijeioeriofjrefo: {} - {}", scard, std::mem::size_of::<ScardHandle>());
        let handle = Box::new(SystemScard::new(scard, self.h_context)?);

        Ok(ScardConnectData {
            handle,
            protocol: Protocol::from_bits(active_protocol.try_into().unwrap()).unwrap_or_default(),
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
                "SCardListReaders failed"
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
                "SCardListReaders failed"
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

    #[instrument]
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

    fn write_cache(
        &mut self,
        _card_id: Uuid,
        _freshness_counter: u32,
        key: String,
        mut value: Vec<u8>,
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
                        value.as_mut_ptr(),
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

    fn get_status_change(&self, _timeout: u32, reader_states: &mut [ReaderState]) -> WinScardResult<()> {
        #[cfg(not(target_os = "windows"))]
        {
            use winscard::winscard::CurrentState;
            use winscard::NEW_READER_NOTIFICATION;

            let supported_readers = self.list_readers()?;

            for reader_state in reader_states {
                if supported_readers.contains(&reader_state.reader_name) {
                    reader_state.event_state = CurrentState::SCARD_STATE_UNNAMED_CONSTANT
                        | CurrentState::SCARD_STATE_INUSE
                        | CurrentState::SCARD_STATE_PRESENT
                        | CurrentState::SCARD_STATE_CHANGED;
                    reader_state.atr[0..23].copy_from_slice(&[59, 253, 19, 0, 0, 129, 49, 254, 21, 128, 115, 192, 33, 192, 87, 89, 117, 98, 105, 75, 101, 121, 64]);
                    reader_state.atr_len = 23;
                } else if reader_state.reader_name.as_ref() == NEW_READER_NOTIFICATION {
                    reader_state.event_state = CurrentState::SCARD_STATE_UNNAMED_CONSTANT;
                } else {
                    error!(?reader_state.reader_name, "Unsupported reader");
                }
            }

            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            use std::ffi::NulError;

            use ffi_types::winscard::ScardReaderStateA;
            use winscard::winscard::CurrentState;

            let mut states = Vec::with_capacity(reader_states.len());
            let c_readers = reader_states
                .iter()
                .map(|reader_state| CString::new(reader_state.reader_name.as_ref()))
                .collect::<Result<Vec<CString>, NulError>>()?;

            for (reader_state, c_reader) in reader_states.iter_mut().zip(c_readers.iter()) {
                states.push(ScardReaderStateA {
                    sz_reader: c_reader.as_ptr() as *const _,
                    pv_user_data: reader_state.user_data as _,
                    dw_current_state: reader_state.current_state.bits(),
                    dw_event_state: reader_state.event_state.bits(),
                    cb_atr: reader_state.atr_len.try_into()?,
                    rgb_atr: reader_state.atr,
                });
            }

            try_execute!(
                // SAFETY: This function is safe to call because the `self.h_context` is always a valid handle
                // and other parameters are type checked.
                unsafe {
                    (self.api.SCardGetStatusChangeA)(
                        self.h_context,
                        _timeout,
                        states.as_mut_ptr(),
                        reader_states.len().try_into()?,
                    )
                },
                "SCardGetStatusChangeA failed"
            )?;

            // We do not need to change all fields. Only event state and atr values can be changed.
            for (state, reader_state) in states.iter().zip(reader_states.iter_mut()) {
                reader_state.event_state = CurrentState::from_bits(state.dw_event_state)
                    .ok_or_else(|| Error::new(ErrorKind::InternalError, "invalid dwEventState"))?;
                reader_state.atr_len = state.cb_atr.try_into()?;
                reader_state.atr = state.rgb_atr;
            }

            Ok(())
        }
    }

    fn list_cards(&self, _atr: Option<&[u8]>, _required_interfaces: Option<&[Uuid]>) -> WinScardResult<Vec<Cow<str>>> {
        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::new(
                ErrorKind::UnsupportedFeature,
                "SCardGetStatusChangeW function is not supported in PCSC-lite API",
            ))
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

    fn get_card_type_provider_name(&self, _card_name: &str, _provider_id: ProviderId) -> WinScardResult<Cow<str>> {
        #[cfg(not(target_os = "windows"))]
        {
            Err(Error::new(
                ErrorKind::UnsupportedFeature,
                "SCardGetCardTypeProviderNameW function is not supported in PCSC-lite API",
            ))
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
                        _provider_id.into(),
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

#[cfg(test)]
mod tests {
    use winscard::winscard::ScardScope;
    use winscard::winscard::WinScardContext;
    use winscard::winscard::Protocol;
    use winscard::winscard::ShareMode;

    use super::SystemScardContext;
    use crate::winscard::pcsc_lite::{initialize_pcsc_lite_api, ScardContext, ScardHandle};
    use std::mem::size_of;

    fn init_logging() {
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::filter::LevelFilter;
        use std::io;

        let stdout_layer = tracing_subscriber::fmt::layer()
            .with_level(true)
            .with_writer(io::stdout)
            .with_filter(LevelFilter::TRACE);

        tracing_subscriber::registry()
            .with(stdout_layer)
            .init()
    }

    #[test]
    fn bt() {
        init_logging();

        let scard_context = SystemScardContext::establish(ScardScope::User).unwrap();
        let mut scard = scard_context.connect(
            "Yubico YubiKey CCID 00 00",
            ShareMode::Shared,
            Some(Protocol::T0 | Protocol::T1),
        ).unwrap();
        // scard.handle.begin_transaction().unwrap();
        println!("{:?}", scard.handle.status().unwrap());
        // println!("{} {}", size_of::<ScardContext>(), size_of::<ScardHandle>())
    }

    #[test]
    fn rt() {
        // let mut h_context = 0;

        // let api = initialize_pcsc_lite_api()?;

        // try_execute!(
        //     // SAFETY: This function is safe to call because the `scope` parameter value is type checked
        //     // and `*mut h_context` can't be `null`.
        //     unsafe { (api.SCardEstablishContext)(scope.into(), null_mut(), null_mut(), &mut h_context) },
        //     "SCardEstablishContext failed"
        // ).unwrap();

        // assert!(h_context != 0);

        // debug!("Created context: {} - {}", h_context, std::mem::size_of::<ScardContext>());
    }
}
