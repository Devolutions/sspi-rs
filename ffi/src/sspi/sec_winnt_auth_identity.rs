use std::ptr::copy_nonoverlapping;
#[cfg(windows)]
use std::ptr::null_mut;
use std::slice::from_raw_parts;

use libc::{c_char, c_void};
#[cfg(windows)]
use sspi::Secret;
#[cfg(all(feature = "scard", target_os = "windows"))]
use sspi::SmartCardIdentityBuffers;
use sspi::{AuthIdentityBuffers, CredentialsBuffers, Error, ErrorKind, Result};
#[cfg(windows)]
use symbol_rename_macro::rename_symbol;
#[cfg(all(feature = "scard", target_os = "windows"))]
use windows_sys::Win32::Security::Credentials::CredIsMarshaledCredentialW;
#[cfg(feature = "tsssp")]
use windows_sys::Win32::Security::Credentials::{CredUIPromptForWindowsCredentialsW, CREDUI_INFOW};

use super::sspi_data_types::{SecWChar, SecurityStatus};
use crate::utils::{credentials_str_into_bytes, into_raw_ptr, w_str_len};

pub const SEC_WINNT_AUTH_IDENTITY_ANSI: u32 = 0x1;
pub const SEC_WINNT_AUTH_IDENTITY_UNICODE: u32 = 0x2;

#[repr(C)]
pub struct SecWinntAuthIdentityW {
    pub user: *const u16,
    pub user_length: u32,
    pub domain: *const u16,
    pub domain_length: u32,
    pub password: *const u16,
    pub password_length: u32,
    pub flags: u32,
}

#[repr(C)]
pub struct SecWinntAuthIdentityA {
    pub user: *const c_char,
    pub user_length: u32,
    pub domain: *const c_char,
    pub domain_length: u32,
    pub password: *const c_char,
    pub password_length: u32,
    pub flags: u32,
}

pub const SEC_WINNT_AUTH_IDENTITY_VERSION: u32 = 0x200;

#[derive(Debug)]
#[repr(C)]
pub struct SecWinntAuthIdentityExW {
    pub version: u32,
    pub length: u32,
    pub user: *const u16,
    pub user_length: u32,
    pub domain: *const u16,
    pub domain_length: u32,
    pub password: *const u16,
    pub password_length: u32,
    pub flags: u32,
    pub package_list: *const u16,
    pub package_list_length: u32,
}

#[repr(C)]
pub struct SecWinntAuthIdentityExA {
    pub version: u32,
    pub length: u32,
    pub user: *const c_char,
    pub user_length: u32,
    pub domain: *const c_char,
    pub domain_length: u32,
    pub password: *const c_char,
    pub password_length: u32,
    pub flags: u32,
    pub package_list: *const c_char,
    pub package_list_length: u32,
}

pub const SEC_WINNT_AUTH_IDENTITY_VERSION_2: u32 = 0x201;

/// [SEC_WINNT_AUTH_IDENTITY_EX2](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_winnt_auth_identity_ex2)
///
/// ```not_rust
/// typedef struct _SEC_WINNT_AUTH_IDENTITY_EX2 {
///   unsigned long  Version;
///   unsigned short cbHeaderLength;
///   unsigned long  cbStructureLength;
///   unsigned long  UserOffset;
///   unsigned short UserLength;
///   unsigned long  DomainOffset;
///   unsigned short DomainLength;
///   unsigned long  PackedCredentialsOffset;
///   unsigned short PackedCredentialsLength;
///   unsigned long  Flags;
///   unsigned long  PackageListOffset;
///   unsigned short PackageListLength;
/// } SEC_WINNT_AUTH_IDENTITY_EX2, *PSEC_WINNT_AUTH_IDENTITY_EX2;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecWinntAuthIdentityEx2 {
    pub version: u32,
    pub cb_header_length: u16,
    pub cb_structure_length: u32,
    pub user_offset: u32,
    pub user_length: u16,
    pub domain_offset: u32,
    pub domain_length: u16,
    pub packed_credentials_offset: u32,
    pub packed_credentials_length: u16,
    pub flags: u32,
    pub package_list_offset: u32,
    pub package_list_length: u16,
}

/// [CREDSPP_SUBMIT_TYPE](https://learn.microsoft.com/en-us/windows/win32/api/credssp/ne-credssp-credspp_submit_type)
///
/// ```not_rust
/// typedef enum _CREDSSP_SUBMIT_TYPE {
///   CredsspPasswordCreds = 2,
///   CredsspSchannelCreds = 4,
///   CredsspCertificateCreds = 13,
///   CredsspSubmitBufferBoth = 50,
///   CredsspSubmitBufferBothOld = 51,
///   CredsspCredEx = 100
/// } CREDSPP_SUBMIT_TYPE;
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub enum CredSspSubmitType {
    CredsspPasswordCreds = 2,
    CredsspSchannelCreds = 4,
    CredsspCertificateCreds = 13,
    CredsspSubmitBufferBoth = 50,
    CredsspSubmitBufferBothOld = 51,
    CredsspCredEx = 100,
}

/// [CREDSSP_CRED](https://learn.microsoft.com/en-us/windows/win32/api/credssp/ns-credssp-credssp_cred)
///
/// ```not_rust
/// typedef struct _CREDSSP_CRED {
///   CREDSPP_SUBMIT_TYPE Type;
///   PVOID               pSchannelCred;
///   PVOID               pSpnegoCred;
/// } CREDSSP_CRED, *PCREDSSP_CRED;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct CredSspCred {
    pub submit_type: CredSspSubmitType,
    pub p_schannel_cred: *const c_void,
    pub p_spnego_cred: *const c_void,
}

pub unsafe fn get_auth_data_identity_version_and_flags(p_auth_data: *const c_void) -> (u32, u32) {
    let auth_version = *p_auth_data.cast::<u32>();
    if auth_version == SEC_WINNT_AUTH_IDENTITY_VERSION {
        let auth_data = p_auth_data.cast::<SecWinntAuthIdentityExW>();
        (auth_version, (*auth_data).flags)
    } else if auth_version == SEC_WINNT_AUTH_IDENTITY_VERSION_2 {
        let auth_data = p_auth_data.cast::<SecWinntAuthIdentityEx2>();
        (auth_version, (*auth_data).flags)
    } else {
        // SEC_WINNT_AUTH_IDENTITY
        let auth_data = p_auth_data.cast::<SecWinntAuthIdentityW>();
        (auth_version, (*auth_data).flags)
    }
}

// The only one purpose of this function is to handle CredSSP credentials passed into the AcquireCredentialsHandle function
#[cfg(feature = "tsssp")]
unsafe fn credssp_auth_data_to_identity_buffers(p_auth_data: *const c_void) -> Result<CredentialsBuffers> {
    use sspi::string_to_utf16;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;

    let credssp_cred = p_auth_data.cast::<CredSspCred>().as_ref().unwrap();

    if credssp_cred.submit_type == CredSspSubmitType::CredsspSubmitBufferBothOld {
        if credssp_cred.p_spnego_cred.is_null() {
            // When logging on using the saved (remembered) credentials, the mstsc sets the submit_type to CredSspSubmitType::CredsspSubmitBufferBothOld
            // and p_spnego_cred to NULL. Then the inner security package should use saved credentials in the Credentials Manager for the authentication.
            // But, unfortunately, we are unable to read those credentials because they are accessible only for Microsoft's security packages.
            //
            // [CRED_TYPE_DOMAIN_PASSWORD](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw)
            // The NTLM, Kerberos, and Negotiate authentication packages will automatically use this credential when connecting to the named target.
            // More info: https://blog.gentilkiwi.com/tag/cred_type_domain_password
            //
            // In this case, we just asked the user to re-enter the credentials.
            let message = string_to_utf16("We're unable to load saved credentials\0");
            let caption = string_to_utf16("Enter credentials\0");
            let cred_ui_info = CREDUI_INFOW {
                cbSize: std::mem::size_of::<CREDUI_INFOW>().try_into().unwrap(),
                hwndParent: null_mut(),
                pszMessageText: message.as_ptr() as *const _,
                pszCaptionText: caption.as_ptr() as *const _,
                hbmBanner: null_mut(),
            };
            let mut auth_package_count = 0;
            let mut out_buffer_size = 1024;
            let mut out_buffer = null_mut();

            let result = CredUIPromptForWindowsCredentialsW(
                &cred_ui_info,
                0,
                &mut auth_package_count,
                null_mut(),
                0,
                &mut out_buffer,
                &mut out_buffer_size,
                null_mut(),
                0,
            );

            if result != ERROR_SUCCESS {
                return Err(Error::new(
                    ErrorKind::NoCredentials,
                    format!("Can not get user credentials: {:0x?}", result),
                ));
            }

            unpack_sec_winnt_auth_identity_ex2_w_sized(out_buffer, out_buffer_size)
        } else {
            // When we try to pass the plain password in the `ClearTextPassword` .rdp file property,
            // the CredSSP credentials will have the type `CredsspSubmitBufferBothOld` and
            // will be packed in the `SEC_WINNT_AUTH_IDENTITY_W` structure.
            //
            // Additional info:
            // * [ClearTextPassword](https://github.com/Devolutions/MsRdpEx/blob/a7978812cb31e363f4b536316bd59e1573e69384/README.md#extended-rdp-file-options)
            auth_data_to_identity_buffers_w(credssp_cred.p_spnego_cred, &mut None)
        }
    } else {
        unpack_sec_winnt_auth_identity_ex2_w(credssp_cred.p_spnego_cred)
    }
}

// This function determines what format credentials have: ASCII or UNICODE,
// and then calls an appropriate raw credentials handler function.
// Why do we need such a function:
// Actually, on Linux FreeRDP can pass UNICODE credentials into the AcquireCredentialsHandleA function.
// So, we need to be able to handle any credentials format in the AcquireCredentialsHandleA/W functions.
pub unsafe fn auth_data_to_identity_buffers(
    _security_package_name: &str,
    p_auth_data: *const c_void,
    package_list: &mut Option<String>,
) -> Result<CredentialsBuffers> {
    #[cfg(feature = "tsssp")]
    if _security_package_name == sspi::credssp::sspi_cred_ssp::PKG_NAME {
        return credssp_auth_data_to_identity_buffers(p_auth_data);
    }

    let (_, auth_flags) = get_auth_data_identity_version_and_flags(p_auth_data);

    if (auth_flags & SEC_WINNT_AUTH_IDENTITY_ANSI) != 0 {
        auth_data_to_identity_buffers_a(p_auth_data, package_list)
    } else {
        auth_data_to_identity_buffers_w(p_auth_data, package_list)
    }
}

pub unsafe fn auth_data_to_identity_buffers_a(
    p_auth_data: *const c_void,
    package_list: &mut Option<String>,
) -> Result<CredentialsBuffers> {
    let (auth_version, _) = get_auth_data_identity_version_and_flags(p_auth_data);

    if auth_version == SEC_WINNT_AUTH_IDENTITY_VERSION {
        let auth_data = p_auth_data.cast::<SecWinntAuthIdentityExA>();
        if !(*auth_data).package_list.is_null() && (*auth_data).package_list_length > 0 {
            *package_list = Some(
                String::from_utf8_lossy(from_raw_parts(
                    (*auth_data).package_list as *const _,
                    (*auth_data).package_list_length as usize,
                ))
                .to_string(),
            );
        }
        Ok(CredentialsBuffers::AuthIdentity(AuthIdentityBuffers {
            user: credentials_str_into_bytes((*auth_data).user, (*auth_data).user_length as usize),
            domain: credentials_str_into_bytes((*auth_data).domain, (*auth_data).domain_length as usize),
            password: credentials_str_into_bytes((*auth_data).password, (*auth_data).password_length as usize).into(),
        }))
    } else {
        let auth_data = p_auth_data.cast::<SecWinntAuthIdentityA>();
        Ok(CredentialsBuffers::AuthIdentity(AuthIdentityBuffers {
            user: credentials_str_into_bytes((*auth_data).user, (*auth_data).user_length as usize),
            domain: credentials_str_into_bytes((*auth_data).domain, (*auth_data).domain_length as usize),
            password: credentials_str_into_bytes((*auth_data).password, (*auth_data).password_length as usize).into(),
        }))
    }
}

pub unsafe fn auth_data_to_identity_buffers_w(
    p_auth_data: *const c_void,
    package_list: &mut Option<String>,
) -> Result<CredentialsBuffers> {
    let (auth_version, _) = get_auth_data_identity_version_and_flags(p_auth_data);

    if auth_version == SEC_WINNT_AUTH_IDENTITY_VERSION {
        let auth_data = p_auth_data.cast::<SecWinntAuthIdentityExW>();
        if !(*auth_data).package_list.is_null() && (*auth_data).package_list_length > 0 {
            *package_list = Some(String::from_utf16_lossy(from_raw_parts(
                (*auth_data).package_list,
                usize::try_from((*auth_data).package_list_length).unwrap(),
            )));
        }
        let user = credentials_str_into_bytes((*auth_data).user as *const _, (*auth_data).user_length as usize * 2);
        let password = credentials_str_into_bytes(
            (*auth_data).password as *const _,
            (*auth_data).password_length as usize * 2,
        )
        .into();

        // Only marshaled smart card creds starts with '@' char.
        #[cfg(all(feature = "scard", target_os = "windows"))]
        if !user.is_empty() && CredIsMarshaledCredentialW(user.as_ptr() as *const _) != 0 {
            return handle_smart_card_creds(user, password);
        }

        Ok(CredentialsBuffers::AuthIdentity(AuthIdentityBuffers {
            user,
            domain: credentials_str_into_bytes(
                (*auth_data).domain as *const _,
                (*auth_data).domain_length as usize * 2,
            ),
            password,
        }))
    } else {
        let auth_data = p_auth_data.cast::<SecWinntAuthIdentityW>();
        let user = credentials_str_into_bytes((*auth_data).user as *const _, (*auth_data).user_length as usize * 2);
        let password = credentials_str_into_bytes(
            (*auth_data).password as *const _,
            (*auth_data).password_length as usize * 2,
        )
        .into();

        // Only marshaled smart card creds starts with '@' char.
        #[cfg(all(feature = "scard", target_os = "windows"))]
        if !user.is_empty() && CredIsMarshaledCredentialW(user.as_ptr() as *const _) != 0 {
            return handle_smart_card_creds(user, password);
        }

        // Try to collect credentials for the emulated smart card.
        #[cfg(all(feature = "scard", target_os = "windows"))]
        if let Ok(scard_creds) = collect_smart_card_creds(&user, password.as_ref()) {
            return Ok(CredentialsBuffers::SmartCard(scard_creds));
        }

        Ok(CredentialsBuffers::AuthIdentity(AuthIdentityBuffers {
            user,
            domain: credentials_str_into_bytes(
                (*auth_data).domain as *const _,
                (*auth_data).domain_length as usize * 2,
            ),
            password,
        }))
    }
}

#[cfg(all(feature = "scard", target_os = "windows"))]
fn collect_smart_card_creds(username: &[u8], password: &[u8]) -> Result<SmartCardIdentityBuffers> {
    if username.contains(&b'@') {
        info!("Trying to collect smart card creds...");
        use winscard::{SmartCardInfo, DEFAULT_CARD_NAME, MICROSOFT_DEFAULT_CSP};

        use crate::sspi::utils::raw_wide_str_trim_nulls;
        use crate::utils::str_encode_utf16;

        match SmartCardInfo::try_from_env() {
            Ok(smart_card_info) => {
                let mut username = username.to_vec();
                let mut pin = password.to_vec();

                raw_wide_str_trim_nulls(&mut username);
                raw_wide_str_trim_nulls(&mut pin);

                info!("Smart card credentials have been collected. Process with scard-based logon.");

                return Ok(SmartCardIdentityBuffers {
                    username,
                    certificate: smart_card_info.auth_cert_der.clone(),
                    card_name: Some(str_encode_utf16(DEFAULT_CARD_NAME)),
                    reader_name: str_encode_utf16(smart_card_info.reader.name.as_ref()),
                    container_name: str_encode_utf16(smart_card_info.container_name.as_ref()),
                    csp_name: str_encode_utf16(MICROSOFT_DEFAULT_CSP),
                    pin: pin.into(),
                    private_key_file_index: None,
                    private_key_pem: Some(str_encode_utf16(smart_card_info.auth_pk_pem.as_ref())),
                });
            }
            Err(err) => {
                warn!(?err);
            }
        }
    }

    Err(Error::new(
        ErrorKind::NoCredentials,
        "Failed to collect smart card credentials. Process with password-based logon.",
    ))
}

#[cfg(not(target_os = "windows"))]
pub fn unpack_sec_winnt_auth_identity_ex2_a(_p_auth_data: *const c_void) -> Result<AuthIdentityBuffers> {
    Err(Error::new(
        ErrorKind::UnsupportedFunction,
        "SecWinntIdentityEx2 is not supported on non Windows systems",
    ))
}

#[cfg(target_os = "windows")]
unsafe fn get_sec_winnt_auth_identity_ex2_size(p_auth_data: *const c_void) -> u32 {
    // https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_winnt_auth_identity_ex2
    // https://github.com/FreeRDP/FreeRDP/blob/master/winpr/libwinpr/sspi/sspi_winpr.c#L473

    // Username length is placed after the first 8 bytes.
    let user_len_ptr = (p_auth_data as *const u16).add(4);
    let user_buffer_len = *user_len_ptr as u32;

    // Domain length is placed after 16 bytes from the username length.
    let domain_len_ptr = user_len_ptr.add(8);
    let domain_buffer_len = *domain_len_ptr as u32;

    // Packet credentials length is placed after 16 bytes from the domain length.
    let creds_len_ptr = domain_len_ptr.add(8);
    let creds_buffer_len = *creds_len_ptr as u32;

    // The resulting size is queal to header size + buffers size.
    64 /* size of the SEC_WINNT_AUTH_IDENTITY_EX2 */ + user_buffer_len + domain_buffer_len + creds_buffer_len
}

#[cfg(target_os = "windows")]
pub unsafe fn unpack_sec_winnt_auth_identity_ex2_a(p_auth_data: *const c_void) -> Result<CredentialsBuffers> {
    use windows_sys::Win32::Security::Credentials::{CredUnPackAuthenticationBufferA, CRED_PACK_PROTECTED_CREDENTIALS};

    if p_auth_data.is_null() {
        return Err(Error::new(
            ErrorKind::InvalidParameter,
            "Cannot unpack credentials: p_auth_data is null",
        ));
    }

    let auth_data_len = get_sec_winnt_auth_identity_ex2_size(p_auth_data);

    let mut username_len = 0;
    let mut domain_len = 0;
    let mut password_len = 0;

    // The first call is just to query the username, domain, and password lengths.
    CredUnPackAuthenticationBufferA(
        CRED_PACK_PROTECTED_CREDENTIALS,
        p_auth_data,
        auth_data_len,
        null_mut() as *mut _,
        &mut username_len,
        null_mut() as *mut _,
        &mut domain_len,
        null_mut() as *mut _,
        &mut password_len,
    );

    let mut username = vec![0_u8; username_len as usize];
    let mut domain = vec![0_u8; domain_len as usize];
    let mut password = Secret::new(vec![0_u8; password_len as usize]);

    // Knowing the actual sizes, we can unpack credentials into prepared buffers.
    let result = CredUnPackAuthenticationBufferA(
        CRED_PACK_PROTECTED_CREDENTIALS,
        p_auth_data,
        auth_data_len,
        username.as_mut_ptr() as *mut _,
        &mut username_len,
        domain.as_mut_ptr() as *mut _,
        &mut domain_len,
        password.as_mut().as_mut_ptr() as *mut _,
        &mut password_len,
    );

    if result != 1 {
        return Err(Error::new(
            ErrorKind::WrongCredentialHandle,
            "Cannot unpack credentials",
        ));
    }

    let mut auth_identity_buffers = AuthIdentityBuffers::default();

    // In the `auth_identity_buffers` structure we hold credentials as raw wide string without NULL-terminator bytes.
    // The `CredUnPackAuthenticationBufferW` function always returns credentials as strings.
    // So, username data is a C string and we need to delete the NULL terminator.
    username.pop();
    auth_identity_buffers.user = username;

    if domain_len == 0 {
        // Sometimes username can be formatted as `DOMAIN\username`.
        if let Some(index) = auth_identity_buffers.user.iter().position(|b| *b == b'\\') {
            auth_identity_buffers.domain = auth_identity_buffers.user[0..index].to_vec();
            auth_identity_buffers.user = auth_identity_buffers.user[(index + 1)..].to_vec();
        }
    } else {
        // In the `auth_identity_buffers` structure we hold credentials as raw wide string without NULL-terminator bytes.
        // The `CredUnPackAuthenticationBufferW` function always returns credentials as strings.
        // So, domain data is a C string and we need to delete the NULL terminator.
        domain.pop();
        auth_identity_buffers.domain = domain;
    }

    // In the `auth_identity_buffers` structure we hold credentials as raw wide string without NULL-terminator bytes.
    // The `CredUnPackAuthenticationBufferW` function always returns credentials as strings.
    // So, password data is a C string and we need to delete the NULL terminator.
    password.as_mut().pop();
    auth_identity_buffers.password = password;

    Ok(CredentialsBuffers::AuthIdentity(auth_identity_buffers))
}

#[cfg(not(target_os = "windows"))]
pub fn unpack_sec_winnt_auth_identity_ex2_w(_p_auth_data: *const c_void) -> Result<CredentialsBuffers> {
    Err(Error::new(
        ErrorKind::UnsupportedFunction,
        "SecWinntIdentityEx2 is not supported on non Windows systems",
    ))
}

#[cfg(all(feature = "scard", target_os = "windows"))]
#[instrument(level = "trace", ret)]
unsafe fn handle_smart_card_creds(mut username: Vec<u8>, password: Secret<Vec<u8>>) -> Result<CredentialsBuffers> {
    use std::ptr::null_mut;

    use sspi::cert_utils::{finalize_smart_card_info, SmartCardInfo};
    use sspi::string_to_utf16;
    use windows_sys::Win32::Security::Credentials::{CertCredential, CredUnmarshalCredentialW, CERT_CREDENTIAL_INFO};

    let mut cred_type = 0;
    let mut credential = null_mut();

    // Win API expects the C string as the first input parameter.
    // So, we need add the NULL terminator.
    username.extend_from_slice(&[0, 0]);

    if CredUnmarshalCredentialW(username.as_ptr() as *const _, &mut cred_type, &mut credential) == 0 {
        return Err(Error::new(
            ErrorKind::NoCredentials,
            "Cannot unmarshal smart card credentials",
        ));
    }

    if cred_type != CertCredential {
        return Err(Error::new(
            ErrorKind::NoCredentials,
            "Unmarshalled smart card credentials is not CRED_MARSHAL_TYPE::CertCredential",
        ));
    }

    let cert_credential = credential.cast::<CERT_CREDENTIAL_INFO>();

    let (raw_certificate, certificate) =
        sspi::cert_utils::extract_certificate_by_thumbprint(&(*cert_credential).rgbHashOfCert)?;

    let username = string_to_utf16(sspi::cert_utils::extract_user_name_from_certificate(&certificate)?);
    let SmartCardInfo {
        key_container_name,
        reader_name,
        certificate: _,
        csp_name,
        private_key_file_index,
    } = finalize_smart_card_info(&certificate.tbs_certificate.serial_number.0)?;

    let creds = CredentialsBuffers::SmartCard(SmartCardIdentityBuffers {
        certificate: raw_certificate,
        reader_name: string_to_utf16(reader_name),
        pin: password,
        username,
        card_name: None,
        container_name: string_to_utf16(key_container_name),
        csp_name: string_to_utf16(csp_name),
        private_key_file_index: Some(private_key_file_index),
        private_key_pem: None,
    });

    Ok(creds)
}

#[cfg(feature = "tsssp")]
#[instrument(level = "trace", ret)]
pub unsafe fn unpack_sec_winnt_auth_identity_ex2_w(p_auth_data: *const c_void) -> Result<CredentialsBuffers> {
    if p_auth_data.is_null() {
        return Err(Error::new(
            ErrorKind::InvalidParameter,
            "Cannot unpack credentials: p_auth_data is null",
        ));
    }

    let auth_data_len = get_sec_winnt_auth_identity_ex2_size(p_auth_data);

    unpack_sec_winnt_auth_identity_ex2_w_sized(p_auth_data, auth_data_len)
}

#[cfg(feature = "tsssp")]
#[instrument(level = "trace", ret)]
pub unsafe fn unpack_sec_winnt_auth_identity_ex2_w_sized(
    p_auth_data: *const c_void,
    auth_data_len: u32,
) -> Result<CredentialsBuffers> {
    use std::ptr::null_mut;

    use windows_sys::Win32::Security::Credentials::{CredUnPackAuthenticationBufferW, CRED_PACK_PROTECTED_CREDENTIALS};

    use super::utils::raw_wide_str_trim_nulls;

    if p_auth_data.is_null() {
        return Err(Error::new(
            ErrorKind::InvalidParameter,
            "Cannot unpack credentials: p_auth_data is null",
        ));
    }

    let mut username_len = 0;
    let mut domain_len = 0;
    let mut password_len = 0;

    // The first call is just to query the username, domain, and password lengths.
    CredUnPackAuthenticationBufferW(
        CRED_PACK_PROTECTED_CREDENTIALS,
        p_auth_data,
        auth_data_len,
        null_mut() as *mut _,
        &mut username_len,
        null_mut() as *mut _,
        &mut domain_len,
        null_mut() as *mut _,
        &mut password_len,
    );

    let mut username = vec![0_u8; username_len as usize * 2];
    let mut domain = vec![0_u8; domain_len as usize * 2];
    let mut password = Secret::new(vec![0_u8; password_len as usize * 2]);

    let result = CredUnPackAuthenticationBufferW(
        CRED_PACK_PROTECTED_CREDENTIALS,
        p_auth_data,
        auth_data_len,
        username.as_mut_ptr() as *mut _,
        &mut username_len,
        domain.as_mut_ptr() as *mut _,
        &mut domain_len,
        password.as_mut().as_mut_ptr() as *mut _,
        &mut password_len,
    );

    if result != 1 {
        return Err(Error::new(
            ErrorKind::WrongCredentialHandle,
            "Cannot unpack credentials",
        ));
    }

    // Try to collect credentials for the emulated smart card.
    #[cfg(feature = "scard")]
    if let Ok(scard_creds) = collect_smart_card_creds(&username, password.as_ref()) {
        return Ok(CredentialsBuffers::SmartCard(scard_creds));
    }

    // Only marshaled smart card creds starts with '@' char.
    #[cfg(feature = "scard")]
    if !username.is_empty() && CredIsMarshaledCredentialW(username.as_ptr() as *const _) != 0 {
        // The `handle_smart_card_creds` function expects credentials in a form of raw wide strings without NULL-terminator bytes.
        // The `CredUnPackAuthenticationBufferW` function always returns credentials as strings.
        // So, password data is a wide C string and we need to delete the NULL terminator.
        let new_len = password.as_ref().len() - 2;
        password.as_mut().truncate(new_len);

        return handle_smart_card_creds(username, password);
    }

    let mut auth_identity_buffers = AuthIdentityBuffers::default();

    // In the `auth_identity_buffers` structure we hold credentials as raw wide string without NULL-terminator bytes.
    // The `CredUnPackAuthenticationBufferW` function always returns credentials as strings.
    // So, username data is a wide C string and we need to delete the NULL terminator.
    raw_wide_str_trim_nulls(&mut username);
    auth_identity_buffers.user = username;

    if domain_len == 0 {
        // Sometimes username can be formatted as `DOMAIN\username`.
        if let Some(index) = auth_identity_buffers.user.iter().position(|b| *b == b'\\') {
            auth_identity_buffers.domain = auth_identity_buffers.user[0..index].to_vec();
            auth_identity_buffers.user = auth_identity_buffers.user[(index + 2)..].to_vec();
        }
    } else {
        // In the `auth_identity_buffers` structure we hold credentials as raw wide string without NULL-terminator bytes.
        // The `CredUnPackAuthenticationBufferW` function always returns credentials as strings.
        // So, domain data is a wide C string and we need to delete the NULL terminator.
        domain.truncate(domain.len() - 2);
        auth_identity_buffers.domain = domain;
    }

    // In the `auth_identity_buffers` structure we hold credentials as raw wide string without NULL-terminator bytes.
    // The `CredUnPackAuthenticationBufferW` function always returns credentials as strings.
    // So, password data is a wide C string and we need to delete the NULL terminator.
    let new_len = password.as_ref().len() - 2;
    password.as_mut().truncate(new_len);
    auth_identity_buffers.password = password;

    Ok(CredentialsBuffers::AuthIdentity(auth_identity_buffers))
}

#[allow(clippy::missing_safety_doc)]
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_SspiEncodeStringsAsAuthIdentity"))]
#[no_mangle]
pub unsafe extern "system" fn SspiEncodeStringsAsAuthIdentity(
    psz_user_name: *const SecWChar,
    psz_domain_name: *const SecWChar,
    psz_packed_credentials_string: *const SecWChar,
    pp_auth_identity: *mut *mut c_void,
) -> SecurityStatus {
    catch_panic! {
        check_null!(pp_auth_identity);
        check_null!(psz_user_name);
        check_null!(psz_domain_name);
        check_null!(psz_packed_credentials_string);

        let user_length = w_str_len(psz_user_name);
        let domain_length = w_str_len(psz_domain_name);
        let password_length = w_str_len(psz_packed_credentials_string);

        if user_length == 0 || domain_length == 0 || password_length == 0 {
            return ErrorKind::InvalidParameter.to_u32().unwrap();
        }

        let user = unsafe { libc::malloc(user_length * 2) as *mut SecWChar };
        if user.is_null() {
            return ErrorKind::InternalError.to_u32().unwrap();
        }
        copy_nonoverlapping(psz_user_name, user, user_length);

        let domain = unsafe { libc::malloc(domain_length * 2) as *mut SecWChar };
        if domain.is_null() {
            return ErrorKind::InternalError.to_u32().unwrap();
        }
        copy_nonoverlapping(psz_domain_name, domain, domain_length);

        let password = unsafe { libc::malloc(password_length * 2) as *mut SecWChar };
        if password.is_null() {
            return ErrorKind::InternalError.to_u32().unwrap();
        }
        copy_nonoverlapping(psz_packed_credentials_string, password, password_length);

        let auth_identity = SecWinntAuthIdentityW {
            user,
            user_length: user_length.try_into().unwrap(),
            domain,
            domain_length: domain_length.try_into().unwrap(),
            password,
            password_length: password_length.try_into().unwrap(),
            flags: 0,
        };

        *pp_auth_identity = into_raw_ptr(auth_identity) as *mut c_void;

        0
    }
}

#[allow(clippy::missing_safety_doc)]
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_SspiFreeAuthIdentity"))]
#[no_mangle]
pub unsafe extern "system" fn SspiFreeAuthIdentity(auth_data: *mut c_void) -> SecurityStatus {
    catch_panic! {
        if auth_data.is_null() {
            return 0;
        }

        let auth_data = auth_data as *mut SecWinntAuthIdentityW;

        unsafe { libc::free((*auth_data).user as *mut _) };
        unsafe { libc::free((*auth_data).domain as *mut _) };
        unsafe { libc::free((*auth_data).password as *mut _) };

        let _auth_data: Box<SecWinntAuthIdentityW> = Box::from_raw(auth_data);

        0
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::{null, null_mut};
    use std::slice::from_raw_parts;

    use libc::c_void;
    use num_traits::ToPrimitive;
    use sspi::ErrorKind;

    use super::{SecWinntAuthIdentityW, SspiEncodeStringsAsAuthIdentity, SspiFreeAuthIdentity};

    fn get_user_credentials() -> ([u16; 5], [u16; 5], [u16; 7]) {
        // (user, pass, domain)
        (
            [0x75, 0x73, 0x65, 0x72, 0],
            [0x70, 0x61, 0x73, 0x73, 0],
            [0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0],
        )
    }

    #[test]
    fn sspi_encode_strings_as_auth_identity() {
        let (username, password, domain) = get_user_credentials();
        let mut identity = null_mut::<c_void>();

        unsafe {
            let status =
                SspiEncodeStringsAsAuthIdentity(username.as_ptr(), domain.as_ptr(), password.as_ptr(), &mut identity);

            assert_eq!(status, 0);
            assert!(!identity.is_null());

            let identity = identity.cast::<SecWinntAuthIdentityW>();

            assert_eq!(
                "user",
                String::from_utf16_lossy(from_raw_parts((*identity).user, (*identity).user_length as usize))
            );
            assert_eq!(
                "pass",
                String::from_utf16_lossy(from_raw_parts(
                    (*identity).password,
                    (*identity).password_length as usize
                ))
            );
            assert_eq!(
                "domain",
                String::from_utf16_lossy(from_raw_parts((*identity).domain, (*identity).domain_length as usize))
            );

            let status = SspiFreeAuthIdentity(identity as *mut _);
            assert_eq!(status, 0);
        }
    }

    #[test]
    fn sspi_encode_strings_as_auth_identity_on_null() {
        let mut identity = null_mut::<c_void>();

        unsafe {
            let status = SspiEncodeStringsAsAuthIdentity(null(), null(), null(), &mut identity);

            assert_eq!(status, ErrorKind::InvalidParameter.to_u32().unwrap());
            assert!(identity.is_null());
        }
    }

    #[test]
    fn sspi_encode_strings_as_auth_identity_on_empty_creds() {
        let username = [0];
        let password = [0];
        let domain = [0];
        let mut identity = null_mut::<c_void>();

        unsafe {
            let status =
                SspiEncodeStringsAsAuthIdentity(username.as_ptr(), domain.as_ptr(), password.as_ptr(), &mut identity);

            assert_eq!(status, ErrorKind::InvalidParameter.to_u32().unwrap());
            assert!(identity.is_null());
        }
    }

    #[test]
    fn sspi_free_auth_identity() {
        let (username, password, domain) = get_user_credentials();
        let mut identity = null_mut::<c_void>();

        unsafe {
            let status =
                SspiEncodeStringsAsAuthIdentity(username.as_ptr(), domain.as_ptr(), password.as_ptr(), &mut identity);
            assert_eq!(status, 0);

            let status = SspiFreeAuthIdentity(identity);
            assert_eq!(status, 0);
        }
    }

    #[test]
    fn sspi_free_auth_identity_on_null() {
        unsafe {
            let status = SspiFreeAuthIdentity(null_mut::<c_void>());

            assert_eq!(status, 0);
        }
    }
}
