use std::slice::from_raw_parts;

use libc::{c_char, c_void};
use sspi::{AuthIdentityBuffers, Error, ErrorKind, Result, CredentialsBuffers, SmartCardIdentityBuffers};
#[cfg(windows)]
use symbol_rename_macro::rename_symbol;

use crate::sspi_data_types::{SecWChar, SecurityStatus};
use crate::utils::{c_w_str_to_string, into_raw_ptr, raw_str_into_bytes};

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
#[derive(Debug)]
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

pub unsafe fn auth_data_to_identity_buffers(
    security_package_name: &str,
    p_auth_data: *const c_void,
    package_list: &mut Option<String>,
) -> Result<CredentialsBuffers> {
    warn!("auth_data_to_identity_buffers");
    let (_, auth_flags) = get_auth_data_identity_version_and_flags(p_auth_data);

    if (auth_flags & SEC_WINNT_AUTH_IDENTITY_UNICODE) != 0 {
        warn!("auth data to identity buffers w");
    } else {
        warn!("auth data to identity buffers a");
        // auth_data_to_identity_buffers_a(security_package_name, p_auth_data, package_list)
    }

    auth_data_to_identity_buffers_w(security_package_name, p_auth_data, package_list)

    // if (auth_flags & SEC_WINNT_AUTH_IDENTITY_UNICODE) != 0 {
    //     auth_data_to_identity_buffers_w(security_package_name, p_auth_data, package_list)
    // } else {
    //     auth_data_to_identity_buffers_a(security_package_name, p_auth_data, package_list)
    // }
}

pub unsafe fn auth_data_to_identity_buffers_a(
    _security_package_name: &str,
    p_auth_data: *const c_void,
    package_list: &mut Option<String>,
) -> Result<CredentialsBuffers> {
    #[cfg(feature = "tsssp")]
    if _security_package_name == sspi::credssp::sspi_cred_ssp::PKG_NAME {
        let credssp_cred = p_auth_data.cast::<CredSspCred>().as_ref().unwrap();

        return unpack_sec_winnt_auth_identity_ex2_a(credssp_cred.p_spnego_cred);
    }

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
            user: raw_str_into_bytes((*auth_data).user, (*auth_data).user_length as usize),
            domain: raw_str_into_bytes((*auth_data).domain, (*auth_data).domain_length as usize),
            password: raw_str_into_bytes((*auth_data).password, (*auth_data).password_length as usize).into(),
        }))
    } else {
        let auth_data = p_auth_data.cast::<SecWinntAuthIdentityA>();
        Ok(CredentialsBuffers::AuthIdentity(AuthIdentityBuffers {
            user: raw_str_into_bytes((*auth_data).user, (*auth_data).user_length as usize),
            domain: raw_str_into_bytes((*auth_data).domain, (*auth_data).domain_length as usize),
            password: raw_str_into_bytes((*auth_data).password, (*auth_data).password_length as usize).into(),
        }))
    }
}

pub unsafe fn auth_data_to_identity_buffers_w(
    _security_package_name: &str,
    p_auth_data: *const c_void,
    package_list: &mut Option<String>,
) -> Result<CredentialsBuffers> {
    #[cfg(feature = "tsssp")]
    if _security_package_name == sspi::credssp::sspi_cred_ssp::PKG_NAME {
        let credssp_cred = p_auth_data.cast::<CredSspCred>().as_ref().unwrap();

        return unpack_sec_winnt_auth_identity_ex2_w(credssp_cred.p_spnego_cred);
    }

    let (auth_version, _) = get_auth_data_identity_version_and_flags(p_auth_data);

    if auth_version == SEC_WINNT_AUTH_IDENTITY_VERSION {
        let auth_data = p_auth_data.cast::<SecWinntAuthIdentityExW>();
        if !(*auth_data).package_list.is_null() && (*auth_data).package_list_length > 0 {
            *package_list = Some(String::from_utf16_lossy(from_raw_parts(
                (*auth_data).package_list as *const u16,
                (*auth_data).package_list_length as usize,
            )));
        }
        Ok(CredentialsBuffers::AuthIdentity(AuthIdentityBuffers {
            user: raw_str_into_bytes((*auth_data).user as *const _, (*auth_data).user_length as usize * 2),
            domain: raw_str_into_bytes((*auth_data).domain as *const _, (*auth_data).domain_length as usize * 2),
            password: raw_str_into_bytes(
                (*auth_data).password as *const _,
                (*auth_data).password_length as usize * 2,
            )
            .into(),
        }))
    } else {
        let auth_data = p_auth_data.cast::<SecWinntAuthIdentityW>();
        Ok(CredentialsBuffers::AuthIdentity(AuthIdentityBuffers {
            user: raw_str_into_bytes((*auth_data).user as *const _, (*auth_data).user_length as usize * 2),
            domain: raw_str_into_bytes((*auth_data).domain as *const _, (*auth_data).domain_length as usize * 2),
            password: raw_str_into_bytes(
                (*auth_data).password as *const _,
                (*auth_data).password_length as usize * 2,
            )
            .into(),
        }))
    }
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

    // username length is placed after the first 8 bytes
    let user_len_ptr = (p_auth_data as *const u16).add(4);
    let user_buffer_len = *user_len_ptr as u32;

    // domain length is placed after 16 bytes from the username length
    let domain_len_ptr = user_len_ptr.add(8);
    let domain_buffer_len = *domain_len_ptr as u32;

    // packet credentials length is placed after 16 bytes from the domain length
    let creds_len_ptr = domain_len_ptr.add(8);
    let creds_buffer_len = *creds_len_ptr as u32;

    // header size + buffers size
    64 /* size of the SEC_WINNT_AUTH_IDENTITY_EX2 */ + user_buffer_len + domain_buffer_len + creds_buffer_len
}

#[cfg(target_os = "windows")]
pub unsafe fn unpack_sec_winnt_auth_identity_ex2_a(p_auth_data: *const c_void) -> Result<CredentialsBuffers> {
    use std::ptr::null_mut;

    use sspi::Secret;
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

    // the first call is just to query the username, domain, and password length
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

    // remove null
    username.pop();
    auth_identity_buffers.user = username;

    if domain_len == 0 {
        // sometimes username can be formatted as `DOMAIN\username`
        if let Some(index) = auth_identity_buffers.user.iter().position(|b| *b == b'\\') {
            auth_identity_buffers.domain = auth_identity_buffers.user[0..index].to_vec();
            auth_identity_buffers.user = auth_identity_buffers.user[(index + 1)..].to_vec();
        }
    } else {
        // remove null
        domain.pop();
        auth_identity_buffers.domain = domain;
    }

    // remove null
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

#[cfg(target_os = "windows")]
pub unsafe fn unpack_sec_winnt_auth_identity_ex2_w(p_auth_data: *const c_void) -> Result<CredentialsBuffers> {
    use std::ptr::null_mut;

    use sspi::Secret;
    use winapi::um::wincred::{CredUnmarshalCredentialW, CRED_MARSHAL_TYPE, CertCredential, CERT_CREDENTIAL_INFO};
    use windows_sys::Win32::Security::Credentials::{CredUnPackAuthenticationBufferW, CRED_PACK_PROTECTED_CREDENTIALS};

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

    // the first call is just to query the username, domain, and password length
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

    // only marshaled smart card creds starts with '@' char
    if username[0] == b'@' {
        let mut cred_type = 0;
        let mut credential = null_mut();

        let result = CredUnmarshalCredentialW(username.as_ptr() as *const _, &mut cred_type, &mut credential);

        if result == 1 {
            if cred_type == CertCredential {
                let cert_credential = credential.cast::<CERT_CREDENTIAL_INFO>();

                let certificate = sspi::cert_utils::extract_raw_certificate_by_thumbprint(&(*cert_credential).rgbHashOfCert)?;

                // test credentials
                // todo: use real reader name
                let reader_name = "Microsoft Virtual Smart Card 0".encode_utf16().flat_map(|v| v.to_le_bytes()).collect();
                // todo: extract username from the certificate
                let username = "pw13@example.com".encode_utf16().flat_map(|v| v.to_le_bytes()).collect();

                // remove null
                let new_len = password.as_ref().len() - 2;
                password.as_mut().truncate(new_len);

                let creds = CredentialsBuffers::SmartCard(SmartCardIdentityBuffers {
                    certificate,
                    reader_name,
                    pin: password,
                    username,
                });
                warn!(creds = ?creds);

                return Ok(creds);
            } else {
                return Err(Error::new(ErrorKind::NoCredentials, "Unmarshalled credentials is not CRED_MARSHAL_TYPE::CertCredential"));
            }
        } else {
            return Err(Error::new(ErrorKind::NoCredentials, "Cannot unmarshal smart card credentials"));
        }
    }

    let mut auth_identity_buffers = AuthIdentityBuffers::default();

    // remove null
    username.truncate(username.len() - 2);
    auth_identity_buffers.user = username;

    if domain_len == 0 {
        // sometimes username can be formatted as `DOMAIN\username`
        if let Some(index) = auth_identity_buffers.user.iter().position(|b| *b == b'\\') {
            auth_identity_buffers.domain = auth_identity_buffers.user[0..index].to_vec();
            auth_identity_buffers.user = auth_identity_buffers.user[(index + 2)..].to_vec();
        }
    } else {
        // remove null
        domain.truncate(domain.len() - 2);
        auth_identity_buffers.domain = domain;
    }

    // remove null
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

        let user = c_w_str_to_string(psz_user_name);
        let domain = c_w_str_to_string(psz_domain_name);
        let password = c_w_str_to_string(psz_packed_credentials_string);

        let auth_identity = SecWinntAuthIdentityW {
            user: psz_user_name,
            user_length: user.len().try_into().unwrap(),
            domain: psz_domain_name,
            domain_length: domain.len().try_into().unwrap(),
            password: psz_packed_credentials_string,
            password_length: password.len().try_into().unwrap(),
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

        let _auth_data: Box<SecWinntAuthIdentityW> = Box::from_raw(auth_data as *mut _);

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

    use super::{SecWinntAuthIdentityW, SspiEncodeStringsAsAuthIdentity};
    use crate::sec_winnt_auth_identity::SspiFreeAuthIdentity;

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

            assert_eq!(status, 0);
            assert!(!identity.is_null());

            let identity = identity.cast::<SecWinntAuthIdentityW>();

            assert_eq!(
                "",
                String::from_utf16_lossy(from_raw_parts((*identity).user, (*identity).user_length as usize))
            );
            assert_eq!(
                "",
                String::from_utf16_lossy(from_raw_parts(
                    (*identity).password,
                    (*identity).password_length as usize
                ))
            );
            assert_eq!(
                "",
                String::from_utf16_lossy(from_raw_parts((*identity).domain, (*identity).domain_length as usize))
            );
        }
    }

    #[test]
    fn sspi_free_auth_identity() {
        let (username, password, domain) = get_user_credentials();
        let mut identity = null_mut::<c_void>();

        unsafe {
            SspiEncodeStringsAsAuthIdentity(username.as_ptr(), domain.as_ptr(), password.as_ptr(), &mut identity);

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
