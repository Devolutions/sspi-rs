use std::mem::size_of;
use std::slice::from_raw_parts;

use libc::c_void;
use sspi::{Error, ErrorKind, Result};

use super::sspi_data_types::{SecChar, SecWChar};
use super::utils::hostname;

#[derive(Debug)]
pub struct KdcProxySettings {
    pub proxy_server: String,
    #[allow(dead_code)]
    pub client_tls_cred: Option<String>,
}

#[derive(Default, Debug)]
pub struct CredentialsAttributes {
    pub package_list: Option<String>,
    pub kdc_url: Option<String>,
    pub kdc_proxy_settings: Option<KdcProxySettings>,
    pub workstation: Option<String>,
}

impl CredentialsAttributes {
    pub fn new() -> Self {
        CredentialsAttributes::default()
    }

    pub fn new_with_package_list(package_list: Option<String>) -> Self {
        CredentialsAttributes {
            package_list,
            ..Default::default()
        }
    }

    pub fn kdc_url(&self) -> Option<String> {
        if let Some(kdc_url) = &self.kdc_url {
            Some(kdc_url.to_string())
        } else {
            self.kdc_proxy_settings
                .as_ref()
                .map(|kdc_proxy_settings| kdc_proxy_settings.proxy_server.to_string())
        }
    }

    pub fn hostname(&self) -> Result<String> {
        if let Some(hostname) = self.workstation.as_ref() {
            Ok(hostname.clone())
        } else {
            hostname()
        }
    }
}

#[repr(C)]
pub struct SecPkgCredentialsKdcProxySettingsW {
    pub version: u32,
    pub flags: u32,
    pub proxy_server_offset: u16,
    pub proxy_server_length: u16,
    pub client_tls_cred_offset: u16,
    pub client_tls_cred_length: u16,
}

/// Extracts [KdcProxySettings].
///
/// # Safety:
///
/// * The pointer must not be null.
/// * The pointer value must be [SecPkgCredentialsKdcProxySettingsW].
/// * The proxy server and client TLS credentials (if any) values must be placed right after the [SecPkgCredentialsKdcProxySettingsW] value.
pub unsafe fn extract_kdc_proxy_settings(p_buffer: *mut c_void) -> Result<KdcProxySettings> {
    if p_buffer.is_null() {
        return Err(Error::new(ErrorKind::InvalidParameter, "p_buffer cannot be null"));
    }

    // SAFETY:
    // * `p_buffer` is not null: checked above;
    // * the user must all other properties of the pointer and the value behind this pointer.
    let kdc_proxy_settings = unsafe {
        p_buffer
            .cast::<SecPkgCredentialsKdcProxySettingsW>()
            .as_ref()
            .expect("p_buffer must not be null")
    };

    let SecPkgCredentialsKdcProxySettingsW {
        proxy_server_offset,
        proxy_server_length,
        client_tls_cred_offset,
        client_tls_cred_length,
        ..
    } = kdc_proxy_settings;

    // SAFETY: `p_buffer` is not null (checked above). `kdc_proxy_settings` was cast from the `p_buffer',
    // so it's not null either.
    let proxy_server = String::from_utf16_lossy(unsafe {
        from_raw_parts(
            p_buffer.add(*proxy_server_offset as usize) as *const u16,
            *proxy_server_length as usize / size_of::<SecWChar>(),
        )
    });

    // SAFETY: `p_buffer` is not null (checked above). `kdc_proxy_settings` was cast from the `p_buffer',
    // so it's not null either.
    let client_tls_cred = unsafe {
        if *client_tls_cred_offset != 0 && *client_tls_cred_length != 0 {
            Some(String::from_utf16_lossy(from_raw_parts(
                p_buffer.add(*client_tls_cred_offset as usize) as *const u16,
                *client_tls_cred_length as usize,
            )))
        } else {
            None
        }
    };

    Ok(KdcProxySettings {
        proxy_server,
        client_tls_cred,
    })
}

#[repr(C)]
pub struct SecPkgCredentialsKdcUrlA {
    pub kdc_url: *mut SecChar,
}

#[repr(C)]
pub struct SecPkgCredentialsKdcUrlW {
    pub kdc_url: *mut SecWChar,
}
