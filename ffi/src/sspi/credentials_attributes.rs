use std::mem::size_of;
use std::slice::from_raw_parts;

use libc::c_void;

use super::sspi_data_types::{SecChar, SecWChar};

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

pub unsafe fn extract_kdc_proxy_settings(p_buffer: *mut c_void) -> KdcProxySettings {
    let kdc_proxy_settings = p_buffer.cast::<SecPkgCredentialsKdcProxySettingsW>();

    let proxy_server = String::from_utf16_lossy(from_raw_parts(
        p_buffer.add((*kdc_proxy_settings).proxy_server_offset as usize) as *const u16,
        (*kdc_proxy_settings).proxy_server_length as usize / size_of::<SecWChar>(),
    ));

    let client_tls_cred =
        if (*kdc_proxy_settings).client_tls_cred_offset != 0 && (*kdc_proxy_settings).client_tls_cred_length != 0 {
            Some(String::from_utf16_lossy(from_raw_parts(
                p_buffer.add((*kdc_proxy_settings).client_tls_cred_offset as usize) as *const u16,
                (*kdc_proxy_settings).client_tls_cred_length as usize,
            )))
        } else {
            None
        };

    KdcProxySettings {
        proxy_server,
        client_tls_cred,
    }
}

#[repr(C)]
pub struct SecPkgCredentialsKdcUrlA {
    pub kdc_url: *mut SecChar,
}

#[repr(C)]
pub struct SecPkgCredentialsKdcUrlW {
    pub kdc_url: *mut SecWChar,
}
