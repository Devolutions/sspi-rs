use libc::{c_uint, c_ulong, c_ushort};

use crate::sspi_data_types::{SecChar, SecWChar};

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
pub struct SecPkgCredentialsKdcProxySettingsA {
    pub version: c_uint,
    pub flags: c_uint,
    pub proxy_server_offset: c_ushort,
    pub proxy_server_length: c_ushort,
    pub client_tls_cred_offset: c_ushort,
    pub client_tls_cred_length: c_ushort,
}

#[repr(C)]
pub struct SecPkgCredentialsKdcProxySettingsW {
    pub version: c_ulong,
    pub flags: c_ulong,
    pub proxy_server_offset: c_ushort,
    pub proxy_server_length: c_ushort,
    pub client_tls_cred_offset: c_ushort,
    pub client_tls_cred_length: c_ushort,
}

#[repr(C)]
pub struct SecPkgCredentialsKdcUrlA {
    pub kdc_url: *mut SecChar,
}

#[repr(C)]
pub struct SecPkgCredentialsKdcUrlW {
    pub kdc_url: *mut SecWChar,
}
