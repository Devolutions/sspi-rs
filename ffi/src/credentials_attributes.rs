use libc::{c_uint, c_ulong, c_ushort};

pub struct KdcProxySettings {
    pub proxy_server: String,
    #[allow(dead_code)]
    pub client_tls_cred: Option<String>,
}

#[derive(Default)]
pub struct CredentialsAttributes {
    pub kdc_proxy_settings: Option<KdcProxySettings>,
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
