use std::ffi::CStr;
use std::mem::size_of;
use std::slice::from_raw_parts;

use libc::{c_ulong, c_ulonglong, c_void};
use num_traits::{FromPrimitive, ToPrimitive};
use sspi::builders::{ChangePasswordBuilder, EmptyInitializeSecurityContext};
use sspi::internal::credssp::SspiContext;
use sspi::internal::SspiImpl;
use sspi::kerberos::config::KerberosConfig;
use sspi::kerberos::network_client::reqwest_network_client::ReqwestNetworkClient;
use sspi::{
    kerberos, negotiate, ntlm, pku2u, AuthIdentityBuffers, ClientRequestFlags, DataRepresentation, Error, ErrorKind,
    Kerberos, Negotiate, NegotiateConfig, Ntlm, Pku2u, Pku2uConfig, Result, Sspi,
};
#[cfg(windows)]
use symbol_rename_macro::rename_symbol;

use crate::credentials_attributes::{
    CredentialsAttributes, KdcProxySettings, SecPkgCredentialsKdcProxySettingsA, SecPkgCredentialsKdcProxySettingsW,
};
use crate::sec_buffer::{copy_to_c_sec_buffer, p_sec_buffers_to_security_buffers, PSecBuffer, PSecBufferDesc};
use crate::sec_pkg_info::{SecNegoInfoA, SecNegoInfoW, SecPkgInfoA, SecPkgInfoW};
use crate::sec_winnt_auth_identity::{SecWinntAuthIdentityA, SecWinntAuthIdentityW};
use crate::sspi_data_types::{
    LpStr, LpcWStr, PSecurityString, PTimeStamp, SecChar, SecGetKeyFn, SecPkgContextSizes, SecWChar, SecurityStatus,
};
use crate::utils::{
    c_w_str_to_string, into_raw_ptr, raw_str_into_bytes, raw_w_str_to_bytes, transform_credentials_handle,
};

pub const SECPKG_NEGOTIATION_COMPLETE: u32 = 0;
pub const SECPKG_NEGOTIATION_OPTIMISTIC: u32 = 1;
pub const SECPKG_NEGOTIATION_IN_PROGRESS: u32 = 2;

pub const SECPKG_ATTR_SIZES: u32 = 0;
pub const SECPKG_ATTR_NEGOTIATION_INFO: u32 = 12;

const SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS: c_ulong = 3;

#[repr(C)]
pub struct SecHandle {
    pub dw_lower: c_ulonglong,
    pub dw_upper: c_ulonglong,
}

pub type PCredHandle = *mut SecHandle;
pub type PCtxtHandle = *mut SecHandle;

pub struct CredentialsHandle {
    pub credentials: AuthIdentityBuffers,
    pub security_package_name: String,
    pub attributes: CredentialsAttributes,
}

pub(crate) unsafe fn p_ctxt_handle_to_sspi_context(
    context: &mut PCtxtHandle,
    security_package_name: Option<&str>,
    attributes: &CredentialsAttributes,
) -> Result<*mut SspiContext> {
    if context.is_null() {
        *context = into_raw_ptr(SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        });
    }

    if (*(*context)).dw_lower == 0 {
        if security_package_name.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                "Security package name is not provided".into(),
            ));
        }
        let name = security_package_name.expect("security package name must be provided");

        let sspi_context = match name {
            negotiate::PKG_NAME => {
                if let Some(settings) = &attributes.kdc_proxy_settings {
                    SspiContext::Negotiate(Negotiate::new(NegotiateConfig::new(Box::new(
                        KerberosConfig::from_kdc_url(&settings.proxy_server, Box::new(ReqwestNetworkClient::new())),
                    )))?)
                } else {
                    SspiContext::Negotiate(Negotiate::new(NegotiateConfig::default())?)
                }
            }
            pku2u::PKG_NAME => {
                #[cfg(not(target_os = "windows"))]
                return Err(Error::new(
                    ErrorKind::InvalidParameter,
                    "PKU2U is not supported on non-Windows OS yet".into(),
                ));
                #[cfg(target_os = "windows")]
                SspiContext::Pku2u(Pku2u::new_client_from_config(Pku2uConfig::default_client_config()?)?)
            }
            kerberos::PKG_NAME => {
                if let Some(settings) = &attributes.kdc_proxy_settings {
                    SspiContext::Kerberos(Kerberos::new_client_from_config(KerberosConfig::from_kdc_url(
                        &settings.proxy_server,
                        Box::new(ReqwestNetworkClient::new()),
                    ))?)
                } else {
                    SspiContext::Kerberos(Kerberos::new_client_from_config(KerberosConfig::from_env())?)
                }
            }
            ntlm::PKG_NAME => SspiContext::Ntlm(Ntlm::new()),
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidParameter,
                    format!("security package name `{}` is not supported", name),
                ))
            }
        };

        (*(*context)).dw_lower = into_raw_ptr(sspi_context) as c_ulonglong;
        (*(*context)).dw_upper = into_raw_ptr(name.to_owned()) as c_ulonglong;
    }
    Ok((*(*context)).dw_lower as *mut SspiContext)
}

#[cfg_attr(windows, rename_symbol(to = "Rust_AcquireCredentialsHandleA"))]
#[no_mangle]
pub unsafe extern "system" fn AcquireCredentialsHandleA(
    _psz_principal: LpStr,
    psz_package: LpStr,
    _f_aredential_use: c_ulong,
    _pv_logon_id: *const c_void,
    p_auth_data: *const c_void,
    _p_get_key_fn: SecGetKeyFn,
    _pv_get_key_argument: *const c_void,
    ph_credential: PCredHandle,
    _pts_expiry: PTimeStamp,
) -> SecurityStatus {
    catch_panic!(
        check_null!(psz_package);
        check_null!(p_auth_data);
        check_null!(ph_credential);

        let security_package_name =
            try_execute!(CStr::from_ptr(psz_package).to_str(), ErrorKind::InvalidParameter).to_owned();

        let auth_data = p_auth_data.cast::<SecWinntAuthIdentityA>();

        let credentials = AuthIdentityBuffers {
            user: raw_str_into_bytes((*auth_data).user, (*auth_data).user_length as usize * 2),
            domain: raw_str_into_bytes((*auth_data).domain, (*auth_data).domain_length as usize * 2),
            password: raw_str_into_bytes((*auth_data).password, (*auth_data).password_length as usize * 2),
        };

        (*ph_credential).dw_lower = into_raw_ptr(CredentialsHandle {
            credentials,
            security_package_name,
            attributes: CredentialsAttributes::default(),
        }) as c_ulonglong;

        0
    )
}
pub type AcquireCredentialsHandleFnA = unsafe extern "system" fn(
    LpStr,
    LpStr,
    c_ulong,
    *const c_void,
    *const c_void,
    SecGetKeyFn,
    *const c_void,
    PCredHandle,
    PTimeStamp,
) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_AcquireCredentialsHandleW"))]
#[no_mangle]
pub unsafe extern "system" fn AcquireCredentialsHandleW(
    _psz_principal: LpcWStr,
    psz_package: LpcWStr,
    _f_credential_use: c_ulong,
    _pv_logon_id: *const c_void,
    p_auth_data: *const c_void,
    _p_get_key_fn: SecGetKeyFn,
    _pv_get_key_argument: *const c_void,
    ph_credential: PCredHandle,
    _pts_expiry: PTimeStamp,
) -> SecurityStatus {
    catch_panic!(
        check_null!(psz_package);
        check_null!(p_auth_data);
        check_null!(ph_credential);

        let security_package_name = c_w_str_to_string(psz_package);

        let auth_data = p_auth_data.cast::<SecWinntAuthIdentityW>();

        let credentials = AuthIdentityBuffers {
            user: raw_w_str_to_bytes((*auth_data).user, (*auth_data).user_length as usize),
            domain: raw_w_str_to_bytes((*auth_data).domain, (*auth_data).domain_length as usize),
            password: raw_w_str_to_bytes((*auth_data).password, (*auth_data).password_length as usize),
        };

        (*ph_credential).dw_lower = into_raw_ptr(CredentialsHandle {
            credentials,
            security_package_name,
            attributes: CredentialsAttributes::default(),
        }) as c_ulonglong;

        0
    )
}
pub type AcquireCredentialsHandleFnW = unsafe extern "system" fn(
    LpcWStr,
    LpcWStr,
    c_ulong,
    *const c_void,
    *const c_void,
    SecGetKeyFn,
    *const c_void,
    PCredHandle,
    PTimeStamp,
) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_QueryCredentialsAttributesA"))]
#[no_mangle]
pub extern "system" fn QueryCredentialsAttributesA(
    _ph_credential: PCredHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryCredentialsAttributesFnA = extern "system" fn(PCredHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_QueryCredentialsAttributesW"))]
#[no_mangle]
pub extern "system" fn QueryCredentialsAttributesW(
    _ph_credential: PCredHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryCredentialsAttributesFnW = extern "system" fn(PCredHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
#[cfg_attr(windows, rename_symbol(to = "Rust_InitializeSecurityContextA"))]
#[no_mangle]
pub unsafe extern "system" fn InitializeSecurityContextA(
    ph_credential: PCredHandle,
    mut ph_context: PCtxtHandle,
    p_target_name: *const SecChar,
    f_context_req: c_ulong,
    _reserved1: c_ulong,
    target_data_rep: c_ulong,
    p_input: PSecBufferDesc,
    _reserved2: c_ulong,
    ph_new_context: PCtxtHandle,
    p_output: PSecBufferDesc,
    pf_context_attr: *mut c_ulong,
    _pts_expiry: PTimeStamp,
) -> SecurityStatus {
    catch_panic!(
        // ph_context can be null on the first call
        // p_input can be null on the first call
        check_null!(ph_new_context);
        check_null!(ph_credential);
        check_null!(p_output);
        check_null!(pf_context_attr);

        let service_principal = if p_target_name.is_null() {
            ""
        } else {
            try_execute!(CStr::from_ptr(p_target_name).to_str(), ErrorKind::InvalidParameter)
        };

        let credentials_handle = (*ph_credential).dw_lower as *mut CredentialsHandle;

        let (auth_data, security_package_name, attributes) = match transform_credentials_handle(credentials_handle) {
            Some(creds_handle) => creds_handle,
            None => return ErrorKind::InvalidHandle.to_u32().unwrap(),
        };

        let sspi_context_ptr = try_execute!(p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            Some(security_package_name),
            attributes
        ));
        let sspi_context = sspi_context_ptr
            .as_mut()
            .expect("security context pointer cannot be null");

        let mut input_tokens = if p_input.is_null() {
            Vec::new()
        } else {
            p_sec_buffers_to_security_buffers(from_raw_parts((*p_input).p_buffers, (*p_input).c_buffers as usize))
        };

        let len = (*p_output).c_buffers as usize;
        let raw_buffers = from_raw_parts((*p_output).p_buffers, len);
        let mut output_tokens = p_sec_buffers_to_security_buffers(raw_buffers);
        output_tokens.iter_mut().for_each(|s| s.buffer.clear());

        let mut auth_data = Some(auth_data);
        let mut builder = EmptyInitializeSecurityContext::<<SspiContext as SspiImpl>::CredentialsHandle>::new()
            .with_credentials_handle(&mut auth_data)
            .with_context_requirements(ClientRequestFlags::from_bits(f_context_req.try_into().unwrap()).unwrap())
            .with_target_data_representation(DataRepresentation::from_u32(target_data_rep.try_into().unwrap()).unwrap())
            .with_target_name(service_principal)
            .with_input(&mut input_tokens)
            .with_output(&mut output_tokens);
        let result_status = sspi_context.initialize_security_context_impl(&mut builder);

        copy_to_c_sec_buffer((*p_output).p_buffers, &output_tokens);

        (*ph_new_context).dw_lower = sspi_context_ptr as c_ulonglong;
        (*ph_new_context).dw_upper = into_raw_ptr(security_package_name.to_owned()) as c_ulonglong;

        *pf_context_attr = f_context_req;

        result_status.map_or_else(
            |err| err.error_type.to_u32().unwrap(),
            |result| result.status.to_u32().unwrap(),
        )
    )
}
pub type InitializeSecurityContextFnA = unsafe extern "system" fn(
    PCredHandle,
    PCtxtHandle,
    *const SecChar,
    c_ulong,
    c_ulong,
    c_ulong,
    PSecBufferDesc,
    c_ulong,
    PCtxtHandle,
    PSecBufferDesc,
    *mut c_ulong,
    PTimeStamp,
) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
#[cfg_attr(windows, rename_symbol(to = "Rust_InitializeSecurityContextW"))]
#[no_mangle]
pub unsafe extern "system" fn InitializeSecurityContextW(
    ph_credential: PCredHandle,
    mut ph_context: PCtxtHandle,
    p_target_name: *const SecWChar,
    f_context_req: c_ulong,
    _reserved1: c_ulong,
    target_data_rep: c_ulong,
    p_input: PSecBufferDesc,
    _reserved2: c_ulong,
    ph_new_context: PCtxtHandle,
    p_output: PSecBufferDesc,
    pf_context_attr: *mut c_ulong,
    _pts_expiry: PTimeStamp,
) -> SecurityStatus {
    catch_panic!(
        // ph_context can be null on the first call
        // p_input can be null on the first call
        check_null!(ph_new_context);
        check_null!(ph_credential);
        check_null!(p_output);
        check_null!(pf_context_attr);

        let service_principal = if p_target_name.is_null() {
            String::new()
        } else {
            c_w_str_to_string(p_target_name)
        };

        let credentials_handle = (*ph_credential).dw_lower as *mut CredentialsHandle;

        let (auth_data, security_package_name, attributes) = match transform_credentials_handle(credentials_handle) {
            Some(creds_handle) => creds_handle,
            None => return ErrorKind::InvalidHandle.to_u32().unwrap(),
        };

        let sspi_context_ptr = try_execute!(p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            Some(security_package_name),
            attributes,
        ));
        let sspi_context = sspi_context_ptr
            .as_mut()
            .expect("security context pointer cannot be null");

        let mut input_tokens = if p_input.is_null() {
            Vec::new()
        } else {
            p_sec_buffers_to_security_buffers(from_raw_parts((*p_input).p_buffers, (*p_input).c_buffers as usize))
        };

        let raw_buffers = from_raw_parts((*p_output).p_buffers, (*p_output).c_buffers as usize);
        let mut output_tokens = p_sec_buffers_to_security_buffers(raw_buffers);
        output_tokens.iter_mut().for_each(|s| s.buffer.clear());

        let mut auth_data = Some(auth_data);
        let mut builder = EmptyInitializeSecurityContext::<<SspiContext as SspiImpl>::CredentialsHandle>::new()
            .with_credentials_handle(&mut auth_data)
            .with_context_requirements(ClientRequestFlags::from_bits(f_context_req.try_into().unwrap()).unwrap())
            .with_target_data_representation(DataRepresentation::from_u32(target_data_rep.try_into().unwrap()).unwrap())
            .with_target_name(&service_principal)
            .with_input(&mut input_tokens)
            .with_output(&mut output_tokens);
        let result_status = sspi_context.initialize_security_context_impl(&mut builder);

        copy_to_c_sec_buffer((*p_output).p_buffers, &output_tokens);

        *pf_context_attr = f_context_req;

        (*ph_new_context).dw_lower = sspi_context_ptr as c_ulonglong;
        (*ph_new_context).dw_upper = into_raw_ptr(security_package_name.to_owned()) as c_ulonglong;

        result_status.map_or_else(
            |err| err.error_type.to_u32().unwrap(),
            |result| result.status.to_u32().unwrap(),
        )
    )
}
pub type InitializeSecurityContextFnW = unsafe extern "system" fn(
    PCredHandle,
    PCtxtHandle,
    *const SecWChar,
    c_ulong,
    c_ulong,
    c_ulong,
    PSecBufferDesc,
    c_ulong,
    PCtxtHandle,
    PSecBufferDesc,
    *mut c_ulong,
    PTimeStamp,
) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryContextAttributesA"))]
#[no_mangle]
pub unsafe extern "system" fn QueryContextAttributesA(
    mut ph_context: PCtxtHandle,
    ul_attribute: c_ulong,
    p_buffer: *mut c_void,
) -> SecurityStatus {
    catch_panic!(
        let sspi_context = try_execute!(p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            None,
            &CredentialsAttributes::default()
        ))
        .as_mut()
        .expect("security context pointer cannot be null");

        check_null!(p_buffer);

        match ul_attribute.try_into().unwrap() {
            SECPKG_ATTR_SIZES => {
                let sizes = p_buffer.cast::<SecPkgContextSizes>();

                let pkg_sizes = try_execute!(sspi_context.query_context_sizes());

                (*sizes).cb_max_token = pkg_sizes.max_token;
                (*sizes).cb_max_signature = pkg_sizes.max_signature;
                (*sizes).cb_block_size = pkg_sizes.block;
                (*sizes).cb_security_trailer = pkg_sizes.security_trailer;

                0
            }
            SECPKG_ATTR_NEGOTIATION_INFO => {
                let nego_info = p_buffer.cast::<SecNegoInfoA>();

                (*nego_info).nego_state = SECPKG_NEGOTIATION_COMPLETE;
                (*nego_info).package_info = into_raw_ptr(SecPkgInfoA::from(try_execute!(
                    sspi_context.query_context_package_info()
                )));

                0
            }
            _ => ErrorKind::UnsupportedFunction.to_u32().unwrap(),
        }
    )
}
pub type QueryContextAttributesFnA = unsafe extern "system" fn(PCtxtHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryContextAttributesW"))]
#[no_mangle]
pub unsafe extern "system" fn QueryContextAttributesW(
    mut ph_context: PCtxtHandle,
    ul_attribute: c_ulong,
    p_buffer: *mut c_void,
) -> SecurityStatus {
    catch_panic!(
        let sspi_context = try_execute!(p_ctxt_handle_to_sspi_context(
            &mut ph_context,
            None,
            &CredentialsAttributes::default()
        ))
        .as_mut()
        .expect("security context pointer cannot be null");

        check_null!(p_buffer);

        match ul_attribute.try_into().unwrap() {
            SECPKG_ATTR_SIZES => {
                let sizes = p_buffer.cast::<SecPkgContextSizes>();

                let pkg_sizes = try_execute!(sspi_context.query_context_sizes());

                (*sizes).cb_max_token = pkg_sizes.max_token;
                (*sizes).cb_max_signature = pkg_sizes.max_signature;
                (*sizes).cb_block_size = pkg_sizes.block;
                (*sizes).cb_security_trailer = pkg_sizes.security_trailer;

                0
            }
            SECPKG_ATTR_NEGOTIATION_INFO => {
                let nego_info = p_buffer.cast::<SecNegoInfoW>();

                (*nego_info).nego_state = SECPKG_NEGOTIATION_COMPLETE.try_into().unwrap();
                (*nego_info).package_info = into_raw_ptr(SecPkgInfoW::from(try_execute!(
                    sspi_context.query_context_package_info()
                )));

                0
            }
            _ => ErrorKind::UnsupportedFunction.to_u32().unwrap(),
        }
    )
}
pub type QueryContextAttributesFnW = unsafe extern "system" fn(PCtxtHandle, c_ulong, *mut c_void) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_ImportSecurityContextA"))]
#[no_mangle]
pub extern "system" fn ImportSecurityContextA(
    _psz_package: PSecurityString,
    _p_packed_context: PSecBuffer,
    _token: *mut c_void,
    _ph_context: PCtxtHandle,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type ImportSecurityContextFnA =
    extern "system" fn(PSecurityString, PSecBuffer, *mut c_void, PCtxtHandle) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_ImportSecurityContextW"))]
#[no_mangle]
pub extern "system" fn ImportSecurityContextW(
    _psz_package: PSecurityString,
    _p_packed_context: PSecBuffer,
    _token: *mut c_void,
    _ph_context: PCtxtHandle,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type ImportSecurityContextFnW =
    extern "system" fn(PSecurityString, PSecBuffer, *mut c_void, PCtxtHandle) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_AddCredentialsA"))]
#[no_mangle]
pub extern "system" fn AddCredentialsA(
    _ph_credential: PCredHandle,
    _s1: *mut SecChar,
    _s2: *mut SecChar,
    _n1: c_ulong,
    _p1: *mut c_void,
    _f: SecGetKeyFn,
    _p2: *mut c_void,
    _t: PTimeStamp,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type AddCredentialsFnA = extern "system" fn(
    PCredHandle,
    *mut SecChar,
    *mut SecChar,
    c_ulong,
    *mut c_void,
    SecGetKeyFn,
    *mut c_void,
    PTimeStamp,
) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_AddCredentialsW"))]
#[no_mangle]
pub extern "system" fn AddCredentialsW(
    _ph_credential: PCredHandle,
    _s1: *mut SecWChar,
    _s2: *mut SecWChar,
    _n1: c_ulong,
    _p1: *mut c_void,
    _f: SecGetKeyFn,
    _p2: *mut c_void,
    _t: PTimeStamp,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type AddCredentialsFnW = extern "system" fn(
    PCredHandle,
    *mut SecWChar,
    *mut SecWChar,
    c_ulong,
    *mut c_void,
    SecGetKeyFn,
    *mut c_void,
    PTimeStamp,
) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SetContextAttributesA"))]
#[no_mangle]
pub extern "system" fn SetContextAttributesA(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type SetContextAttributesFnA = extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SetContextAttributesW"))]
#[no_mangle]
pub extern "system" fn SetContextAttributesW(
    _ph_credential: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type SetContextAttributesFnW = extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SetCredentialsAttributesA"))]
#[no_mangle]
pub unsafe extern "system" fn SetCredentialsAttributesA(
    ph_credential: PCtxtHandle,
    ul_attribute: c_ulong,
    p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    catch_panic!(if ul_attribute == SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS {
        check_null!(ph_credential);
        check_null!(p_buffer);

        let mut credentials_handle = ((*ph_credential).dw_lower as *mut CredentialsHandle).as_mut().unwrap();

        let kdc_proxy_settings = p_buffer.cast::<SecPkgCredentialsKdcProxySettingsA>();

        let proxy_server = String::from_utf8_unchecked(
            from_raw_parts(
                p_buffer.add((*kdc_proxy_settings).proxy_server_offset as usize) as *const u8,
                (*kdc_proxy_settings).proxy_server_length as usize,
            )
            .to_vec(),
        );

        let client_tls_cred =
            if (*kdc_proxy_settings).client_tls_cred_offset != 0 && (*kdc_proxy_settings).client_tls_cred_length != 0 {
                Some(String::from_utf8_unchecked(
                    from_raw_parts(
                        p_buffer.add((*kdc_proxy_settings).client_tls_cred_offset as usize) as *const u8,
                        (*kdc_proxy_settings).client_tls_cred_length as usize,
                    )
                    .to_vec(),
                ))
            } else {
                None
            };

        credentials_handle.attributes.kdc_proxy_settings = Some(KdcProxySettings {
            proxy_server,
            client_tls_cred,
        });

        0
    } else {
        ErrorKind::UnsupportedFunction.to_u32().unwrap()
    })
}
pub type SetCredentialsAttributesFnA =
    unsafe extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SetCredentialsAttributesW"))]
#[no_mangle]
pub unsafe extern "system" fn SetCredentialsAttributesW(
    ph_credential: PCtxtHandle,
    ul_attribute: c_ulong,
    p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    catch_panic!(if ul_attribute == SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS {
        check_null!(ph_credential);
        check_null!(p_buffer);

        let mut credentials_handle = ((*ph_credential).dw_lower as *mut CredentialsHandle).as_mut().unwrap();

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

        credentials_handle.attributes.kdc_proxy_settings = Some(KdcProxySettings {
            proxy_server,
            client_tls_cred,
        });

        0
    } else {
        ErrorKind::UnsupportedFunction.to_u32().unwrap()
    })
}
pub type SetCredentialsAttributesFnW =
    unsafe extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_ChangeAccountPasswordA"))]
#[no_mangle]
pub unsafe extern "system" fn ChangeAccountPasswordA(
    psz_package_name: *mut SecChar,
    psz_domain_name: *mut SecChar,
    psz_account_name: *mut SecChar,
    psz_old_password: *mut SecChar,
    psz_new_password: *mut SecChar,
    _b_impersonating: bool,
    _dw_reserved: c_ulong,
    p_output: PSecBufferDesc,
) -> SecurityStatus {
    catch_panic!(
        check_null!(psz_package_name);
        check_null!(psz_domain_name);
        check_null!(psz_account_name);
        check_null!(psz_old_password);
        check_null!(psz_new_password);
        check_null!(p_output);

        let security_package_name = try_execute!(CStr::from_ptr(psz_package_name).to_str(), ErrorKind::InvalidParameter);

        let domain = try_execute!(CStr::from_ptr(psz_domain_name).to_str(), ErrorKind::InvalidParameter);
        let username = try_execute!(CStr::from_ptr(psz_account_name).to_str(), ErrorKind::InvalidParameter);
        let password = try_execute!(CStr::from_ptr(psz_old_password).to_str(), ErrorKind::InvalidParameter);
        let new_password = try_execute!(CStr::from_ptr(psz_new_password).to_str(), ErrorKind::InvalidParameter);

        let len = (*p_output).c_buffers as usize;
        let mut output_tokens = p_sec_buffers_to_security_buffers(from_raw_parts((*p_output).p_buffers, len));
        output_tokens.iter_mut().for_each(|s| s.buffer.clear());

        let change_password = ChangePasswordBuilder::new()
            .with_domain_name(domain)
            .with_account_name(username)
            .with_old_password(password)
            .with_new_password(new_password)
            .with_output(&mut output_tokens)
            .build()
            .expect("change password builder should never fail");

        let mut sspi_context = match security_package_name {
            negotiate::PKG_NAME => SspiContext::Negotiate(try_execute!(Negotiate::new(NegotiateConfig::default()))),
            kerberos::PKG_NAME => SspiContext::Kerberos(try_execute!(Kerberos::new_client_from_config(
                KerberosConfig::from_env()
            ))),
            ntlm::PKG_NAME => SspiContext::Ntlm(Ntlm::new()),
            _ => {
                return ErrorKind::InvalidParameter.to_u32().unwrap();
            }
        };

        let result_status = sspi_context.change_password(change_password);

        copy_to_c_sec_buffer((*p_output).p_buffers, &output_tokens);

        result_status.map_or_else(|err| err.error_type.to_u32().unwrap(), |_| 0)
    )
}
pub type ChangeAccountPasswordFnA = unsafe extern "system" fn(
    *mut SecChar,
    *mut SecChar,
    *mut SecChar,
    *mut SecChar,
    *mut SecChar,
    bool,
    c_ulong,
    PSecBufferDesc,
) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_ChangeAccountPasswordW"))]
#[no_mangle]
pub unsafe extern "system" fn ChangeAccountPasswordW(
    psz_package_name: *mut SecWChar,
    psz_domain_name: *mut SecWChar,
    psz_account_name: *mut SecWChar,
    psz_old_password: *mut SecWChar,
    psz_new_password: *mut SecWChar,
    b_impersonating: bool,
    dw_reserved: c_ulong,
    p_output: PSecBufferDesc,
) -> SecurityStatus {
    catch_panic!(
        check_null!(psz_package_name);
        check_null!(psz_domain_name);
        check_null!(psz_account_name);
        check_null!(psz_old_password);
        check_null!(psz_new_password);
        check_null!(p_output);

        let security_package_name = c_w_str_to_string(psz_package_name);

        let domain = c_w_str_to_string(psz_domain_name);
        let username = c_w_str_to_string(psz_account_name);
        let password = c_w_str_to_string(psz_old_password);
        let new_password = c_w_str_to_string(psz_new_password);

        ChangeAccountPasswordA(
            security_package_name.as_ptr() as *mut _,
            domain.as_ptr() as *mut _,
            username.as_ptr() as *mut _,
            password.as_ptr() as *mut _,
            new_password.as_ptr() as *mut _,
            b_impersonating,
            dw_reserved,
            p_output,
        )
    )
}
pub type ChangeAccountPasswordFnW = unsafe extern "system" fn(
    *mut SecWChar,
    *mut SecWChar,
    *mut SecWChar,
    *mut SecWChar,
    *mut SecWChar,
    bool,
    c_ulong,
    PSecBufferDesc,
) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_QueryContextAttributesExA"))]
#[no_mangle]
pub extern "system" fn QueryContextAttributesExA(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryContextAttributesExFnA = extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_QueryContextAttributesExW"))]
#[no_mangle]
pub extern "system" fn QueryContextAttributesExW(
    _ph_context: PCtxtHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _cb_buffer: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryContextAttributesExFnW = extern "system" fn(PCtxtHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_QueryCredentialsAttributesExA"))]
#[no_mangle]
pub extern "system" fn QueryCredentialsAttributesExA(
    _ph_credential: PCredHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _c_buffers: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryCredentialsAttributesExFnA =
    extern "system" fn(PCredHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_QueryCredentialsAttributesExW"))]
#[no_mangle]
pub extern "system" fn QueryCredentialsAttributesExW(
    _ph_aredential: PCredHandle,
    _ul_attribute: c_ulong,
    _p_buffer: *mut c_void,
    _c_buffers: c_ulong,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
pub type QueryCredentialsAttributesExFnW =
    extern "system" fn(PCredHandle, c_ulong, *mut c_void, c_ulong) -> SecurityStatus;
