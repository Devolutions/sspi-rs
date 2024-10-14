use std::ffi::CStr;
use std::slice::from_raw_parts;
use std::sync::Mutex;

use libc::{c_ulonglong, c_void};
use num_traits::{FromPrimitive, ToPrimitive};
use sspi::builders::ChangePasswordBuilder;
#[cfg(feature = "tsssp")]
use sspi::credssp::sspi_cred_ssp;
#[cfg(feature = "tsssp")]
use sspi::credssp::sspi_cred_ssp::SspiCredSsp;
use sspi::credssp::SspiContext;
use sspi::kerberos::config::KerberosConfig;
use sspi::ntlm::NtlmConfig;
use sspi::{
    kerberos, negotiate, ntlm, pku2u, CertContext, ClientRequestFlags, ConnectionInfo, Credentials, CredentialsBuffers,
    DataRepresentation, Error, ErrorKind, Kerberos, Negotiate, NegotiateConfig, Ntlm, PackageInfo, Result, Secret,
    Sspi, SspiImpl, StreamSizes,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::Cryptography::{
    CertAddEncodedCertificateToStore, CertOpenStore, CERT_CONTEXT, CERT_STORE_ADD_REPLACE_EXISTING,
    CERT_STORE_CREATE_NEW_FLAG, CERT_STORE_PROV_MEMORY,
};

cfg_if::cfg_if! {
    if #[cfg(target_os = "windows")] {
        use symbol_rename_macro::rename_symbol;
        use sspi::{Pku2u, Pku2uConfig};
    }
}

use super::credentials_attributes::{
    extract_kdc_proxy_settings, CredentialsAttributes, SecPkgCredentialsKdcUrlA, SecPkgCredentialsKdcUrlW,
};
use super::sec_buffer::{copy_to_c_sec_buffer, p_sec_buffers_to_security_buffers, PSecBuffer, PSecBufferDesc};
use super::sec_pkg_info::{RawSecPkgInfoA, RawSecPkgInfoW, SecNegoInfoA, SecNegoInfoW, SecPkgInfoA, SecPkgInfoW};
use super::sec_winnt_auth_identity::auth_data_to_identity_buffers;
use super::sspi_data_types::{
    CertTrustStatus, LpStr, LpcWStr, PSecurityString, PTimeStamp, SecChar, SecGetKeyFn, SecPkgContextConnectionInfo,
    SecPkgContextFlags, SecPkgContextSizes, SecPkgContextStreamSizes, SecWChar, SecurityStatus,
};
use super::utils::{hostname, transform_credentials_handle};
use crate::utils::{c_w_str_to_string, into_raw_ptr};

pub const SECPKG_NEGOTIATION_COMPLETE: u32 = 0;
pub const SECPKG_NEGOTIATION_OPTIMISTIC: u32 = 1;
pub const SECPKG_NEGOTIATION_IN_PROGRESS: u32 = 2;

// the sizes of the structures used in the per-message functions and authentication exchanges
pub const SECPKG_ATTR_SIZES: u32 = 0;
// information about the security package to be used with the negotiation process and the current state of the negotiation for the use of that package
pub const SECPKG_ATTR_NEGOTIATION_INFO: u32 = 12;
// the sizes of the various parts of a stream used in the per-message functions
pub const SECPKG_ATTR_STREAM_SIZES: u32 = 4;
// certificate context that contains the end certificate supplied by the server
pub const SECPKG_ATTR_REMOTE_CERT_CONTEXT: u32 = 0x53;
// the name of the authentication package negotiated by the Microsoft Negotiate provider
pub const SECPKG_ATTR_NEGOTIATION_PACKAGE: u32 = 0x80000081;
// information on the SSP in use
pub const SECPKG_ATTR_PACKAGE_INFO: u32 = 10;
// information about the flags in the current security context
pub const SECPKG_ATTR_SERVER_AUTH_FLAGS: u32 = 0x80000083;
// trust information about the certificate
pub const SECPKG_ATTR_CERT_TRUST_STATUS: u32 = 0x80000084;
// detailed information on the established connection
pub const SECPKG_ATTR_CONNECTION_INFO: u32 = 0x5a;

// Sets the name of a credential
// In our library, we use this attribute to set the workstation for auth identity
const SECPKG_CRED_ATTR_NAMES: u32 = 1;
// Sets the Kerberos proxy setting
const SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS: u32 = 3;

const SECPKG_CRED_ATTR_KDC_URL: u32 = 501;

#[derive(Debug)]
#[repr(C)]
pub struct SecHandle {
    pub dw_lower: c_ulonglong,
    pub dw_upper: c_ulonglong,
}

pub type PCredHandle = *mut SecHandle;
pub type PCtxtHandle = *mut SecHandle;

/// Synchronized version of the [SspiContext].
///
/// All functions are synchronized by wrapping [SspiContext] in [Mutex].
pub struct SspiHandle {
    sspi_context: Mutex<SspiContext>,
}

impl SspiHandle {
    /// Creates a new [SspiHandle] based on the provided [SspiContext].
    pub fn new(sspi_context: SspiContext) -> Self {
        Self {
            sspi_context: Mutex::new(sspi_context),
        }
    }
}

impl SspiImpl for SspiHandle {
    type CredentialsHandle = Option<CredentialsBuffers>;
    type AuthenticationData = Credentials;

    fn acquire_credentials_handle_impl<'a>(
        &'a mut self,
        builder: sspi::builders::FilledAcquireCredentialsHandle<'a, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> Result<sspi::AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        let mut context = self.sspi_context.lock()?;
        context.acquire_credentials_handle_impl(builder)
    }

    fn initialize_security_context_impl<'a>(
        &'a mut self,
        builder: &'a mut sspi::builders::FilledInitializeSecurityContext<'a, Self::CredentialsHandle>,
    ) -> Result<sspi::generator::GeneratorInitSecurityContext> {
        let mut context = self.sspi_context.lock()?;
        Ok(context.initialize_security_context_sync(builder).into())
    }

    fn accept_security_context_impl(
        &mut self,
        builder: sspi::builders::FilledAcceptSecurityContext<'_, Self::CredentialsHandle>,
    ) -> Result<sspi::AcceptSecurityContextResult> {
        self.sspi_context.lock()?.accept_security_context_impl(builder)
    }
}

impl Sspi for SspiHandle {
    fn complete_auth_token(&mut self, token: &mut [sspi::OwnedSecurityBuffer]) -> Result<sspi::SecurityStatus> {
        self.sspi_context.lock()?.complete_auth_token(token)
    }

    fn encrypt_message(
        &mut self,
        flags: sspi::EncryptionFlags,
        message: &mut [sspi::SecurityBuffer],
        sequence_number: u32,
    ) -> Result<sspi::SecurityStatus> {
        self.sspi_context
            .lock()?
            .encrypt_message(flags, message, sequence_number)
    }

    fn decrypt_message(
        &mut self,
        message: &mut [sspi::SecurityBuffer],
        sequence_number: u32,
    ) -> Result<sspi::DecryptionFlags> {
        self.sspi_context.lock()?.decrypt_message(message, sequence_number)
    }

    fn query_context_sizes(&mut self) -> Result<sspi::ContextSizes> {
        self.sspi_context.lock()?.query_context_sizes()
    }

    fn query_context_names(&mut self) -> Result<sspi::ContextNames> {
        self.sspi_context.lock()?.query_context_names()
    }

    fn query_context_stream_sizes(&mut self) -> Result<StreamSizes> {
        self.sspi_context.lock()?.query_context_stream_sizes()
    }

    fn query_context_package_info(&mut self) -> Result<PackageInfo> {
        self.sspi_context.lock()?.query_context_package_info()
    }

    fn query_context_cert_trust_status(&mut self) -> Result<sspi::CertTrustStatus> {
        self.sspi_context.lock()?.query_context_cert_trust_status()
    }

    fn query_context_remote_cert(&mut self) -> Result<CertContext> {
        self.sspi_context.lock()?.query_context_remote_cert()
    }

    fn query_context_negotiation_package(&mut self) -> Result<PackageInfo> {
        self.sspi_context.lock()?.query_context_negotiation_package()
    }

    fn query_context_connection_info(&mut self) -> Result<ConnectionInfo> {
        self.sspi_context.lock()?.query_context_connection_info()
    }

    fn change_password<'a>(
        &'a mut self,
        change_password: sspi::builders::ChangePassword<'a>,
    ) -> Result<sspi::generator::GeneratorChangePassword> {
        let mut context = self.sspi_context.lock()?;
        Ok(context.change_password_sync(change_password).into())
    }
}

pub struct CredentialsHandle {
    pub credentials: CredentialsBuffers,
    pub security_package_name: String,
    pub attributes: CredentialsAttributes,
}

fn create_negotiate_context(attributes: &CredentialsAttributes) -> Result<Negotiate> {
    let client_computer_name = attributes.hostname()?;

    if let Some(kdc_url) = attributes.kdc_url() {
        let kerberos_config = KerberosConfig::new(&kdc_url, client_computer_name.clone());
        let negotiate_config = NegotiateConfig::new(
            Box::new(kerberos_config),
            attributes.package_list.clone(),
            client_computer_name,
        );

        Negotiate::new(negotiate_config)
    } else {
        let negotiate_config = NegotiateConfig {
            protocol_config: Box::new(NtlmConfig::new(client_computer_name.clone())),
            package_list: attributes.package_list.clone(),
            client_computer_name,
        };
        Negotiate::new(negotiate_config)
    }
}

#[instrument(ret)]
pub(crate) unsafe fn p_ctxt_handle_to_sspi_context(
    context: &mut PCtxtHandle,
    security_package_name: Option<&str>,
    attributes: &CredentialsAttributes,
) -> Result<*mut SspiHandle> {
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
                "Security package name is not provided",
            ));
        }
        let name = security_package_name.expect("security package name must be provided");

        info!(?name, "Creating context");

        let sspi_context = SspiHandle::new(match name {
            negotiate::PKG_NAME => SspiContext::Negotiate(create_negotiate_context(attributes)?),
            pku2u::PKG_NAME => {
                #[cfg(not(target_os = "windows"))]
                return Err(Error::new(
                    ErrorKind::InvalidParameter,
                    "PKU2U is not supported on non-Windows OS yet",
                ));
                #[cfg(target_os = "windows")]
                SspiContext::Pku2u(Pku2u::new_client_from_config(Pku2uConfig::default_client_config(
                    hostname()?,
                )?)?)
            }
            kerberos::PKG_NAME => {
                let client_computer_name = attributes.hostname()?;

                if let Some(kdc_url) = attributes.kdc_url() {
                    SspiContext::Kerberos(Kerberos::new_client_from_config(KerberosConfig::new(
                        &kdc_url,
                        client_computer_name,
                    ))?)
                } else {
                    let krb_config = KerberosConfig {
                        client_computer_name: Some(client_computer_name),
                        kdc_url: None,
                    };
                    SspiContext::Kerberos(Kerberos::new_client_from_config(krb_config)?)
                }
            }
            ntlm::PKG_NAME => {
                let hostname = attributes.hostname()?;

                SspiContext::Ntlm(Ntlm::with_config(NtlmConfig::new(hostname)))
            }
            #[cfg(feature = "tsssp")]
            sspi_cred_ssp::PKG_NAME => SspiContext::CredSsp(SspiCredSsp::new_client(SspiContext::Negotiate(
                create_negotiate_context(attributes)?,
            ))?),
            _ => {
                return Err(Error::new(
                    ErrorKind::SecurityPackageNotFound,
                    format!("security package name `{}` is not supported", name),
                ));
            }
        });

        (*(*context)).dw_lower = into_raw_ptr(sspi_context) as c_ulonglong;
        if (*(*context)).dw_upper == 0 {
            (*(*context)).dw_upper = into_raw_ptr(name.to_owned()) as c_ulonglong;
        }
    }

    Ok((*(*context)).dw_lower as *mut _)
}

fn verify_security_package(package_name: &str) -> Result<()> {
    match package_name {
        negotiate::PKG_NAME | pku2u::PKG_NAME | kerberos::PKG_NAME | ntlm::PKG_NAME => Ok(()),
        #[cfg(feature = "tsssp")]
        sspi_cred_ssp::PKG_NAME => Ok(()),
        _ => Err(Error::new(
            ErrorKind::SecurityPackageNotFound,
            format!("security package name `{}` is not supported", package_name),
        )),
    }
}

/// AcquireCredentialsHandleA function acquires a handle to preexisting credentials of a security principal.
///
/// NOTE: Although in the original Windows SSPI, `p_auth_data` parameter can be NULL, in our implementation it must be non-NULL.
/// That's because we cannot get the default credentials handle for security package, like Windows can.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_AcquireCredentialsHandleA"))]
#[no_mangle]
pub unsafe extern "system" fn AcquireCredentialsHandleA(
    _psz_principal: LpStr,
    psz_package: LpStr,
    _f_aredential_use: u32,
    _pv_logon_id: *const c_void,
    p_auth_data: *const c_void,
    _p_get_key_fn: SecGetKeyFn,
    _pv_get_key_argument: *const c_void,
    ph_credential: PCredHandle,
    _pts_expiry: PTimeStamp,
) -> SecurityStatus {
    catch_panic! {
        check_null!(psz_package);
        check_null!(p_auth_data);
        check_null!(ph_credential);

        let security_package_name =
            try_execute!(CStr::from_ptr(psz_package).to_str(), ErrorKind::InvalidParameter).to_owned();
        try_execute!(verify_security_package(&security_package_name));

        debug!(?security_package_name);

        let mut package_list: Option<String> = None;

        let credentials = try_execute!(auth_data_to_identity_buffers(&security_package_name, p_auth_data, &mut package_list));

        (*ph_credential).dw_lower = into_raw_ptr(CredentialsHandle {
            credentials,
            security_package_name,
            attributes: CredentialsAttributes::new_with_package_list(package_list),
        }) as c_ulonglong;

        0
    }
}

pub type AcquireCredentialsHandleFnA = unsafe extern "system" fn(
    LpStr,
    LpStr,
    u32,
    *const c_void,
    *const c_void,
    SecGetKeyFn,
    *const c_void,
    PCredHandle,
    PTimeStamp,
) -> SecurityStatus;

/// AcquireCredentialsHandleW function acquires a handle to preexisting credentials of a security principal.
///
/// NOTE: Although in the original Windows SSPI, `p_auth_data` parameter can be NULL, in our implementation it must be non-NULL.
/// That's because we cannot get the default credentials handle for security package, like Windows can.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_AcquireCredentialsHandleW"))]
#[no_mangle]
pub unsafe extern "system" fn AcquireCredentialsHandleW(
    _psz_principal: LpcWStr,
    psz_package: LpcWStr,
    _f_credential_use: u32,
    _pv_logon_id: *const c_void,
    p_auth_data: *const c_void,
    _p_get_key_fn: SecGetKeyFn,
    _pv_get_key_argument: *const c_void,
    ph_credential: PCredHandle,
    _pts_expiry: PTimeStamp,
) -> SecurityStatus {
    catch_panic! {
        check_null!(psz_package);
        check_null!(p_auth_data);
        check_null!(ph_credential);

        let security_package_name = c_w_str_to_string(psz_package);
        try_execute!(verify_security_package(&security_package_name));

        debug!(?security_package_name);

        let mut package_list: Option<String> = None;

        let credentials = try_execute!(auth_data_to_identity_buffers(&security_package_name, p_auth_data, &mut package_list));

        (*ph_credential).dw_lower = into_raw_ptr(CredentialsHandle {
            credentials,
            security_package_name,
            attributes: CredentialsAttributes::new_with_package_list(package_list),
        }) as c_ulonglong;

        0
    }
}

pub type AcquireCredentialsHandleFnW = unsafe extern "system" fn(
    LpcWStr,
    LpcWStr,
    u32,
    *const c_void,
    *const c_void,
    SecGetKeyFn,
    *const c_void,
    PCredHandle,
    PTimeStamp,
) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryCredentialsAttributesA"))]
#[no_mangle]
pub extern "system" fn QueryCredentialsAttributesA(
    _ph_credential: PCredHandle,
    _ul_attribute: u32,
    _p_buffer: *mut c_void,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type QueryCredentialsAttributesFnA = extern "system" fn(PCredHandle, u32, *mut c_void) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryCredentialsAttributesW"))]
#[no_mangle]
pub extern "system" fn QueryCredentialsAttributesW(
    _ph_credential: PCredHandle,
    _ul_attribute: u32,
    _p_buffer: *mut c_void,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type QueryCredentialsAttributesFnW = extern "system" fn(PCredHandle, u32, *mut c_void) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_InitializeSecurityContextA"))]
#[no_mangle]
pub unsafe extern "system" fn InitializeSecurityContextA(
    ph_credential: PCredHandle,
    mut ph_context: PCtxtHandle,
    p_target_name: *const SecChar,
    f_context_req: u32,
    _reserved1: u32,
    target_data_rep: u32,
    p_input: PSecBufferDesc,
    _reserved2: u32,
    ph_new_context: PCtxtHandle,
    p_output: PSecBufferDesc,
    pf_context_attr: *mut u32,
    _pts_expiry: PTimeStamp,
) -> SecurityStatus {
    catch_panic! {
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
        debug!(?service_principal, "Target name (SPN)");

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
            p_sec_buffers_to_security_buffers(if (*p_input).p_buffers.is_null() {
                &[]
            } else {
                from_raw_parts((*p_input).p_buffers, (*p_input).c_buffers as usize)
            })
        };

        let len = (*p_output).c_buffers as usize;
        let raw_buffers = from_raw_parts((*p_output).p_buffers, len);
        let mut output_tokens = p_sec_buffers_to_security_buffers(raw_buffers);
        output_tokens.iter_mut().for_each(|s| s.buffer.clear());

        let mut auth_data = Some(auth_data);
        let mut builder = sspi_context.initialize_security_context()
            .with_credentials_handle(&mut auth_data)
            .with_context_requirements(ClientRequestFlags::from_bits(f_context_req.try_into().unwrap()).unwrap())
            .with_target_data_representation(DataRepresentation::from_u32(target_data_rep.try_into().unwrap()).unwrap())
            .with_target_name(service_principal)
            .with_input(&mut input_tokens)
            .with_output(&mut output_tokens);
        let result_status = try_execute!(sspi_context.initialize_security_context_impl(&mut builder)).resolve_with_default_network_client();

        let context_requirements = ClientRequestFlags::from_bits_retain(f_context_req);
        let allocate = context_requirements.contains(ClientRequestFlags::ALLOCATE_MEMORY);

        copy_to_c_sec_buffer((*p_output).p_buffers, &output_tokens, allocate);

        (*ph_new_context).dw_lower = sspi_context_ptr as c_ulonglong;
        (*ph_new_context).dw_upper = (*ph_context).dw_upper;

        *pf_context_attr = f_context_req;

        let result = try_execute!(result_status);
        result.status.to_u32().unwrap()
    }
}

pub type InitializeSecurityContextFnA = unsafe extern "system" fn(
    PCredHandle,
    PCtxtHandle,
    *const SecChar,
    u32,
    u32,
    u32,
    PSecBufferDesc,
    u32,
    PCtxtHandle,
    PSecBufferDesc,
    *mut u32,
    PTimeStamp,
) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_InitializeSecurityContextW"))]
#[no_mangle]
pub unsafe extern "system" fn InitializeSecurityContextW(
    ph_credential: PCredHandle,
    mut ph_context: PCtxtHandle,
    p_target_name: *const SecWChar,
    f_context_req: u32,
    _reserved1: u32,
    target_data_rep: u32,
    p_input: PSecBufferDesc,
    _reserved2: u32,
    ph_new_context: PCtxtHandle,
    p_output: PSecBufferDesc,
    pf_context_attr: *mut u32,
    _pts_expiry: PTimeStamp,
) -> SecurityStatus {
    catch_panic! {
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
        debug!(?service_principal, "Target name (SPN)");

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
            p_sec_buffers_to_security_buffers(if (*p_input).p_buffers.is_null() {
                &[]
            } else {
                from_raw_parts((*p_input).p_buffers, (*p_input).c_buffers as usize)
            })
        };

        let raw_buffers = from_raw_parts((*p_output).p_buffers, (*p_output).c_buffers as usize);
        let mut output_tokens = p_sec_buffers_to_security_buffers(raw_buffers);
        output_tokens.iter_mut().for_each(|s| s.buffer.clear());

        let mut auth_data = Some(auth_data);
        let mut builder = sspi_context.initialize_security_context()
            .with_credentials_handle(&mut auth_data)
            .with_context_requirements(ClientRequestFlags::from_bits(f_context_req.try_into().unwrap()).unwrap())
            .with_target_data_representation(DataRepresentation::from_u32(target_data_rep.try_into().unwrap()).unwrap())
            .with_target_name(&service_principal)
            .with_input(&mut input_tokens)
            .with_output(&mut output_tokens);
        let result_status = try_execute!(sspi_context.initialize_security_context_impl(&mut builder)).resolve_with_default_network_client();

        let context_requirements = ClientRequestFlags::from_bits_retain(f_context_req);
        let allocate = context_requirements.contains(ClientRequestFlags::ALLOCATE_MEMORY);

        copy_to_c_sec_buffer((*p_output).p_buffers, &output_tokens, allocate);

        *pf_context_attr = f_context_req;

        (*ph_new_context).dw_lower = sspi_context_ptr as c_ulonglong;
        (*ph_new_context).dw_upper = (*ph_context).dw_upper;

        let result = try_execute!(result_status);
        result.status.to_u32().unwrap()
    }
}

pub type InitializeSecurityContextFnW = unsafe extern "system" fn(
    PCredHandle,
    PCtxtHandle,
    *const SecWChar,
    u32,
    u32,
    u32,
    PSecBufferDesc,
    u32,
    PCtxtHandle,
    PSecBufferDesc,
    *mut u32,
    PTimeStamp,
) -> SecurityStatus;

#[allow(clippy::useless_conversion)]
unsafe fn query_context_attributes_common(
    mut ph_context: PCtxtHandle,
    ul_attribute: u32,
    p_buffer: *mut c_void,
    is_wide: bool,
) -> SecurityStatus {
    catch_panic! {
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

                return 0;
            }
            SECPKG_ATTR_NEGOTIATION_INFO => {
                let package_info = try_execute!(sspi_context.query_context_package_info());

                if is_wide {
                    let nego_info = p_buffer.cast::<SecNegoInfoW>();

                    (*nego_info).nego_state = SECPKG_NEGOTIATION_COMPLETE.try_into().unwrap();

                    let package_info: RawSecPkgInfoW = package_info.into();
                    (*nego_info).package_info = package_info.0;
                } else {
                    let nego_info = p_buffer.cast::<SecNegoInfoA>();

                    (*nego_info).nego_state = SECPKG_NEGOTIATION_COMPLETE.try_into().unwrap();

                    let package_info: RawSecPkgInfoA = package_info.into();
                    (*nego_info).package_info = package_info.0;
                }

                return 0;
            }
            SECPKG_ATTR_STREAM_SIZES => {
                let stream_sizes = try_execute!(sspi_context.query_context_stream_sizes());

                let stream_info = p_buffer.cast::<SecPkgContextStreamSizes>();

                (*stream_info).cb_header = stream_sizes.header;
                (*stream_info).cb_trailer = stream_sizes.trailer;
                (*stream_info).cb_maximum_message = stream_sizes.max_message;
                (*stream_info).c_buffers = stream_sizes.buffers;
                (*stream_info).cb_block_size = stream_sizes.block_size;

                return 0;
            }
            SECPKG_ATTR_REMOTE_CERT_CONTEXT => {
                cfg_if::cfg_if! {
                    if #[cfg(target_os = "windows")] {
                        use std::ptr::{null, null_mut};

                        let cert_context = try_execute!(sspi_context.query_context_remote_cert());

                        let store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, null());

                        if store.is_null() {
                            return ErrorKind::InternalError.to_u32().unwrap();
                        }

                        let mut p_cert_context = null_mut();

                        let result = CertAddEncodedCertificateToStore(
                            store,
                            cert_context.encoding_type.to_u32().unwrap(),
                            cert_context.raw_cert.as_ptr(),
                            cert_context.raw_cert.len() as u32,
                            CERT_STORE_ADD_REPLACE_EXISTING,
                            &mut p_cert_context
                        );
                        if result != 1 {
                            return std::io::Error::last_os_error().raw_os_error().unwrap_or_else(|| ErrorKind::InternalError.to_i32().unwrap()) as u32;
                        }

                        let p_cert_buffer = p_buffer.cast::<*const CERT_CONTEXT>();
                        *p_cert_buffer = p_cert_context;

                        return 0;
                    } else {
                        return ErrorKind::UnsupportedFunction.to_u32().unwrap();
                    }
                }
            }
            SECPKG_ATTR_SERVER_AUTH_FLAGS => {
                let flags = SecPkgContextFlags {
                    flags: 0,
                };

                let sec_context_flags = p_buffer.cast::<*mut SecPkgContextFlags>();
                *sec_context_flags = into_raw_ptr(flags);

                return 0;
            }
            SECPKG_ATTR_CONNECTION_INFO => {
                let connection_info = try_execute!(sspi_context.query_context_connection_info());

                let sec_pkg_context_connection_info = p_buffer.cast::<SecPkgContextConnectionInfo>();

                (*sec_pkg_context_connection_info).dw_protocol = connection_info.protocol.to_u32().unwrap();
                (*sec_pkg_context_connection_info).ai_cipher = connection_info.cipher.to_u32().unwrap();
                (*sec_pkg_context_connection_info).dw_cipher_strength = connection_info.cipher_strength;
                (*sec_pkg_context_connection_info).ai_hash = connection_info.hash.to_u32().unwrap();
                (*sec_pkg_context_connection_info).dw_hash_strength = connection_info.hash_strength;
                (*sec_pkg_context_connection_info).ai_exch = connection_info.key_exchange.to_u32().unwrap();
                (*sec_pkg_context_connection_info).dw_exch_strength = connection_info.exchange_strength;

                return 0;
            }
            SECPKG_ATTR_CERT_TRUST_STATUS => {
                let sspi_cert_trust_status = try_execute!(sspi_context.query_context_cert_trust_status());

                let cert_trust_status = p_buffer.cast::<CertTrustStatus>();
                (*cert_trust_status).dw_error_status = sspi_cert_trust_status.error_status.bits();
                (*cert_trust_status).dw_info_status = sspi_cert_trust_status.info_status.bits();

                return 0;
            }
            _ => {},
        };

        let package_info = try_execute!(match ul_attribute.try_into().unwrap() {
            SECPKG_ATTR_PACKAGE_INFO => {
                sspi_context.query_context_package_info()
            }
            SECPKG_ATTR_NEGOTIATION_PACKAGE => {
                sspi_context.query_context_negotiation_package()
            }
            unsupported => {
                Err(Error::new(ErrorKind::UnsupportedFunction, format!("Unsupported function ID {unsupported}")))
            },
        });

        if is_wide {
            let nego_info = p_buffer.cast::<*mut SecPkgInfoW>();

            let package_info: RawSecPkgInfoW = package_info.into();
            *nego_info = package_info.0;
        } else {
            let nego_info = p_buffer.cast::<*mut SecPkgInfoA>();

            let package_info: RawSecPkgInfoA = package_info.into();
            *nego_info = package_info.0;
        }

        0
    }
}

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryContextAttributesA"))]
#[no_mangle]
pub unsafe extern "system" fn QueryContextAttributesA(
    ph_context: PCtxtHandle,
    ul_attribute: u32,
    p_buffer: *mut c_void,
) -> SecurityStatus {
    query_context_attributes_common(ph_context, ul_attribute, p_buffer, false)
}

pub type QueryContextAttributesFnA = unsafe extern "system" fn(PCtxtHandle, u32, *mut c_void) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryContextAttributesW"))]
#[no_mangle]
pub unsafe extern "system" fn QueryContextAttributesW(
    ph_context: PCtxtHandle,
    ul_attribute: u32,
    p_buffer: *mut c_void,
) -> SecurityStatus {
    query_context_attributes_common(ph_context, ul_attribute, p_buffer, true)
}

pub type QueryContextAttributesFnW = unsafe extern "system" fn(PCtxtHandle, u32, *mut c_void) -> SecurityStatus;

#[instrument(skip_all)]
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

#[instrument(skip_all)]
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

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_AddCredentialsA"))]
#[no_mangle]
pub extern "system" fn AddCredentialsA(
    _ph_credential: PCredHandle,
    _s1: *mut SecChar,
    _s2: *mut SecChar,
    _n1: u32,
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
    u32,
    *mut c_void,
    SecGetKeyFn,
    *mut c_void,
    PTimeStamp,
) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_AddCredentialsW"))]
#[no_mangle]
pub extern "system" fn AddCredentialsW(
    _ph_credential: PCredHandle,
    _s1: *mut SecWChar,
    _s2: *mut SecWChar,
    _n1: u32,
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
    u32,
    *mut c_void,
    SecGetKeyFn,
    *mut c_void,
    PTimeStamp,
) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_SetContextAttributesA"))]
#[no_mangle]
pub extern "system" fn SetContextAttributesA(
    _ph_context: PCtxtHandle,
    _ul_attribute: u32,
    _p_buffer: *mut c_void,
    _cb_buffer: u32,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type SetContextAttributesFnA = extern "system" fn(PCtxtHandle, u32, *mut c_void, u32) -> SecurityStatus;

#[cfg_attr(windows, rename_symbol(to = "Rust_SetContextAttributesW"))]
#[no_mangle]
pub extern "system" fn SetContextAttributesW(
    _ph_context: PCtxtHandle,
    _ul_attribute: u32,
    _p_buffer: *mut c_void,
    _cb_buffer: u32,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type SetContextAttributesFnW = extern "system" fn(PCtxtHandle, u32, *mut c_void, u32) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_SetCredentialsAttributesA"))]
#[no_mangle]
pub unsafe extern "system" fn SetCredentialsAttributesA(
    ph_credential: PCtxtHandle,
    ul_attribute: u32,
    p_buffer: *mut c_void,
    _cb_buffer: u32,
) -> SecurityStatus {
    catch_panic! {
        check_null!(ph_credential);
        check_null!(p_buffer);

        let credentials_handle = ((*ph_credential).dw_lower as *mut CredentialsHandle).as_mut().unwrap();

        if ul_attribute == SECPKG_CRED_ATTR_NAMES {
            let workstation =
                try_execute!(CStr::from_ptr(p_buffer as *const _).to_str(), ErrorKind::InvalidParameter).to_owned();

            credentials_handle.attributes.workstation = Some(workstation);

            0
        } else if ul_attribute == SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS {
            credentials_handle.attributes.kdc_proxy_settings = Some(extract_kdc_proxy_settings(p_buffer));

            0
        } else if ul_attribute == SECPKG_CRED_ATTR_KDC_URL {
            let cred_attr = p_buffer.cast::<SecPkgCredentialsKdcUrlA>();
            let kdc_url = try_execute!(CStr::from_ptr((*cred_attr).kdc_url).to_str(), ErrorKind::InvalidParameter);
            credentials_handle.attributes.kdc_url = Some(kdc_url.to_string());
            0
        } else {
            ErrorKind::UnsupportedFunction.to_u32().unwrap()
        }
    }
}

pub type SetCredentialsAttributesFnA = unsafe extern "system" fn(PCtxtHandle, u32, *mut c_void, u32) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_SetCredentialsAttributesW"))]
#[no_mangle]
pub unsafe extern "system" fn SetCredentialsAttributesW(
    ph_credential: PCtxtHandle,
    ul_attribute: u32,
    p_buffer: *mut c_void,
    _cb_buffer: u32,
) -> SecurityStatus {
    catch_panic! {
        check_null!(ph_credential);
        check_null!(p_buffer);

        let credentials_handle = ((*ph_credential).dw_lower as *mut CredentialsHandle).as_mut().unwrap();

        if ul_attribute == SECPKG_CRED_ATTR_NAMES {
            let workstation = c_w_str_to_string(p_buffer as *const _);

            credentials_handle.attributes.workstation = Some(workstation);

            0
        } else if ul_attribute == SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS {
            credentials_handle.attributes.kdc_proxy_settings = Some(extract_kdc_proxy_settings(p_buffer));

            0
        } else if ul_attribute == SECPKG_CRED_ATTR_KDC_URL {
            let cred_attr = p_buffer.cast::<SecPkgCredentialsKdcUrlW>();
            let kdc_url = c_w_str_to_string((*cred_attr).kdc_url as *const u16);
            credentials_handle.attributes.kdc_url = Some(kdc_url);

            0
        } else {
            ErrorKind::UnsupportedFunction.to_u32().unwrap()
        }
    }
}

pub type SetCredentialsAttributesFnW = unsafe extern "system" fn(PCtxtHandle, u32, *mut c_void, u32) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_ChangeAccountPasswordA"))]
#[no_mangle]
pub unsafe extern "system" fn ChangeAccountPasswordA(
    psz_package_name: *mut SecChar,
    psz_domain_name: *mut SecChar,
    psz_account_name: *mut SecChar,
    psz_old_password: *mut SecChar,
    psz_new_password: *mut SecChar,
    _b_impersonating: bool,
    _dw_reserved: u32,
    p_output: PSecBufferDesc,
) -> SecurityStatus {
    catch_panic! {
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
            negotiate::PKG_NAME => {
                let negotiate_config = NegotiateConfig {
                    protocol_config: Box::new(NtlmConfig::new(try_execute!(hostname()))),
                    package_list: None,
                    client_computer_name: try_execute!(hostname()),
                };
                SspiContext::Negotiate(try_execute!(Negotiate::new(negotiate_config)))
            },
            kerberos::PKG_NAME => {
                let krb_config = KerberosConfig{
                    client_computer_name:Some(try_execute!(hostname())),
                    kdc_url:None
                };
                SspiContext::Kerberos(try_execute!(Kerberos::new_client_from_config(
                    krb_config
                )))
            },
            ntlm::PKG_NAME => SspiContext::Ntlm(Ntlm::with_config(NtlmConfig::new(try_execute!(hostname())))),
            _ => {
                return ErrorKind::InvalidParameter.to_u32().unwrap();
            }
        };

        let result_status = try_execute!(sspi_context.change_password(change_password)).resolve_with_default_network_client();

        copy_to_c_sec_buffer((*p_output).p_buffers, &output_tokens, false);

        try_execute!(result_status);

        0
    }
}

pub type ChangeAccountPasswordFnA = unsafe extern "system" fn(
    *mut SecChar,
    *mut SecChar,
    *mut SecChar,
    *mut SecChar,
    *mut SecChar,
    bool,
    u32,
    PSecBufferDesc,
) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_ChangeAccountPasswordW"))]
#[no_mangle]
pub unsafe extern "system" fn ChangeAccountPasswordW(
    psz_package_name: *mut SecWChar,
    psz_domain_name: *mut SecWChar,
    psz_account_name: *mut SecWChar,
    psz_old_password: *mut SecWChar,
    psz_new_password: *mut SecWChar,
    b_impersonating: bool,
    dw_reserved: u32,
    p_output: PSecBufferDesc,
) -> SecurityStatus {
    catch_panic! {
        check_null!(psz_package_name);
        check_null!(psz_domain_name);
        check_null!(psz_account_name);
        check_null!(psz_old_password);
        check_null!(psz_new_password);
        check_null!(p_output);

        let mut security_package_name = c_w_str_to_string(psz_package_name);

        let mut domain = c_w_str_to_string(psz_domain_name);
        let mut username = c_w_str_to_string(psz_account_name);
        let mut password = Secret::new(c_w_str_to_string(psz_old_password));
        let mut new_password = Secret::new(c_w_str_to_string(psz_new_password));

        ChangeAccountPasswordA(
            security_package_name.as_mut_ptr() as *mut _,
            domain.as_mut_ptr() as *mut _,
            username.as_mut_ptr() as *mut _,
            password.as_mut().as_mut_ptr() as *mut _,
            new_password.as_mut().as_mut_ptr() as *mut _,
            b_impersonating,
            dw_reserved,
            p_output,
        )
    }
}

pub type ChangeAccountPasswordFnW = unsafe extern "system" fn(
    *mut SecWChar,
    *mut SecWChar,
    *mut SecWChar,
    *mut SecWChar,
    *mut SecWChar,
    bool,
    u32,
    PSecBufferDesc,
) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryContextAttributesExA"))]
#[no_mangle]
pub extern "system" fn QueryContextAttributesExA(
    _ph_context: PCtxtHandle,
    _ul_attribute: u32,
    _p_buffer: *mut c_void,
    _cb_buffer: u32,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type QueryContextAttributesExFnA = extern "system" fn(PCtxtHandle, u32, *mut c_void, u32) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryContextAttributesExW"))]
#[no_mangle]
pub extern "system" fn QueryContextAttributesExW(
    _ph_context: PCtxtHandle,
    _ul_attribute: u32,
    _p_buffer: *mut c_void,
    _cb_buffer: u32,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type QueryContextAttributesExFnW = extern "system" fn(PCtxtHandle, u32, *mut c_void, u32) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryCredentialsAttributesExA"))]
#[no_mangle]
pub extern "system" fn QueryCredentialsAttributesExA(
    _ph_credential: PCredHandle,
    _ul_attribute: u32,
    _p_buffer: *mut c_void,
    _c_buffers: u32,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type QueryCredentialsAttributesExFnA = extern "system" fn(PCredHandle, u32, *mut c_void, u32) -> SecurityStatus;

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryCredentialsAttributesExW"))]
#[no_mangle]
pub extern "system" fn QueryCredentialsAttributesExW(
    _ph_aredential: PCredHandle,
    _ul_attribute: u32,
    _p_buffer: *mut c_void,
    _c_buffers: u32,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

pub type QueryCredentialsAttributesExFnW = extern "system" fn(PCredHandle, u32, *mut c_void, u32) -> SecurityStatus;

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::ptr::{null, null_mut};

    use libc::c_void;

    use crate::sspi::common::{DeleteSecurityContext, FreeContextBuffer, FreeCredentialsHandle};
    use crate::sspi::sec_buffer::{SecBuffer, SecBufferDesc};
    use crate::sspi::sec_handle::{
        AcquireCredentialsHandleA, AcquireCredentialsHandleW, InitializeSecurityContextA, InitializeSecurityContextW,
        SecHandle,
    };
    use crate::sspi::sec_pkg_info::{
        EnumerateSecurityPackagesA, EnumerateSecurityPackagesW, PSecPkgInfoA, PSecPkgInfoW, QuerySecurityPackageInfoA,
        QuerySecurityPackageInfoW, SecPkgInfoA, SecPkgInfoW,
    };
    use crate::sspi::sec_winnt_auth_identity::{
        SecWinntAuthIdentityA, SecWinntAuthIdentityW, SEC_WINNT_AUTH_IDENTITY_ANSI, SEC_WINNT_AUTH_IDENTITY_UNICODE,
    };
    use crate::utils::c_w_str_to_string;

    extern "system" fn dummy(_: *mut c_void, _: *mut c_void, _: u32, _: *mut *mut c_void, _: *mut i32) {}

    /// This test simulates initialize security context function call. It's better to run it using Miri
    /// https://github.com/rust-lang/miri
    /// cargo +nightly miri test
    #[test]
    fn initialize_security_context_w() {
        let pkg_name = "NTLM\0".encode_utf16().collect::<Vec<_>>();
        let mut pkg_info: PSecPkgInfoW = null_mut::<SecPkgInfoW>();

        let status = unsafe { QuerySecurityPackageInfoW(pkg_name.as_ptr(), &mut pkg_info) };
        assert_eq!(status, 0);

        // We left all `println`s on purpose:
        // to simulate any memory access to the allocated memory.
        println!("{:?}", unsafe { &*pkg_info });
        println!("{:?}", unsafe { c_w_str_to_string((*pkg_info).name) });
        println!("{:?}", unsafe { c_w_str_to_string((*pkg_info).comment) });

        let cb_max_token = unsafe { (*pkg_info).cb_max_token };

        let status = unsafe { FreeContextBuffer(pkg_info as *mut _) };
        assert_eq!(status, 0);

        let mut pc_packages = 0;
        let mut packages: PSecPkgInfoW = null_mut::<SecPkgInfoW>();

        let status = unsafe { EnumerateSecurityPackagesW(&mut pc_packages, &mut packages) };
        assert_eq!(status, 0);

        for i in 0..pc_packages as usize {
            let pkg_info = unsafe { packages.add(i) };
            println!("{:?}", unsafe { &*pkg_info });
            println!("{:?}", unsafe { c_w_str_to_string((*pkg_info).name) });
            println!("{:?}", unsafe { c_w_str_to_string((*pkg_info).comment) });
        }

        let status = unsafe { FreeContextBuffer(packages as *mut _) };
        assert_eq!(status, 0);

        let user = "user".encode_utf16().collect::<Vec<_>>();
        let domain = "domain".encode_utf16().collect::<Vec<_>>();
        let password = "password".encode_utf16().collect::<Vec<_>>();

        let credentials = SecWinntAuthIdentityW {
            user: user.as_ptr(),
            user_length: user.len() as u32,
            domain: domain.as_ptr(),
            domain_length: domain.len() as u32,
            password: password.as_ptr(),
            password_length: password.len() as u32,
            flags: 0,
        };

        let mut cred_handle = SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        };

        let status = unsafe {
            AcquireCredentialsHandleW(
                null_mut(),
                pkg_name.as_ptr() as *const _,
                2, /* SECPKG_CRED_OUTBOUND */
                null::<c_void>(),
                &credentials as *const _ as *const c_void,
                dummy,
                null::<c_void>(),
                &mut cred_handle,
                null_mut(),
            )
        };
        assert_eq!(status, 0);

        let mut sec_context = SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        };
        let mut new_sec_context = SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        };
        let mut target_name = "TERMSRV/some@example.com\0".encode_utf16().collect::<Vec<_>>();
        let mut attrs = 0;

        let mut out_buffer = vec![0; cb_max_token as usize];
        let mut out_sec_buffer = SecBuffer {
            cb_buffer: cb_max_token,
            buffer_type: 2,
            pv_buffer: out_buffer.as_mut_ptr() as *mut _,
        };
        let mut out_buffer_desk = SecBufferDesc {
            ul_version: 0,
            c_buffers: 1,
            p_buffers: &mut out_sec_buffer,
        };

        let mut in_buffer_desk = SecBufferDesc {
            ul_version: 0,
            c_buffers: 0,
            p_buffers: null_mut::<SecBuffer>(),
        };

        let status = unsafe {
            InitializeSecurityContextW(
                &mut cred_handle,
                &mut sec_context,
                target_name.as_mut_ptr() as *mut _,
                0,
                0,
                0x10, /* SECURITY_NATIVE_DREP */
                &mut in_buffer_desk,
                0,
                &mut new_sec_context,
                &mut out_buffer_desk,
                &mut attrs,
                null_mut(),
            )
        };
        assert_eq!(status, 0x0009_0312 /* CONTINUE_NEEDED */);

        let status = unsafe { FreeCredentialsHandle(&mut cred_handle) };
        assert_eq!(status, 0);

        let status = unsafe { DeleteSecurityContext(&mut new_sec_context) };
        assert_eq!(status, 0);
    }

    /// This test simulates initialize security context function call. It's better to run it using Miri
    /// https://github.com/rust-lang/miri
    /// cargo +nightly miri test
    #[test]
    fn initialize_security_context_a() {
        let pkg_name = "NTLM\0";
        let mut pkg_info: PSecPkgInfoA = null_mut::<SecPkgInfoA>();

        let status = unsafe { QuerySecurityPackageInfoA(pkg_name.as_ptr() as *const _, &mut pkg_info) };
        assert_eq!(status, 0);

        // We left all `println`s on purpose:
        // to simulate any memory access to the allocated memory.
        println!("{:?}", unsafe { &*pkg_info });
        println!("{:?}", unsafe { CStr::from_ptr((*pkg_info).name).to_str().unwrap() });
        println!("{:?}", unsafe { CStr::from_ptr((*pkg_info).comment).to_str().unwrap() });

        let cb_max_token = unsafe { (*pkg_info).cb_max_token };

        let status = unsafe { FreeContextBuffer(pkg_info as *mut _) };
        assert_eq!(status, 0);

        let mut pc_packages = 0;
        let mut packages: PSecPkgInfoA = null_mut::<SecPkgInfoA>();

        let status = unsafe { EnumerateSecurityPackagesA(&mut pc_packages, &mut packages) };
        assert_eq!(status, 0);

        for i in 0..pc_packages as usize {
            let pkg_info = unsafe { packages.add(i) };
            println!("{:?}", unsafe { &*pkg_info });
            println!("{:?}", unsafe { CStr::from_ptr((*pkg_info).name).to_str().unwrap() });
            println!("{:?}", unsafe { CStr::from_ptr((*pkg_info).comment).to_str().unwrap() });
        }

        let status = unsafe { FreeContextBuffer(packages as *mut _) };
        assert_eq!(status, 0);

        let user = "user";
        let domain = "domain";
        let password = "password";

        let credentials = SecWinntAuthIdentityA {
            user: user.as_ptr() as *const _,
            user_length: user.len() as u32,
            domain: domain.as_ptr() as *const _,
            domain_length: domain.len() as u32,
            password: password.as_ptr() as *const _,
            password_length: password.len() as u32,
            flags: 1,
        };

        let mut cred_handle = SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        };

        let status = unsafe {
            AcquireCredentialsHandleA(
                null_mut(),
                pkg_name.as_ptr() as *const _,
                2, /* SECPKG_CRED_OUTBOUND */
                null::<c_void>(),
                &credentials as *const _ as *const c_void,
                dummy,
                null::<c_void>(),
                &mut cred_handle,
                null_mut(),
            )
        };
        assert_eq!(status, 0);

        let mut sec_context = SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        };
        let mut new_sec_context = SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        };
        let mut target_name = String::from("TERMSRV/some@example.com\0");
        let mut attrs = 0;

        let mut out_buffer = vec![0; cb_max_token as usize];
        let mut out_sec_buffer = SecBuffer {
            cb_buffer: cb_max_token,
            buffer_type: 2,
            pv_buffer: out_buffer.as_mut_ptr() as *mut _,
        };
        let mut out_buffer_desk = SecBufferDesc {
            ul_version: 0,
            c_buffers: 1,
            p_buffers: &mut out_sec_buffer,
        };

        let mut in_buffer_desk = SecBufferDesc {
            ul_version: 0,
            c_buffers: 0,
            p_buffers: null_mut::<SecBuffer>(),
        };

        let status = unsafe {
            InitializeSecurityContextA(
                &mut cred_handle,
                &mut sec_context,
                target_name.as_mut_ptr() as *mut _,
                0,
                0,
                0x10, /* SECURITY_NATIVE_DREP */
                &mut in_buffer_desk,
                0,
                &mut new_sec_context,
                &mut out_buffer_desk,
                &mut attrs,
                null_mut(),
            )
        };
        assert_eq!(status, 0x0009_0312 /* CONTINUE_NEEDED */);

        let status = unsafe { FreeCredentialsHandle(&mut cred_handle) };
        assert_eq!(status, 0);

        let status = unsafe { DeleteSecurityContext(&mut new_sec_context) };
        assert_eq!(status, 0);
    }

    /// This test simulates initialize security context function call. It's better to run it using Miri
    /// https://github.com/rust-lang/miri
    /// cargo +nightly miri test
    #[test]
    fn acquire_credentials_handle_w_null_credentials() {
        let pkg_name = "NTLM\0".encode_utf16().collect::<Vec<_>>();

        let user = "user".encode_utf16().collect::<Vec<_>>();
        let domain = "domain".encode_utf16().collect::<Vec<_>>();
        let password = "password".encode_utf16().collect::<Vec<_>>();

        let credentials = vec![
            SecWinntAuthIdentityW {
                user: null(),
                user_length: 0,
                domain: domain.as_ptr(),
                domain_length: domain.len() as u32,
                password: password.as_ptr(),
                password_length: password.len() as u32,
                flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
            },
            SecWinntAuthIdentityW {
                user: user.as_ptr(),
                user_length: user.len() as u32,
                domain: null(),
                domain_length: 0,
                password: password.as_ptr(),
                password_length: password.len() as u32,
                flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
            },
            SecWinntAuthIdentityW {
                user: user.as_ptr(),
                user_length: user.len() as u32,
                domain: domain.as_ptr(),
                domain_length: domain.len() as u32,
                password: null(),
                password_length: 0,
                flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
            },
        ];

        for credentials in credentials {
            let mut cred_handle = SecHandle {
                dw_lower: 0,
                dw_upper: 0,
            };

            let status = unsafe {
                AcquireCredentialsHandleW(
                    null_mut(),
                    pkg_name.as_ptr() as *const _,
                    2, /* SECPKG_CRED_OUTBOUND */
                    null::<c_void>(),
                    &credentials as *const _ as *const c_void,
                    dummy,
                    null::<c_void>(),
                    &mut cred_handle,
                    null_mut(),
                )
            };
            assert_eq!(status, 0);

            let status = unsafe { FreeCredentialsHandle(&mut cred_handle) };
            assert_eq!(status, 0);
        }
    }

    /// This test simulates initialize security context function call. It's better to run it using Miri
    /// https://github.com/rust-lang/miri
    /// cargo +nightly miri test
    #[test]
    fn acquire_credentials_handle_w_empty_credentials() {
        let pkg_name = "NTLM\0".encode_utf16().collect::<Vec<_>>();

        let user = "".encode_utf16().collect::<Vec<_>>();
        let domain = "".encode_utf16().collect::<Vec<_>>();
        let password = "".encode_utf16().collect::<Vec<_>>();

        let credentials = SecWinntAuthIdentityW {
            user: user.as_ptr(),
            user_length: user.len() as u32,
            domain: domain.as_ptr(),
            domain_length: domain.len() as u32,
            password: password.as_ptr(),
            password_length: password.len() as u32,
            flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
        };

        let mut cred_handle = SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        };

        let status = unsafe {
            AcquireCredentialsHandleW(
                null_mut(),
                pkg_name.as_ptr() as *const _,
                2, /* SECPKG_CRED_OUTBOUND */
                null::<c_void>(),
                &credentials as *const _ as *const c_void,
                dummy,
                null::<c_void>(),
                &mut cred_handle,
                null_mut(),
            )
        };
        assert_eq!(status, 0);

        let status = unsafe { FreeCredentialsHandle(&mut cred_handle) };
        assert_eq!(status, 0);
    }

    /// This test simulates initialize security context function call. It's better to run it using Miri
    /// https://github.com/rust-lang/miri
    /// cargo +nightly miri test
    #[test]
    fn acquire_credentials_handle_a_null_credentials() {
        let pkg_name = "NTLM\0";

        let user = "user";
        let domain = "domain";
        let password = "password";

        let credentials = vec![
            SecWinntAuthIdentityA {
                user: null(),
                user_length: 0,
                domain: domain.as_ptr() as *const _,
                domain_length: domain.len() as u32,
                password: password.as_ptr() as *const _,
                password_length: password.len() as u32,
                flags: SEC_WINNT_AUTH_IDENTITY_ANSI,
            },
            SecWinntAuthIdentityA {
                user: user.as_ptr() as *const _,
                user_length: user.len() as u32,
                domain: null(),
                domain_length: 0,
                password: password.as_ptr() as *const _,
                password_length: password.len() as u32,
                flags: SEC_WINNT_AUTH_IDENTITY_ANSI,
            },
            SecWinntAuthIdentityA {
                user: user.as_ptr() as *const _,
                user_length: user.len() as u32,
                domain: domain.as_ptr() as *const _,
                domain_length: domain.len() as u32,
                password: null(),
                password_length: 0,
                flags: SEC_WINNT_AUTH_IDENTITY_ANSI,
            },
        ];

        for credentials in credentials {
            let mut cred_handle = SecHandle {
                dw_lower: 0,
                dw_upper: 0,
            };

            let status = unsafe {
                AcquireCredentialsHandleA(
                    null_mut(),
                    pkg_name.as_ptr() as *const _,
                    2, /* SECPKG_CRED_OUTBOUND */
                    null::<c_void>(),
                    &credentials as *const _ as *const c_void,
                    dummy,
                    null::<c_void>(),
                    &mut cred_handle,
                    null_mut(),
                )
            };
            assert_eq!(status, 0);

            let status = unsafe { FreeCredentialsHandle(&mut cred_handle) };
            assert_eq!(status, 0);
        }
    }

    /// This test simulates initialize security context function call. It's better to run it using Miri
    /// https://github.com/rust-lang/miri
    /// cargo +nightly miri test
    #[test]
    fn acquire_credentials_handle_a_empty_credentials() {
        let pkg_name = "NTLM\0";

        let user = "";
        let domain = "";
        let password = "";

        let credentials = SecWinntAuthIdentityA {
            user: user.as_ptr() as *const _,
            user_length: user.len() as u32,
            domain: domain.as_ptr() as *const _,
            domain_length: domain.len() as u32,
            password: password.as_ptr() as *const _,
            password_length: password.len() as u32,
            flags: SEC_WINNT_AUTH_IDENTITY_ANSI,
        };

        let mut cred_handle = SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        };

        let status = unsafe {
            AcquireCredentialsHandleA(
                null_mut(),
                pkg_name.as_ptr() as *const _,
                2, /* SECPKG_CRED_OUTBOUND */
                null::<c_void>(),
                &credentials as *const _ as *const c_void,
                dummy,
                null::<c_void>(),
                &mut cred_handle,
                null_mut(),
            )
        };
        assert_eq!(status, 0);

        let status = unsafe { FreeCredentialsHandle(&mut cred_handle) };
        assert_eq!(status, 0);
    }
}
