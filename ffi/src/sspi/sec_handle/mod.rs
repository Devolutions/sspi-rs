#[cfg(test)]
#[expect(
    clippy::undocumented_unsafe_blocks,
    reason = "undocumented unsafe is acceptable in tests"
)]
mod tests;

use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, c_ulonglong};
use std::mem::size_of;
use std::ptr::{self, NonNull, copy_nonoverlapping};
use std::slice::from_raw_parts;
use std::sync::{LazyLock, Mutex};

use libc::c_void;
use num_traits::{FromPrimitive, ToPrimitive};
use sha2::{Digest, Sha256};
#[cfg(feature = "scard")]
use sspi::SmartCardType;
use sspi::builders::ChangePasswordBuilder;
use sspi::credssp::SspiContext;
#[cfg(feature = "tsssp")]
use sspi::credssp::sspi_cred_ssp;
#[cfg(feature = "tsssp")]
use sspi::credssp::sspi_cred_ssp::SspiCredSsp;
use sspi::kerberos::config::KerberosConfig;
use sspi::ntlm::NtlmConfig;
use sspi::{
    CertContext, ClientRequestFlags, ConnectionInfo, Credentials, CredentialsBuffers, DataRepresentation, Error,
    ErrorKind, KdcResolution, Kerberos, Negotiate, NegotiateConfig, Ntlm, PackageInfo, Result, Secret, Sspi, SspiImpl,
    StreamSizes, U16CString, Utf16String, Utf16StringExt, kerberos, negotiate, ntlm, pku2u,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_QUERY_ENCODING_TYPE, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_CREATE_NEW_FLAG,
    CERT_STORE_PROV_MEMORY, CertAddEncodedCertificateToStore, CertOpenStore,
};

cfg_if::cfg_if! {
    if #[cfg(target_os = "windows")] {
        use symbol_rename_macro::rename_symbol;
        use sspi::{Pku2u, Pku2uConfig};
    }
}

pub use ffi_types::sspi::{
    AcquireCredentialsHandleFnA, AcquireCredentialsHandleFnW, AddCredentialsFnA, AddCredentialsFnW,
    ChangeAccountPasswordFnA, ChangeAccountPasswordFnW, ImportSecurityContextFnA, ImportSecurityContextFnW,
    InitializeSecurityContextFnA, InitializeSecurityContextFnW, PCredHandle, PCtxtHandle, QueryContextAttributesExFnA,
    QueryContextAttributesExFnW, QueryContextAttributesFnA, QueryContextAttributesFnW, QueryCredentialsAttributesExFnA,
    QueryCredentialsAttributesExFnW, QueryCredentialsAttributesFnA, QueryCredentialsAttributesFnW,
    SECPKG_ATTR_CERT_TRUST_STATUS, SECPKG_ATTR_CONNECTION_INFO, SECPKG_ATTR_NAMES, SECPKG_ATTR_NEGOTIATION_INFO,
    SECPKG_ATTR_NEGOTIATION_PACKAGE, SECPKG_ATTR_PACKAGE_INFO, SECPKG_ATTR_REMOTE_CERT_CONTEXT,
    SECPKG_ATTR_SERVER_AUTH_FLAGS, SECPKG_ATTR_SESSION_KEY, SECPKG_ATTR_SIZES, SECPKG_ATTR_STREAM_SIZES,
    SECPKG_NEGOTIATION_COMPLETE, SECPKG_NEGOTIATION_IN_PROGRESS, SECPKG_NEGOTIATION_OPTIMISTIC, SecHandle,
    SetContextAttributesFnA, SetContextAttributesFnW, SetCredentialsAttributesFnA, SetCredentialsAttributesFnW,
};
use ffi_types::sspi::{
    CertTrustStatus, LpStr, LpcWStr, PSecurityString, PTimeStamp, SecChar, SecGetKeyFn, SecPkgContextConnectionInfo,
    SecPkgContextFlags, SecPkgContextNamesA, SecPkgContextNamesW, SecPkgContextSessionKey, SecPkgContextSizes,
    SecPkgContextStreamSizes, SecWChar, SecurityStatus,
};

use super::credentials_attributes::{
    CredentialsAttributes, SecPkgCredentialsKdcUrlA, SecPkgCredentialsKdcUrlW, extract_kdc_proxy_settings,
};
use super::sec_buffer::{
    PSecBuffer, PSecBufferDesc, copy_to_c_sec_buffer, p_sec_buffers_to_security_buffers,
    sec_buffer_desc_to_security_buffers,
};
use super::sec_pkg_info::{RawSecPkgInfoA, RawSecPkgInfoW, SecNegoInfoA, SecNegoInfoW, SecPkgInfoA, SecPkgInfoW};
use super::sec_winnt_auth_identity::auth_data_to_identity_buffers;
use super::utils::{hostname, log_sec_handle};
use crate::utils::into_raw_ptr;

// Sets the name of a credential
// In our library, we use this attribute to set the workstation for auth identity
const SECPKG_CRED_ATTR_NAMES: u32 = 1;
// Sets the Kerberos proxy setting
const SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS: u32 = 3;

const SECPKG_CRED_ATTR_KDC_URL: u32 = 501;

/// Identifies the security package a security context handle belongs to.
///
/// This value is written into the [SecHandle::dw_lower] field of every security context handle.
/// Callers may compare it against the handle returned by a previous connection, so it must be the same
/// for every context of a given package and stable for the whole process lifetime. Per-context
/// state lives in [SecHandle::dw_upper] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPackageId {
    Ntlm,
    Kerberos,
    Negotiate,
    Pku2u,
    #[cfg(feature = "tsssp")]
    CredSsp,
}

impl SecurityPackageId {
    #[instrument(level = "debug", ret)]
    pub fn from_package_name(package_name: &str) -> Result<Self> {
        match package_name {
            ntlm::PKG_NAME => Ok(Self::Ntlm),
            kerberos::PKG_NAME => Ok(Self::Kerberos),
            negotiate::PKG_NAME => Ok(Self::Negotiate),
            pku2u::PKG_NAME => Ok(Self::Pku2u),
            #[cfg(feature = "tsssp")]
            sspi_cred_ssp::PKG_NAME => Ok(Self::CredSsp),
            _ => Err(Error::new(
                ErrorKind::SecurityPackageNotFound,
                format!("security package name `{package_name}` is not supported"),
            )),
        }
    }
}

impl From<SecurityPackageId> for c_ulonglong {
    fn from(value: SecurityPackageId) -> Self {
        match value {
            SecurityPackageId::Ntlm => 1,
            SecurityPackageId::Kerberos => 2,
            SecurityPackageId::Negotiate => 3,
            SecurityPackageId::Pku2u => 4,
            #[cfg(feature = "tsssp")]
            SecurityPackageId::CredSsp => 5,
        }
    }
}

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

    fn initialize_security_context_impl<'ctx, 'b, 'g>(
        &'ctx mut self,
        builder: &'b mut sspi::builders::FilledInitializeSecurityContext<'ctx, 'ctx, Self::CredentialsHandle>,
    ) -> Result<sspi::generator::GeneratorInitSecurityContext<'g>>
    where
        'ctx: 'g,
        'b: 'g,
    {
        let mut context = self.sspi_context.lock()?;
        Ok(context.initialize_security_context_sync(builder).into())
    }

    fn accept_security_context_impl(
        &mut self,
        builder: sspi::builders::FilledAcceptSecurityContext<'_, Self::CredentialsHandle>,
    ) -> Result<sspi::generator::GeneratorAcceptSecurityContext<'_>> {
        let mut context = self.sspi_context.lock()?;
        Ok(context.accept_security_context_sync(builder).into())
    }
}

impl Sspi for SspiHandle {
    fn complete_auth_token(&mut self, token: &mut [sspi::SecurityBuffer]) -> Result<sspi::SecurityStatus> {
        self.sspi_context.lock()?.complete_auth_token(token)
    }

    fn encrypt_message(
        &mut self,
        flags: sspi::EncryptionFlags,
        message: &mut [sspi::SecurityBufferRef<'_>],
    ) -> Result<sspi::SecurityStatus> {
        self.sspi_context.lock()?.encrypt_message(flags, message)
    }

    fn decrypt_message(&mut self, message: &mut [sspi::SecurityBufferRef<'_>]) -> Result<sspi::DecryptionFlags> {
        self.sspi_context.lock()?.decrypt_message(message)
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

    fn query_context_session_key(&self) -> Result<sspi::SessionKeys> {
        self.sspi_context.lock()?.query_context_session_key()
    }

    fn change_password<'a>(
        &'a mut self,
        change_password: sspi::builders::ChangePassword<'a>,
    ) -> Result<sspi::generator::GeneratorChangePassword<'a>> {
        let mut context = self.sspi_context.lock()?;
        Ok(context.change_password_sync(change_password).into())
    }

    fn make_signature(
        &mut self,
        _flags: u32,
        _message: &mut [sspi::SecurityBufferRef<'_>],
        _sequence_number: u32,
    ) -> Result<()> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "make_signature is not supported",
        ))
    }

    fn verify_signature(&mut self, _message: &mut [sspi::SecurityBufferRef<'_>], _sequence_number: u32) -> Result<u32> {
        Err(Error::new(
            ErrorKind::UnsupportedFunction,
            "verify_signature is not supported",
        ))
    }
}

#[derive(Clone)]
pub struct CredentialsHandle {
    pub credentials: CredentialsBuffers,
    pub security_package_name: String,
    pub attributes: CredentialsAttributes,
}

impl CredentialsHandle {
    fn fingerprint(&self, salt: &[u8; 32]) -> [u8; 32] {
        fn add_bytes(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update(bytes.len().to_le_bytes());
            hasher.update(bytes);
        }

        let mut hasher = Sha256::new();
        hasher.update(salt);
        add_bytes(&mut hasher, self.security_package_name.as_bytes());
        match &self.credentials {
            CredentialsBuffers::AuthIdentity(identity) => {
                hasher.update([0]);
                add_bytes(&mut hasher, identity.user.as_bytes_le());
                add_bytes(&mut hasher, identity.domain.as_bytes_le());
                add_bytes(&mut hasher, identity.password.as_ref().0.as_bytes_le());
            }
            #[cfg(feature = "scard")]
            CredentialsBuffers::SmartCard(identity) => {
                hasher.update([1]);
                add_bytes(&mut hasher, identity.username.as_bytes_le());
                add_bytes(&mut hasher, identity.certificate.as_ref());
                for field in [&identity.card_name, &identity.container_name] {
                    match field {
                        Some(value) => {
                            hasher.update([1]);
                            add_bytes(&mut hasher, value.as_ref().as_bytes_le());
                        }
                        None => hasher.update([0]),
                    }
                }
                add_bytes(&mut hasher, identity.reader_name.as_bytes_le());
                add_bytes(&mut hasher, identity.csp_name.as_bytes_le());
                add_bytes(&mut hasher, identity.pin.as_ref().0.as_bytes_le());
                if let Some(key) = &identity.private_key_pem {
                    hasher.update([1]);
                    add_bytes(&mut hasher, key.as_ref().as_ref().0.as_bytes_le());
                } else {
                    hasher.update([0]);
                }
                match &identity.scard_type {
                    SmartCardType::Emulated { scard_pin } => {
                        hasher.update([0]);
                        add_bytes(&mut hasher, scard_pin.as_ref());
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    SmartCardType::SystemProvided { pkcs11_module_path } => {
                        hasher.update([1]);
                        add_bytes(&mut hasher, pkcs11_module_path.as_os_str().as_encoded_bytes());
                    }
                    #[cfg(target_os = "windows")]
                    SmartCardType::WindowsNative => hasher.update([2]),
                }
            }
            CredentialsBuffers::Keytab(identity) => {
                hasher.update([2]);
                add_bytes(&mut hasher, identity.principal.inner().as_bytes());
                add_bytes(&mut hasher, identity.key.as_ref());
                add_bytes(&mut hasher, format!("{:?}", identity.key_enctype).as_bytes());
            }
        }

        hasher.finalize().into()
    }
}

struct CredentialsEntry {
    credentials: CredentialsHandle,
    fingerprint: [u8; 32],
}

#[derive(Default)]
struct CredentialsRegistry {
    live: HashMap<c_ulonglong, CredentialsEntry>,
    released: VecDeque<([u8; 32], c_ulonglong)>,
    salt: Option<[u8; 32]>,
    next_handle: c_ulonglong,
}

const MAX_RELEASED_CREDENTIALS: usize = 128;

impl CredentialsRegistry {
    fn register(&mut self, credentials: CredentialsHandle) -> Result<c_ulonglong> {
        let salt = match self.salt {
            Some(salt) => salt,
            None => {
                let mut salt = [0; 32];
                getrandom::fill(&mut salt).map_err(|error| {
                    Error::new(
                        ErrorKind::InternalError,
                        format!("Cannot seed credentials cache: {error}"),
                    )
                })?;
                self.salt = Some(salt);
                salt
            }
        };
        let fingerprint = credentials.fingerprint(&salt);
        let handle = if let Some(index) = self.released.iter().rposition(|(key, _)| key == &fingerprint) {
            self.released
                .remove(index)
                .expect("index points to a released handle")
                .1
        } else {
            self.next_handle = self
                .next_handle
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::InternalError, "credentials handle space exhausted"))?;
            self.next_handle
        };

        self.live.insert(
            handle,
            CredentialsEntry {
                credentials,
                fingerprint,
            },
        );
        Ok(handle)
    }

    fn release(&mut self, handle: c_ulonglong) -> bool {
        let Some(entry) = self.live.remove(&handle) else {
            return false;
        };
        if self.released.len() >= MAX_RELEASED_CREDENTIALS {
            self.released.pop_front();
        }
        self.released.push_back((entry.fingerprint, handle));
        true
    }
}

/// Credentials handles keyed by the raw value written into [`SecHandle::dw_lower`].
///
/// A released handle can be reused for the same credentials during reconnection, but simultaneous
/// acquisitions must not share credentials or attributes. Only the most recently released handles
/// are retained, without storing the credentials themselves.
static CREDENTIALS: LazyLock<Mutex<CredentialsRegistry>> = LazyLock::new(|| Mutex::new(CredentialsRegistry::default()));

/// Registers `credentials` and returns their raw handle value.
pub(crate) fn register_credentials(credentials: CredentialsHandle) -> Result<c_ulonglong> {
    CREDENTIALS.lock()?.register(credentials)
}

/// Returns a copy of the credentials registered under `handle`.
pub(crate) fn credentials_by_handle(handle: c_ulonglong) -> Result<Option<CredentialsHandle>> {
    Ok(CREDENTIALS
        .lock()?
        .live
        .get(&handle)
        .map(|entry| entry.credentials.clone()))
}

/// Applies `update` to the attributes of the credentials registered under `handle`.
///
/// Returns `false` when nothing is registered under `handle`.
pub(crate) fn update_credentials_attributes(
    handle: c_ulonglong,
    update: impl FnOnce(&mut CredentialsAttributes),
) -> Result<bool> {
    Ok(CREDENTIALS
        .lock()?
        .live
        .get_mut(&handle)
        .map(|entry| update(&mut entry.credentials.attributes))
        .is_some())
}

/// Releases a credential while retaining only its fingerprint and handle for reconnection.
///
/// Returns `false` when nothing is registered under `handle`.
pub(crate) fn release_credentials(handle: c_ulonglong) -> Result<bool> {
    Ok(CREDENTIALS.lock()?.release(handle))
}

fn create_negotiate_context(attributes: &CredentialsAttributes) -> Result<Negotiate> {
    let client_computer_name = attributes.hostname()?;

    let negotiate_config = if let Some(kdc_url) = attributes.kdc_url() {
        let kerberos_config = KerberosConfig::new_with_kdc_url(&kdc_url, client_computer_name.clone());

        NegotiateConfig::new(
            Box::new(kerberos_config),
            attributes.package_list.clone(),
            client_computer_name,
        )
    } else {
        NegotiateConfig {
            protocol_config: Box::new(NtlmConfig::new(client_computer_name.clone())),
            package_list: attributes.package_list.clone(),
            client_computer_name,
        }
    };

    Negotiate::new_client(negotiate_config)
}

/// Transforms [&mut PCtxtHandle] to [*mut SspiHandle].
///
/// *Note*: `*context` **can** be NULL: the function will create a new security context if [PCtxHandle] is NULL.
///
/// # Safety
///
/// The caller have to ensure that either `*(context)` is null or the pointer is [convertible to a reference](https://doc.rust-lang.org/std/ptr/index.html#pointer-to-reference-conversion).
#[instrument(ret)]
pub(crate) unsafe fn p_ctxt_handle_to_sspi_context(
    context: &mut PCtxtHandle,
    security_package_name: Option<&str>,
    attributes: &CredentialsAttributes,
) -> Result<NonNull<SspiHandle>> {
    if (*context).is_null() {
        *context = into_raw_ptr(SecHandle {
            dw_lower: 0,
            dw_upper: 0,
        });
    }

    // SAFETY: `*context` is guaranteed to be non-null due to the prior check.
    if unsafe { (*(*context)).dw_upper } == 0 {
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
                    SspiContext::Kerberos(Kerberos::new_client_from_config(KerberosConfig::new_with_kdc_url(
                        &kdc_url,
                        client_computer_name,
                    ))?)
                } else {
                    let krb_config = KerberosConfig {
                        client_computer_name,
                        kdc_resolution: KdcResolution::KdcUrl(None),
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
                    format!("security package name `{name}` is not supported"),
                ));
            }
        });

        // SAFETY: `*context` is convertible to a reference.
        let context = unsafe { (*context).as_mut() }.expect("context should not be null");

        context.dw_lower = SecurityPackageId::from_package_name(name)?.into();
        context.dw_upper = into_raw_ptr(sspi_context).expose_provenance().try_into()?;

        debug!(?context);
    }

    // SAFETY: `*context` is guaranteed to be non-null due to the prior check.
    let dw_upper = unsafe { &**context }.dw_upper;
    let addr = usize::try_from(dw_upper)?;
    Ok(NonNull::new(ptr::with_exposed_provenance_mut(addr)).expect("dw_upper must be initialized"))
}

fn verify_security_package(package_name: &str) -> Result<()> {
    match package_name {
        negotiate::PKG_NAME | pku2u::PKG_NAME | kerberos::PKG_NAME | ntlm::PKG_NAME => Ok(()),
        #[cfg(feature = "tsssp")]
        sspi_cred_ssp::PKG_NAME => Ok(()),
        _ => Err(Error::new(
            ErrorKind::SecurityPackageNotFound,
            format!("security package name `{package_name}` is not supported"),
        )),
    }
}

/// The `AcquireCredentialsHandleA` function acquires a handle to preexisting credentials of a security principal.
///
/// NOTE: Although in the original Windows SSPI, `p_auth_data` parameter can be NULL, in our implementation it must be non-NULL.
/// That's because we cannot get the default credentials handle for security package, like Windows can.
///
/// [MSDN Reference](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acquirecredentialshandlea)
///
/// # Safety
///
/// `psz_package` must be a non-null pointer to a valid, null-terminated C string representing the security package name.
/// `p_auth_data` must be a non-null pointer to a valid credentials structure corresponding to the security package in use.
/// `ph_credentials` must be a non-null pointer to a valid `SecHandle` structure.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_AcquireCredentialsHandleA"))]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn AcquireCredentialsHandleA(
    _psz_principal: LpStr,
    psz_package: LpStr,
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

        let security_package_name =
            // SAFETY:
            // - `psz_package` is guaranteed to be non-null due to the prior check.
            // - The memory region `psz_package` contains a valid null-terminator at the end of string.
            // - The memory region `psz_package` points to is valid for reads of bytes up to and including null-terminator.
            try_execute!(unsafe { CStr::from_ptr(psz_package) }.to_str(), ErrorKind::InvalidParameter).to_owned();

        try_execute!(verify_security_package(&security_package_name));

        debug!(?security_package_name);

        let mut package_list: Option<String> = None;

        let credentials = try_execute!(
            // SAFETY: `p_auth_data` is non-null pointer to a valid credentials structure.
            unsafe { auth_data_to_identity_buffers(&security_package_name, p_auth_data, &mut package_list) }
        );

        let handle = try_execute!(register_credentials(CredentialsHandle {
            credentials,
            security_package_name,
            attributes: CredentialsAttributes::new_with_package_list(package_list),
        }));
        // SAFETY: `ph_credentials` is guaranteed to be non-null due to the prior check.
        unsafe {
            (*ph_credential).dw_lower = handle;
        }
        // We do not use `dw_upper` for the credentials handle, so we reset the field.
        // SAFETY: `ph_credentials` is guaranteed to be non-null due to the prior check.
        unsafe {
            (*ph_credential).dw_upper = 0;
        }

        // SAFETY: `ph_credential` is guaranteed to be non-null due to the prior check.
        unsafe { log_sec_handle("AcquireCredentialsHandleA: acquired credentials handle", ph_credential) };

        0
    }
}

/// The `AcquireCredentialsHandleW` function acquires a handle to preexisting credentials of a security principal.
///
/// NOTE: Although in the original Windows SSPI, `p_auth_data` parameter can be NULL, in our implementation it must be non-NULL.
/// That's because we cannot get the default credentials handle for security package, like Windows can.
///
/// [MSDN Reference](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acquirecredentialshandlew)
///
/// # Safety
///
/// - `psz_package` must be a non-null pointer to a valid, null-terminated C string representing the security package name.
///    Must be properly aligned for `u16`.
/// - `p_auth_data` must be a non-null pointer to a valid credentials structure corresponding to the security package in use.
/// - `ph_credentials` must be a non-null pointer to a valid `SecHandle` structure.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_AcquireCredentialsHandleW"))]
#[unsafe(no_mangle)]
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

        let security_package_name = try_execute!(
            // SAFETY:
            // - `psz_package` is guaranteed to be non-null due to the prior check.
            // - The memory region `psz_package` contains a valid null-terminator at the end of string.
            // - The memory region `psz_package` points to is valid for reads of `u16` code units up to and including null-terminator.
            // - `psz_package` is properly aligned for `u16`, per the safety preconditions.
            unsafe { U16CString::from_ptr_str(psz_package) }.to_string().map_err(Error::from)
        );
        try_execute!(verify_security_package(&security_package_name));

        debug!(?security_package_name);

        let mut package_list: Option<String> = None;

        let credentials = try_execute!(
            // SAFETY: `p_auth_data` is non-null pointer to a valid credentials structure.
            unsafe { auth_data_to_identity_buffers(&security_package_name, p_auth_data, &mut package_list) }
        );

        let handle = try_execute!(register_credentials(CredentialsHandle {
            credentials,
            security_package_name,
            attributes: CredentialsAttributes::new_with_package_list(package_list),
        }));
        // SAFETY: `ph_credentials` is guaranteed to be non-null due to the prior check.
        unsafe {
            (*ph_credential).dw_lower = handle;
        }
        // We do not use `dw_upper` for the credentials handle, so we reset the field.
        // SAFETY: `ph_credentials` is guaranteed to be non-null due to the prior check.
        unsafe {
            (*ph_credential).dw_upper = 0;
        }

        // SAFETY: `ph_credential` is guaranteed to be non-null due to the prior check.
        unsafe { log_sec_handle("AcquireCredentialsHandleW: acquired credentials handle", ph_credential) };

        0
    }
}

/// # Safety
///
/// `ph_credential` must be null or a valid pointer to a `SecHandle` structure.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryCredentialsAttributesA"))]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn QueryCredentialsAttributesA(
    ph_credential: PCredHandle,
    ul_attribute: u32,
    _p_buffer: *mut c_void,
) -> SecurityStatus {
    // SAFETY: `ph_credential` is either null or a valid pointer to a `SecHandle`, per the safety preconditions.
    unsafe { log_sec_handle("QueryCredentialsAttributesA", ph_credential) };
    debug!(ul_attribute);

    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

/// # Safety
///
/// `ph_credential` must be null or a valid pointer to a `SecHandle` structure.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryCredentialsAttributesW"))]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn QueryCredentialsAttributesW(
    ph_credential: PCredHandle,
    ul_attribute: u32,
    _p_buffer: *mut c_void,
) -> SecurityStatus {
    // SAFETY: `ph_credential` is either null or a valid pointer to a `SecHandle`, per the safety preconditions.
    unsafe { log_sec_handle("QueryCredentialsAttributesW", ph_credential) };
    debug!(ul_attribute);

    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

/// The `InitializeSecurityContextA` function initiates the client side, outbound `security context` from
/// a credential handle. The function is used to build a security context between the client application
/// and a remote peer. `InitializeSecurityContextA` returns a token that the client must pass to the remote peer,
/// which the peer in turn submits to the local security implementation through the `AcceptSecurityContext` call.
/// The token generated should be considered opaque by all callers.
///
/// [MSDN Reference](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initializesecuritycontexta)
///
/// # Safety
///
/// - `ph_credentials` must be a non-null, valid pointer to a credentials handle, allocated by either [`AcquireCredentialsHandleA`]
///   or [`AcquireCredentialsHandleW`].
/// - `ph_context` must be a valid pointer to a `SecHandle` structure.
///   If `dw_lower` and `dw_upper` fields are non-zero, then they must point to a memory that was allocated by an SSPI function.
/// - `p_target_name` must be a non-null pointer to a valid, null-terminated C string representing the target name.
/// - `p_input` must be a non-null, properly-aligned pointer to a valid `SecBufferDesc` structure that is [convertible to a reference](https://doc.rust-lang.org/std/ptr/index.html#pointer-to-reference-conversion)
/// - `ph_new_context` must be a non-null, properly-aligned pointer to a valid `SecHandle` structure that is [convertible to a reference](https://doc.rust-lang.org/std/ptr/index.html#pointer-to-reference-conversion)
/// - `p_output` must be a non-null, properly-aligned pointer to a valid `SecBufferDesc` structure.
///   It must contain enough buffers, and each buffer must have enough space to hold the output tokens.
/// - `pf_context_attr` must be a non-null, properly-aligned pointer to a `u32` value.
#[allow(clippy::useless_conversion)]
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_InitializeSecurityContextA"))]
#[unsafe(no_mangle)]
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

        // SAFETY: `p_output` is guaranteed to be non-null due to the prior check.
        let p_output_buffers = unsafe { (*p_output).p_buffers };
        check_null!(p_output_buffers);

        let service_principal = if p_target_name.is_null() {
            ""
        } else {
            // SAFETY:
            // - `p_target_name` is guaranteed to be non-null due to the prior check.
            // - The memory region `p_target_name` contains a valid null-terminator at the end of string.
            // - The memory region `p_target_name` points to is valid for reads of bytes up to and including null-terminator.
            try_execute!(unsafe { CStr::from_ptr(p_target_name) }.to_str(), ErrorKind::InvalidParameter)
        };
        debug!(?service_principal, "Target name (SPN)");

        // SAFETY: `ph_credentials` is guaranteed to be non-null due to the prior check.
        let dw_lower = unsafe { (*ph_credential).dw_lower };

        let CredentialsHandle { credentials: auth_data, security_package_name, attributes } =
            match try_execute!(credentials_by_handle(dw_lower)) {
                Some(creds_handle) => creds_handle,
                None => return ErrorKind::InvalidHandle.to_u32().unwrap(),
            };

        let mut sspi_context_ptr = try_execute!(
            // SAFETY:
            // - `ph_context` is either null or convertible to a reference.
            // - The values behind `ph_context.dw_lower` and `ph_context.dw_upper` pointers are allocated by an SSPI function.
            unsafe { p_ctxt_handle_to_sspi_context(
                &mut ph_context,
                Some(security_package_name.as_str()),
                &attributes
            )}
        );

        // SAFETY: `sspi_context_ptr` is a valid, local pointer to the `SspiHandle` allocated by the `p_ctx_handle_to_sspi_context`.
        let sspi_context = unsafe { sspi_context_ptr.as_mut() };

        // SAFETY: `p_input` is either null or a pointer to a valid `SecBufferDesc` structure convertible to a reference.
        let input_tokens = unsafe { sec_buffer_desc_to_security_buffers(p_input) };
        let mut input_tokens = try_execute!(input_tokens);

        // SAFETY: `p_output` is guaranteed to be non-null due to the prior check.
        let len = unsafe { (*p_output).c_buffers };
        let len = try_execute!(len.try_into(), ErrorKind::InvalidParameter);

        // SAFETY:
        // - `p_output_buffers` is guaranteed to be non-null due to the prior check.
        // - The memory region `p_output_buffers` points to is valid for reads of `len` elements.
        let raw_buffers = unsafe { from_raw_parts(p_output_buffers, len) };

        // SAFETY:
        // - `raw_buffers` array contains valid `SecBuffer` structures.
        // - Each `SecBuffer` have a valid `pv_buffer` pointer that is valid for reads of `cb_buffer` bytes.
        let output_tokens = unsafe { p_sec_buffers_to_security_buffers(raw_buffers) };
        let mut output_tokens = try_execute!(output_tokens);
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

        // SAFETY:
        // - `p_buffers` is a valid pointer to an array of security buffers.
        // - The memory region `p_buffers` points to is valid for writes of `from_buffers.len()` elements.
        // - For each element in the `p_buffers` array, the `pv_buffer` pointer points to a valid memory,
        //   that is valid for writes of `cb_buffer` bytes.
        try_execute!(unsafe { copy_to_c_sec_buffer(p_output_buffers, &output_tokens, allocate) });

        // SAFETY: `ph_new_context` is convertible to a reference.
        let new_context = unsafe { ph_new_context.as_mut() }.expect("ph_new_context is non-null");

        let dw_upper = sspi_context_ptr.as_ptr().expose_provenance();
        new_context.dw_upper = try_execute!(dw_upper.try_into(), ErrorKind::InvalidHandle);
        // SAFETY:
        // `ph_context` is guaranteed to be non-null since it is initialized in the `p_ctxt_handle_to_sspi_context`
        // if it was previously null.
        new_context.dw_lower = unsafe { (*ph_context).dw_lower };

        // SAFETY: `pf_context_attr` is guaranteed to be non-null due to the prior check.
        unsafe { *pf_context_attr = f_context_req; }

        let result = try_execute!(result_status);
        result.status.to_u32().unwrap()
    }
}

/// The `InitializeSecurityContextW` function initiates the client side, outbound `security context` from
/// a credential handle. The function is used to build a security context between the client application
/// and a remote peer. `InitializeSecurityContextW` returns a token that the client must pass to the remote peer,
/// which the peer in turn submits to the local security implementation through the `AcceptSecurityContext` call.
/// The token generated should be considered opaque by all callers.
///
/// [MSDN Reference](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initializesecuritycontextw)
///
/// # Safety
///
/// - `ph_credentials` must be a non-null, valid pointer to a credentials handle, allocated by either [`AcquireCredentialsHandleA`]
///   or [`AcquireCredentialsHandleW`].
/// - `ph_context` must be a valid pointer to a `SecHandle` structure.
///   If `dw_lower` and `dw_upper` fields are non-zero, then they must point to a memory that was allocated by an SSPI function.
/// - `p_target_name` must be a non-null pointer to a valid, null-terminated C string representing the target name.
///    Must be properly aligned for `u16`.
/// - `p_input` must be a non-null, properly-aligned pointer to a valid `SecBufferDesc` structure that is [convertible to a reference](https://doc.rust-lang.org/std/ptr/index.html#pointer-to-reference-conversion)
/// - `ph_new_context` must be a non-null, properly-aligned pointer to a valid `SecHandle` structure that is [convertible to a reference](https://doc.rust-lang.org/std/ptr/index.html#pointer-to-reference-conversion)
/// - `p_output` must be a non-null, properly-aligned pointer to a valid `SecBufferDesc` structure.
///   It must contain enough buffers, and each buffer must have enough space to hold the output tokens.
/// - `pf_context_attr` must be a non-null, properly-aligned pointer to a `u32` value.
#[allow(clippy::useless_conversion)]
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_InitializeSecurityContextW"))]
#[unsafe(no_mangle)]
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

        // SAFETY: `p_output` is guaranteed to be non-null due to the prior check.
        let p_output_buffers = unsafe { (*p_output).p_buffers };
        check_null!(p_output_buffers);

        let service_principal = if p_target_name.is_null() {
            String::new()
        } else {
            try_execute!(
                // SAFETY:
                // - `p_target_name` is guaranteed to be non-null due to the prior check.
                // - The memory region `p_target_name` contains a valid null-terminator at the end of string.
                // - The memory region `p_target_name` points to is valid for reads of bytes up to and including null-terminator.
                // - `p_target_name` is properly aligned for `u16`, per the safety preconditions.
                unsafe { U16CString::from_ptr_str(p_target_name) }.to_string().map_err(Error::from)
            )
        };
        debug!(?service_principal, "Target name (SPN)");

        // SAFETY: `ph_credentials` is guaranteed to be non-null due to the prior check.
        let dw_lower = unsafe { (*ph_credential).dw_lower };

        let CredentialsHandle { credentials: auth_data, security_package_name, attributes } =
            match try_execute!(credentials_by_handle(dw_lower)) {
                Some(creds_handle) => creds_handle,
                None => return ErrorKind::InvalidHandle.to_u32().unwrap(),
            };

        let mut sspi_context_ptr = try_execute!(
            // SAFETY:
            // - `ph_context` is either null or convertible to a reference.
            // - The values behind `ph_context.dw_lower` and `ph_context.dw_upper` pointers are allocated by an SSPI function.
            unsafe { p_ctxt_handle_to_sspi_context(
                &mut ph_context,
                Some(security_package_name.as_str()),
                &attributes,
            )}
        );

        // SAFETY: `sspi_context_ptr` is a valid, local pointer to the `SspiHandle` allocated by the `p_ctx_handle_to_sspi_context`.
        let sspi_context = unsafe { sspi_context_ptr.as_mut() };

        // SAFETY: `p_input` is either null or a pointer to a valid `SecBufferDesc` structure convertible to a reference.
        let input_tokens = unsafe { sec_buffer_desc_to_security_buffers(p_input) };
        let mut input_tokens = try_execute!(input_tokens);

        // SAFETY: `p_output` is guaranteed to be non-null due to the prior check.
        let len = unsafe { (*p_output).c_buffers };
        let len = try_execute!(len.try_into(), ErrorKind::InvalidParameter);

        // SAFETY:
        // - `p_output_buffers` is guaranteed to be non-null due to the prior check.
        // - The memory region `p_output_buffers` points to is valid for reads of `len` elements.
        let raw_buffers = unsafe { from_raw_parts(p_output_buffers, len) };

        // SAFETY:
        // - `raw_buffers` array contains valid `SecBuffer` structures.
        // - Each `SecBuffer` have a valid `pv_buffer` pointer that is valid for reads of `cb_buffer` bytes.
        let output_tokens = unsafe { p_sec_buffers_to_security_buffers(raw_buffers) };
        let mut output_tokens = try_execute!(output_tokens);
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

        try_execute!(
            // SAFETY:
            // - `p_buffers` is a valid pointer to an array of security buffers.
            // - The memory region `p_buffers` points to is valid for writes of `from_buffers.len()` elements.
            // - For each element in the `p_buffers` array, the `pv_buffer` pointer points to a valid memory,
            //   that is valid for writes of `cb_buffer` bytes.
            unsafe { copy_to_c_sec_buffer(p_output_buffers, &output_tokens, allocate) }
        );

        // SAFETY: `ph_new_context` is convertible to a reference.
        let new_context = unsafe { ph_new_context.as_mut() }.expect("ph_new_context is non-null");

        let dw_upper = sspi_context_ptr.as_ptr().expose_provenance();
        new_context.dw_upper = try_execute!(dw_upper.try_into(), ErrorKind::InvalidHandle);
        // SAFETY:
        // `ph_context` is guaranteed to be non-null since it is initialized in the `p_ctxt_handle_to_sspi_context`
        // if it was previously null.
        new_context.dw_lower = unsafe { (*ph_context).dw_lower };

        // SAFETY: `pf_context_attr` is guaranteed to be non-null due to the prior check.
        unsafe { *pf_context_attr = f_context_req; }

        let result = try_execute!(result_status);
        result.status.to_u32().unwrap()
    }
}

/// # Safety
///
/// - `ph_context` must be a valid pointer to a `SecHandle` structure.
///   If `dw_lower` and `dw_upper` fields are non-zero, then they must point to a memory that was allocated by an SSPI function.
/// - `p_buffer` must be a non-null, valid pointer to some attribute structure.
#[allow(clippy::useless_conversion)]
unsafe fn query_context_attributes_common(
    mut ph_context: PCtxtHandle,
    ul_attribute: u32,
    p_buffer: *mut c_void,
    is_wide: bool,
) -> SecurityStatus {
    catch_panic! {
        check_null!(p_buffer);

        let mut sspi_context_ptr = try_execute!(
            // SAFETY:
            // - `ph_context` is either null or convertible to a reference.
            // - The values behind `ph_context.dw_lower` and `ph_context.dw_upper` pointers are allocated by an SSPI function.
            unsafe {
                p_ctxt_handle_to_sspi_context(&mut ph_context, None, &CredentialsAttributes::default())
            }
        );

        // SAFETY: `sspi_context_ptr` is a valid, local pointer to the `SspiHandle` allocated by the `p_ctx_handle_to_sspi_context`.
        let sspi_context = unsafe { sspi_context_ptr.as_mut() };

        match ul_attribute.try_into().unwrap() {
            SECPKG_ATTR_SIZES => {
                let sizes = p_buffer.cast::<SecPkgContextSizes>();

                let pkg_sizes = try_execute!(sspi_context.query_context_sizes());

                // SAFETY: `sizes` is non-null because it was cast from a non-null `p_buffer`.
                let sizes = unsafe { sizes.as_mut() }.expect("sized pointer should not be null");

                sizes.cb_max_token = pkg_sizes.max_token;
                sizes.cb_max_signature = pkg_sizes.max_signature;
                sizes.cb_block_size = pkg_sizes.block;
                sizes.cb_security_trailer = pkg_sizes.security_trailer;

                return 0;
            }
            SECPKG_ATTR_NEGOTIATION_INFO => {
                let package_info = try_execute!(sspi_context.query_context_package_info());

                if is_wide {
                    let nego_info = p_buffer.cast::<SecNegoInfoW>();

                    // SAFETY: `nego_info` is non-null because it was cast from a non-null `p_buffer`.
                    let nego_info = unsafe { nego_info.as_mut() }.expect("nego_info pointer should not be null");

                    nego_info.nego_state = SECPKG_NEGOTIATION_COMPLETE.try_into().unwrap();

                    let package_info: RawSecPkgInfoW = package_info.into();
                    nego_info.package_info = package_info.0;
                } else {
                    let nego_info = p_buffer.cast::<SecNegoInfoA>();

                    // SAFETY: `nego_info` is non-null because it was cast from a non-null `p_buffer`.
                    let nego_info = unsafe { nego_info.as_mut() }.expect("nego_info pointer should not be null");

                    nego_info.nego_state = SECPKG_NEGOTIATION_COMPLETE.try_into().unwrap();

                    let package_info: RawSecPkgInfoA = package_info.into();
                    nego_info.package_info = package_info.0;
                }

                return 0;
            }
            SECPKG_ATTR_STREAM_SIZES => {
                let stream_sizes = try_execute!(sspi_context.query_context_stream_sizes());

                let stream_info = p_buffer.cast::<SecPkgContextStreamSizes>();

                // SAFETY: `stream_info` is non-null because it was cast from a non-null `p_buffer`.
                let stream_info = unsafe { stream_info.as_mut() }.expect("stream_info pointer should not be null");

                stream_info.cb_header = stream_sizes.header;
                stream_info.cb_trailer = stream_sizes.trailer;
                stream_info.cb_maximum_message = stream_sizes.max_message;
                stream_info.c_buffers = stream_sizes.buffers;
                stream_info.cb_block_size = stream_sizes.block_size;

                return 0;
            }
            SECPKG_ATTR_REMOTE_CERT_CONTEXT => {
                cfg_if::cfg_if! {
                    if #[cfg(target_os = "windows")] {
                        use std::ptr::{null_mut};

                        let cert_context = try_execute!(sspi_context.query_context_remote_cert());

                        // SAFETY: FFI call without no outstanding preconditions.
                        let store = unsafe { CertOpenStore(CERT_STORE_PROV_MEMORY, CERT_QUERY_ENCODING_TYPE(0), None, CERT_STORE_CREATE_NEW_FLAG, None) };

                        let Ok(store) = store.inspect_err(|error| {
                            error!(?error, "Failed to open store");
                        }) else {
                            return ErrorKind::InternalError.to_u32().expect("ErrorKind is castable to u32")
                        };

                        let mut p_cert_context = null_mut();

                        let encoding_type = cert_context.encoding_type.to_u32().expect("cert_context.encoding_type is castable to u32");

                        // SAFETY: FFI call without no outstanding preconditions.
                        let result = unsafe { CertAddEncodedCertificateToStore(
                            Some(store),
                            CERT_QUERY_ENCODING_TYPE(encoding_type),
                            &cert_context.raw_cert,
                            CERT_STORE_ADD_REPLACE_EXISTING,
                            Some(&mut p_cert_context),
                        )};

                        if let Err(error) = result {
                            return error.code().0.to_u32().expect("error.code() is castable to u32");
                        }

                        let p_cert_buffer = p_buffer.cast::<*const CERT_CONTEXT>();

                        // SAFETY: `p_cert_buffer` is non-null because it was cast from a non-null `p_buffer`.
                        unsafe { *p_cert_buffer = p_cert_context; }

                        return 0;
                    } else {
                        return ErrorKind::UnsupportedFunction.to_u32().unwrap();
                    }
                }
            }
            SECPKG_ATTR_SERVER_AUTH_FLAGS => {
                // The caller owns the `SecPkgContextFlags` structure and passes a pointer to it,
                // so the flags value is written in place.
                // https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_flags
                let sec_context_flags = p_buffer.cast::<SecPkgContextFlags>();

                // SAFETY: `sec_context_flags` is non-null because it was cast from a non-null `p_buffer`.
                let sec_context_flags = unsafe { sec_context_flags.as_mut() }.expect("sec_context_flags pointer should not be null");
                sec_context_flags.flags = 0;

                return 0;
            }
            SECPKG_ATTR_CONNECTION_INFO => {
                let connection_info = try_execute!(sspi_context.query_context_connection_info());

                let sec_pkg_context_connection_info = p_buffer.cast::<SecPkgContextConnectionInfo>();
                // SAFETY: `sec_pgk_context_connection_info` is non-null because it was cast from a non-null `p_buffer`.
                let sec_pkg_context_connection_info = unsafe { sec_pkg_context_connection_info.as_mut() }.expect("sec_pkg_context_connection_info should not be null");
                sec_pkg_context_connection_info.dw_protocol = connection_info.protocol.to_u32().unwrap();
                sec_pkg_context_connection_info.ai_cipher = connection_info.cipher.to_u32().unwrap();
                sec_pkg_context_connection_info.dw_cipher_strength = connection_info.cipher_strength;
                sec_pkg_context_connection_info.ai_hash = connection_info.hash.to_u32().unwrap();
                sec_pkg_context_connection_info.dw_hash_strength = connection_info.hash_strength;
                sec_pkg_context_connection_info.ai_exch = connection_info.key_exchange.to_u32().unwrap();
                sec_pkg_context_connection_info.dw_exch_strength = connection_info.exchange_strength;

                return 0;
            }
            SECPKG_ATTR_CERT_TRUST_STATUS => {
                let sspi_cert_trust_status = try_execute!(sspi_context.query_context_cert_trust_status());

                let cert_trust_status = p_buffer.cast::<CertTrustStatus>();
                // SAFETY: `cert_trust_status` is non-null because it was cast from a non-null `p_buffer`.
                let cert_trust_status = unsafe { cert_trust_status.as_mut() }.expect("cert_trust_status pointer should not be null");

                cert_trust_status.dw_error_status = sspi_cert_trust_status.error_status.bits();
                cert_trust_status.dw_info_status = sspi_cert_trust_status.info_status.bits();

                return 0;
            }
            SECPKG_ATTR_SESSION_KEY => {
                let session_key = try_execute!(sspi_context.query_context_session_key()).session_key;
                let session_key_len = session_key.as_ref().len();

                let sec_pkg_context_session_key = p_buffer.cast::<SecPkgContextSessionKey>();

                // SAFETY: `sec_pkg_context_session_key` is non-null because it was cast from a non-null `p_buffer`.
                unsafe {
                    (*sec_pkg_context_session_key).session_key_len = try_execute!(session_key_len.try_into(), ErrorKind::InvalidParameter);
                }

                // SAFETY: Memory allocation is safe.
                let buf = unsafe {
                    libc::malloc(session_key_len)
                }.cast::<u8>();

                if buf.is_null() {
                    return ErrorKind::InsufficientMemory.to_u32().unwrap();
                }

                // SAFETY:
                // - `session_key.as_ref().as_ptr()` pointer is valid for reads of `session_key_len` bytes,
                //   because it is Rust-allocated vector of u8 values with size of `session_key_len`.
                // - `sec_pkg_context_session_key_ptr` is valid for writes of `session_key_len` bytes.
                // - `session_key` and memory behind `sec_pkg_context_session_key_ptr` are properly-aligned.
                // - `session_key` and memory behind `sec_pkg_context_session_key_ptr` do not overlap,
                //   because they are allocated separately.
                unsafe {
                    copy_nonoverlapping(session_key.as_ref().as_ptr(), buf, session_key_len);
                }

                // SAFETY:
                // - `sec_pkg_context_session_key` is a valid pointer to a `SecPkgContextSessionKey` structure due to a previous check.
                unsafe {
                    (*sec_pkg_context_session_key).session_key = buf;
                }

                return 0;
            }
            SECPKG_ATTR_NAMES => {
                let sspi_names = try_execute!(sspi_context.query_context_names());

                if is_wide {
                    let sec_pkg_names = p_buffer.cast::<SecPkgContextNamesW>();
                    // We use `.inner()` instead of `.account_name()` because we want to return the full username, including the domain part.
                    let wide_username = Utf16String::from_str(sspi_names.username.inner()).into_vec_with_nul();
                    let username_len = wide_username.len();

                    // SAFETY: Memory allocation is safe.
                    let buf = unsafe {
                        libc::malloc(username_len * size_of::<u16>())
                    }.cast::<u16>();

                    if buf.is_null() {
                        return ErrorKind::InsufficientMemory.to_u32().unwrap();
                    }

                    // SAFETY:
                    // - `wide_username.as_ptr()` pointer is valid for reads of `username_len` u16 values,
                    //   because it is Rust-allocated vector of u16 values with size of `username_len`.
                    // - `buf` is valid for writes of `username_len` u16 values.
                    // - `wide_username` and memory behind `buf` are properly-aligned.
                    // - `wide_username` and memory behind `buf` do not overlap,
                    //   because they are allocated separately.
                    unsafe {
                        copy_nonoverlapping(wide_username.as_ptr(), buf, username_len);
                    }

                    // SAFETY: `sec_pkg_names` is non-null because it was cast from a non-null `p_buffer`.
                    unsafe {
                        (*sec_pkg_names).user_name = buf;
                    }

                    return 0;
                } else {
                    let sec_pkg_names = p_buffer.cast::<SecPkgContextNamesA>();

                    // We use `.inner()` instead of `.account_name()` because we want to return the full username, including the domain part.
                    let username = sspi_names.username.inner();

                    // SAFETY: Memory allocation is safe.
                    let buf = unsafe {
                        // +1 for the null terminator.
                        libc::malloc(username.len() + 1)
                    }.cast::<u8>();

                    if buf.is_null() {
                        return ErrorKind::InsufficientMemory.to_u32().unwrap();
                    }

                    // SAFETY:
                    // - `username.as_ptr()` pointer is valid for reads of `username.len()` bytes,
                    //   because it is Rust-allocated string with size of `username.len()`.
                    // - `buf` is valid for writes of `username.len() + 1` bytes.
                    // - `username` and memory behind `buf` are properly-aligned.
                    // - `username` and memory behind `buf` do not overlap,
                    //   because they are allocated separately.
                    unsafe {
                        copy_nonoverlapping(username.as_ptr(), buf, username.len());
                    }

                    // SAFETY: `buf` is valid for writes of `username.len() + 1` bytes.
                    let null_terminator_ptr = unsafe { buf.add(username.len()) };
                    // SAFETY: `buf` is valid for writes of `username.len() + 1` bytes.
                    unsafe {
                        *null_terminator_ptr = 0;
                    }

                    // SAFETY: `sec_pkg_names` is non-null because it was cast from a non-null `p_buffer`.
                    unsafe {
                        (*sec_pkg_names).user_name = buf.cast();
                    }

                    return 0;
                }
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
                Err(Error::new(
                    ErrorKind::UnsupportedFunction,
                    format!("Unsupported function ID {unsupported}"),
                ))
            }
        });

        if is_wide {
            let nego_info = p_buffer.cast::<*mut SecPkgInfoW>();

            let package_info: RawSecPkgInfoW = package_info.into();
            // SAFETY: `nego_info` is non-null because it was cast from a non-null `p_buffer`.
            unsafe { *nego_info = package_info.0; }
        } else {
            let nego_info = p_buffer.cast::<*mut SecPkgInfoA>();

            let package_info: RawSecPkgInfoA = package_info.into();
            // SAFETY: `nego_info` is non-null because it was cast from a non-null `p_buffer`.
            unsafe { *nego_info = package_info.0; }
        }

        0
    }
}

/// The `QueryContextAttributesA` function lets a transport application query the Credential Security
/// Support Provider (CredSSP) `security package` for certain attributes of a `security context`.
///
/// [MSDN Reference](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querycontextattributesa)
///
/// # Safety
///
/// - `ph_context` must be a valid pointer to a `SecHandle` structure.
///   If `dw_lower` and `dw_upper` fields are non-zero, then they must point to a memory that was allocated by an SSPI function.
/// - `p_buffer` must be a non-null, valid pointer to some attribute structure.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryContextAttributesA"))]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn QueryContextAttributesA(
    ph_context: PCtxtHandle,
    ul_attribute: u32,
    p_buffer: *mut c_void,
) -> SecurityStatus {
    check_null!(p_buffer);

    // SAFETY:
    // - `ph_context` is either null or convertible to a reference.
    // - The values behind `ph_context.dw_lower` and `ph_context.dw_upper` pointers are allocated by an SSPI function.
    // - `p_buffer` is guaranteed to be non-null due to the prior check.
    unsafe { query_context_attributes_common(ph_context, ul_attribute, p_buffer, false) }
}

/// The `QueryContextAttributesW` function lets a transport application query the Credential Security
/// Support Provider (CredSSP) `security package` for certain attributes of a `security context`.
///
/// [MSDN Reference](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querycontextattributesw)
///
/// # Safety
///
/// - `ph_context` must be a valid pointer to a `SecHandle` structure.
///   If `dw_lower` and `dw_upper` fields are non-zero, then they must point to a memory that was allocated by an SSPI function.
/// - `p_buffer` must be a non-null, valid pointer to some attribute structure.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryContextAttributesW"))]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn QueryContextAttributesW(
    ph_context: PCtxtHandle,
    ul_attribute: u32,
    p_buffer: *mut c_void,
) -> SecurityStatus {
    check_null!(p_buffer);

    // SAFETY:
    // - `ph_context` is either null or convertible to a reference.
    // - The values behind `ph_context.dw_lower` and `ph_context.dw_upper` pointers are allocated by an SSPI function.
    // - `p_buffer` is guaranteed to be non-null due to the prior check.
    unsafe { query_context_attributes_common(ph_context, ul_attribute, p_buffer, true) }
}

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_ImportSecurityContextA"))]
#[unsafe(no_mangle)]
pub extern "system" fn ImportSecurityContextA(
    _psz_package: PSecurityString,
    _p_packed_context: PSecBuffer,
    _token: *mut c_void,
    _ph_context: PCtxtHandle,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_ImportSecurityContextW"))]
#[unsafe(no_mangle)]
pub extern "system" fn ImportSecurityContextW(
    _psz_package: PSecurityString,
    _p_packed_context: PSecBuffer,
    _token: *mut c_void,
    _ph_context: PCtxtHandle,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_AddCredentialsA"))]
#[unsafe(no_mangle)]
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

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_AddCredentialsW"))]
#[unsafe(no_mangle)]
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

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_SetContextAttributesA"))]
#[unsafe(no_mangle)]
pub extern "system" fn SetContextAttributesA(
    _ph_context: PCtxtHandle,
    _ul_attribute: u32,
    _p_buffer: *mut c_void,
    _cb_buffer: u32,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

#[cfg_attr(windows, rename_symbol(to = "Rust_SetContextAttributesW"))]
#[unsafe(no_mangle)]
pub extern "system" fn SetContextAttributesW(
    _ph_context: PCtxtHandle,
    _ul_attribute: u32,
    _p_buffer: *mut c_void,
    _cb_buffer: u32,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

/// Sets the `attributes` of a `credential`, such as the name associated with the credential. The information
/// is valid for any `security context` created with the specified credential.
///
/// [MSDN Reference](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-setcredentialsattributesa)
///
/// # Safety
///
/// - `ph_context` must be a non-null, valid pointer to a `SecHandle` structure.
///   If `dw_lower` and `dw_upper` fields are non-zero, then they must point to a memory that was allocated by an SSPI function.
/// - If `ul_attribute` is [`SECPKG_CRED_ATTR_NAMES`] or [`SECPKG_CRED_ATTR_KDC_URL`],
///  `p_buffer` must be a non-null pointer to a valid null-terminated C String.
/// - Else, `p_buffer` must be a non-null pointer to a valid [`SecPkgCredentialsKdcProxySettingsW`] structure.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_SetCredentialsAttributesA"))]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetCredentialsAttributesA(
    ph_credential: PCtxtHandle,
    ul_attribute: u32,
    p_buffer: *mut c_void,
    _cb_buffer: u32,
) -> SecurityStatus {
    catch_panic! {
        check_null!(ph_credential);
        check_null!(p_buffer);

        // SAFETY: `ph_credential` is guaranteed to be non-null due to the prior check.
        unsafe { log_sec_handle("SetCredentialsAttributesA", ph_credential) };
        debug!(ul_attribute);

        // SAFETY:
        // - `ph_credentials` is guaranteed to be non-null due to the prior check.
        // - `ph_credentials` points to a valid `credentials handle` allocated by an SSPI function.
        let dw_lower = unsafe { (*ph_credential).dw_lower };

        let updated = if ul_attribute == SECPKG_CRED_ATTR_NAMES {
            let workstation =
                try_execute!(
                    // SAFETY:
                    // - `p_buffer` is guaranteed to be non-null due to the prior check.
                    // - The memory region `p_buffer` contains a valid null-terminator at the end of string.
                    // - The memory region `p_buffer` points to is valid for reads of bytes up to and including null-terminator.
                    unsafe { CStr::from_ptr(p_buffer.cast()) }.to_str(),
                    ErrorKind::InvalidParameter
                ).to_owned();

            try_execute!(update_credentials_attributes(dw_lower, |attributes| {
                attributes.workstation = Some(workstation);
            }))
        } else if ul_attribute == SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS {
            let kdc_proxy_settings = try_execute!(
                // SAFETY:
                // - `p_buffer` is not-null.
                // - `p_buffer` points to a valid `SecPkgCredentialsKdcProxySettingsW` structure.
                unsafe { extract_kdc_proxy_settings(NonNull::new(p_buffer).expect("p_buffer should not be null")) }
            );

            try_execute!(update_credentials_attributes(dw_lower, |attributes| {
                attributes.kdc_proxy_settings = Some(kdc_proxy_settings);
            }))
        } else if ul_attribute == SECPKG_CRED_ATTR_KDC_URL {
            let cred_attr = p_buffer.cast::<SecPkgCredentialsKdcUrlA>();

            // SAFETY:
            // - `cred_attr` is guaranteed to be non-null due to the prior check.
            let kdc_url = unsafe {
                (*cred_attr).kdc_url
            };

            if kdc_url.is_null() {
                return ErrorKind::IncompleteCredentials.to_u32().unwrap();
            }

            let kdc_url = try_execute!(
                // SAFETY:
                // - `kdc_url` is non-null due to the prior check.
                // - The memory region `kdc_url` contains a valid null-terminator at the end of string.
                // - The memory region `kdc_url` points to is valid for reads of bytes up to and including null-terminator.
                unsafe { CStr::from_ptr(kdc_url) }.to_str(),
                ErrorKind::InvalidParameter
            ).to_owned();

            try_execute!(update_credentials_attributes(dw_lower, |attributes| {
                attributes.kdc_url = Some(kdc_url);
            }))
        } else {
            return ErrorKind::UnsupportedFunction.to_u32().unwrap();
        };

        if updated {
            0
        } else {
            ErrorKind::InvalidParameter.to_u32().unwrap()
        }
    }
}

/// Sets the `attributes` of a `credential`, such as the name associated with the credential. The information
/// is valid for any `security context` created with the specified credential.
///
/// [MSDN Reference](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-setcredentialsattributesw)
///
/// # Safety
///
/// - `ph_context` must be a non-null, valid pointer to a `SecHandle` structure.
///   If `dw_lower` and `dw_upper` fields are non-zero, then they must point to a memory that was allocated by an SSPI function.
/// - If `ul_attribute` is [`SECPKG_CRED_ATTR_NAMES`] or [`SECPKG_CRED_ATTR_KDC_URL`],
///  `p_buffer` must be a non-null pointer to a valid null-terminated C String and be properly aligned for `u16`.
/// - Else, `p_buffer` must be a non-null pointer to a valid [`SecPkgCredentialsKdcProxySettingsW`] structure.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_SetCredentialsAttributesW"))]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn SetCredentialsAttributesW(
    ph_credential: PCtxtHandle,
    ul_attribute: u32,
    p_buffer: *mut c_void,
    _cb_buffer: u32,
) -> SecurityStatus {
    catch_panic! {
        check_null!(ph_credential);
        check_null!(p_buffer);

        // SAFETY: `ph_credential` is guaranteed to be non-null due to the prior check.
        unsafe { log_sec_handle("SetCredentialsAttributesW", ph_credential) };
        debug!(ul_attribute);

        // SAFETY:
        // - `ph_credentials` is guaranteed to be non-null due to the prior check.
        // - `ph_credentials` points to a valid `credentials handle` allocated by an SSPI function.
        let dw_lower = unsafe { (*ph_credential).dw_lower };

        let updated = if ul_attribute == SECPKG_CRED_ATTR_NAMES {
            let workstation = try_execute!(
                // SAFETY:
                // - `p_buffer` is guaranteed to be non-null due to the prior check.
                // - The memory region `p_buffer` contains a valid null-terminator at the end of string.
                // - The memory region `p_buffer` points to is valid for reads of `u16` code units up to and including null-terminator.
                // - `p_buffer` is properly aligned for `u16`, per the safety preconditions.
                unsafe { U16CString::from_ptr_str(p_buffer.cast()) }.to_string().map_err(Error::from)
            );

            try_execute!(update_credentials_attributes(dw_lower, |attributes| {
                attributes.workstation = Some(workstation);
            }))
        } else if ul_attribute == SECPKG_CRED_ATTR_KDC_PROXY_SETTINGS {
            let kdc_proxy_settings = try_execute!(
                // SAFETY:
                // - `p_buffer` is not-null.
                // - `p_buffer` points to a valid `SecPkgCredentialsKdcProxySettingsW` structure.
                unsafe { extract_kdc_proxy_settings(NonNull::new(p_buffer).expect("p_buffer should not be null")) }
            );

            try_execute!(update_credentials_attributes(dw_lower, |attributes| {
                attributes.kdc_proxy_settings = Some(kdc_proxy_settings);
            }))
        } else if ul_attribute == SECPKG_CRED_ATTR_KDC_URL {
            let cred_attr = p_buffer.cast::<SecPkgCredentialsKdcUrlW>();
            // SAFETY:
            // - `cred_attr` is guaranteed to be non-null due to the prior check.
            let kdc_url = unsafe {
                (*cred_attr).kdc_url
            }.cast_const();

            if kdc_url.is_null() {
                return ErrorKind::IncompleteCredentials.to_u32().unwrap();
            }

            let kdc_url = try_execute!(
                // SAFETY:
                // - `kdc_url` is guaranteed to be non-null due to the prior null check.
                // - The memory region `kdc_url` contains a valid null-terminator at the end of string.
                // - The memory region `kdc_url` points to is valid for reads of `u16` code units up to and including the null-terminator.
                // - `kdc_url` is properly aligned for `u16`, per the safety preconditions.
                unsafe { U16CString::from_ptr_str(kdc_url) }.to_string().map_err(Error::from)
            );

            try_execute!(update_credentials_attributes(dw_lower, |attributes| {
                attributes.kdc_url = Some(kdc_url);
            }))
        } else {
            return ErrorKind::UnsupportedFunction.to_u32().unwrap();
        };

        if updated {
            0
        } else {
            ErrorKind::InvalidParameter.to_u32().unwrap()
        }
    }
}

/// The `ChangeAccountPasswordA` function changes the password for a Windows domain account by using
/// the specified `Security Support Provider`.
///
/// [MSDN Reference](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-changeaccountpassworda)
///
/// # Safety
///
/// - `psz_package_name` must be a non-null pointer to a valid, null-terminated C string representing the package name.
/// - `psz_domain_name` must be a non-null pointer to a valid, null-terminated C string representing the domain name.
/// - `psz_account_name` must be a non-null pointer to a valid, null-terminated C string representing the account name.
/// - `psz_old_password` must be a non-null pointer to a valid, null-terminated C string representing the old password.
/// - `psz_new_password` must be a non-null pointer to a valid, null-terminated C string representing the new password.
/// - `p_output` must be a non-null, properly-aligned pointer to a valid `SecBufferDesc` structure.
///   It must contain enough buffers, and each buffer must have enough space to hold the output tokens.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_ChangeAccountPasswordA"))]
#[unsafe(no_mangle)]
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

        let security_package_name =
            // SAFETY:
            // - `psz_package_name` is guaranteed to be non-null due to the prior check.
            // - The memory region `psz_package_name` contains a valid null-terminator at the end of string.
            // - The memory region `psz_package_name` points to is valid for reads of bytes up to and including null-terminator.
            try_execute!(unsafe { CStr::from_ptr(psz_package_name) }.to_str(), ErrorKind::InvalidParameter);

        let domain =
            // SAFETY:
            // - `psz_domain_name` is guaranteed to be non-null due to the prior check.
            // - The memory region `psz_domain_name` contains a valid null-terminator at the end of string.
            // - The memory region `psz_domain_name` points to is valid for reads of bytes up to and including null-terminator.
            try_execute!(unsafe { CStr::from_ptr(psz_domain_name) }.to_str(), ErrorKind::InvalidParameter);
        let username =
            // SAFETY:
            // - `psz_account_name` is guaranteed to be non-null due to the prior check.
            // - The memory region `psz_account_name` contains a valid null-terminator at the end of string.
            // - The memory region `psz_account_name` points to is valid for reads of bytes up to and including null-terminator.
            try_execute!(unsafe { CStr::from_ptr(psz_account_name) }.to_str(), ErrorKind::InvalidParameter);
        let password =
            // SAFETY:
            // - `psz_old_password` is guaranteed to be non-null due to the prior check.
            // - The memory region `psz_old_password` contains a valid null-terminator at the end of string.
            // - The memory region `psz_old_password` points to is valid for reads of bytes up to and including null-terminator.
            try_execute!(unsafe { CStr::from_ptr(psz_old_password) }.to_str(), ErrorKind::InvalidParameter);
        let new_password =
            // SAFETY:
            // - `psz_new_password` is guaranteed to be non-null due to the prior check.
            // - The memory region `psz_new_password` contains a valid null-terminator at the end of string.
            // - The memory region `psz_new_password` points to is valid for reads of bytes up to and including null-terminator.
            try_execute!(unsafe { CStr::from_ptr(psz_new_password) }.to_str(), ErrorKind::InvalidParameter);

        // SAFETY: `p_output` is convertible to a reference.
        let p_output = unsafe { p_output.as_mut() }.expect("p_output pointer should not be null");
        let len = try_execute!(usize::try_from(p_output.c_buffers), ErrorKind::InvalidParameter);

        check_null!(p_output.p_buffers);

        // SAFETY:
        // - `p_output.p_buffers` is guaranteed to be non-null due to the prior check.
        // - The memory region `p_output.p_buffers` points to is valid for reads of `len` elements.
        let p_buffers = unsafe { from_raw_parts(p_output.p_buffers, len) };
        // SAFETY:
        // - `p_buffers` must contain valid [SecBuffer] structures: upheld by the user.
        let output_tokens = unsafe { p_sec_buffers_to_security_buffers(p_buffers) };
        let mut output_tokens = try_execute!(output_tokens);
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
                SspiContext::Negotiate(try_execute!(Negotiate::new_client(negotiate_config)))
            },
            kerberos::PKG_NAME => {
                let krb_config = KerberosConfig {
                    client_computer_name: try_execute!(hostname()),
                    kdc_resolution: KdcResolution::KdcUrl(None),
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

        // SAFETY:
        // - `p_output.p_buffers` is a valid pointer to an array of security buffers.
        // - The memory region `p_output.p_buffers` points to is valid for writes of `from_buffers.len()` elements.
        // - For each element in the `p_output.p_buffers` array, the `pv_buffer` pointer points to a valid memory,
        //   that is valid for writes of `cb_buffer` bytes.
        try_execute!(unsafe { copy_to_c_sec_buffer(p_output.p_buffers, &output_tokens, false) });

        try_execute!(result_status);

        0
    }
}

/// The `ChangeAccountPasswordW` function changes the password for a Windows domain account by using
/// the specified `Security Support Provider`.
///
/// [MSDN Reference](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-changeaccountpasswordw)
///
/// # Safety
///
/// - `psz_package_name` must be a non-null pointer to a valid, null-terminated C string representing the package name.
///   Must be properly aligned for `u16`.
/// - `psz_domain_name` must be a non-null pointer to a valid, null-terminated C string representing the domain name.
///   Must be properly aligned for `u16`.
/// - `psz_account_name` must be a non-null pointer to a valid, null-terminated C string representing the account name.
///   Must be properly aligned for `u16`.
/// - `psz_old_password` must be a non-null pointer to a valid, null-terminated C string representing the old password.
///   Must be properly aligned for `u16`.
/// - `psz_new_password` must be a non-null pointer to a valid, null-terminated C string representing the new password.
///   Must be properly aligned for `u16`.
/// - `p_output` must be a non-null, properly-aligned pointer to a valid `SecBufferDesc` structure.
///   It must contain enough buffers, and each buffer must have enough space to hold the output tokens.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_ChangeAccountPasswordW"))]
#[unsafe(no_mangle)]
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

        let mut security_package_name = try_execute!(
            // SAFETY:
            // - `psz_package_name` is guaranteed to be non-null due to the prior check.
            // - The memory region `psz_package_name` contains a valid null-terminator at the end of string.
            // - The memory region `psz_package_name` points to is valid for reads of `u16` code units up to and including null-terminator.
            // - `psz_package_name` is properly aligned for `u16`, per the safety preconditions.
            unsafe { U16CString::from_ptr_str(psz_package_name) }.to_string().map_err(Error::from)
        );

        let mut domain = try_execute!(
            // SAFETY:
            // - `psz_domain_name` is guaranteed to be non-null due to the prior check.
            // - The memory region `psz_domain_name` contains a valid null-terminator at the end of string.
            // - The memory region `psz_domain_name` points to is valid for reads of `u16` code units up to and including null-terminator.
            // - `psz_domain_name` is properly aligned for `u16`, per the safety preconditions.
            unsafe { U16CString::from_ptr_str(psz_domain_name) }.to_string().map_err(Error::from)
        );
        let mut username = try_execute!(
            // SAFETY:
            // - `psz_account_name` is guaranteed to be non-null due to the prior check.
            // - The memory region `psz_account_name` contains a valid null-terminator at the end of string.
            // - The memory region `psz_account_name` points to is valid for reads of `u16` code units up to and including null-terminator.
            // - `psz_account_name` is properly aligned for `u16`, per the safety preconditions.
            unsafe { U16CString::from_ptr_str(psz_account_name) }.to_string().map_err(Error::from)
        );
        let mut password = Secret::new(try_execute!(
            // SAFETY:
            // - `psz_old_password` is guaranteed to be non-null due to the prior check.
            // - The memory region `psz_old_password` contains a valid null-terminator at the end of string.
            // - The memory region `psz_old_password` points to is valid for reads of `u16` code units up to and including null-terminator.
            // - `psz_old_password` is properly aligned for `u16`, per the safety preconditions.
            unsafe { U16CString::from_ptr_str(psz_old_password) }.to_string().map_err(Error::from)
        ));
        let mut new_password = Secret::new(try_execute!(
            // SAFETY:
            // - `psz_new_password` is guaranteed to be non-null due to the prior check.
            // - The memory region `psz_new_password` contains a valid null-terminator at the end of string.
            // - The memory region `psz_new_password` points to is valid for reads of `u16` code units up to and including null-terminator.
            // - `psz_new_password` is properly aligned for `u16`, per the safety preconditions.
            unsafe { U16CString::from_ptr_str(psz_new_password) }.to_string().map_err(Error::from)
        ));

        // SAFETY:
        // * `security_package_name' is a `String`.
        // * `domain' is a `String`.
        // * `username' is a `String`.
        // * `password' is a `String`.
        // * `new_password' is a `String`.
        // * `p_output' is not-null pointer to a valid `SecBufferDesc` structure.
        unsafe {
            ChangeAccountPasswordA(
                security_package_name.as_mut_ptr().cast(),
                domain.as_mut_ptr().cast(),
                username.as_mut_ptr().cast(),
                password.as_mut().as_mut_ptr().cast(),
                new_password.as_mut().as_mut_ptr().cast(),
                b_impersonating,
                dw_reserved,
                p_output,
            )
        }
    }
}

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryContextAttributesExA"))]
#[unsafe(no_mangle)]
pub extern "system" fn QueryContextAttributesExA(
    _ph_context: PCtxtHandle,
    _ul_attribute: u32,
    _p_buffer: *mut c_void,
    _cb_buffer: u32,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryContextAttributesExW"))]
#[unsafe(no_mangle)]
pub extern "system" fn QueryContextAttributesExW(
    _ph_context: PCtxtHandle,
    _ul_attribute: u32,
    _p_buffer: *mut c_void,
    _cb_buffer: u32,
) -> SecurityStatus {
    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

/// # Safety
///
/// `ph_credential` must be null or a valid pointer to a `SecHandle` structure.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryCredentialsAttributesExA"))]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn QueryCredentialsAttributesExA(
    ph_credential: PCredHandle,
    ul_attribute: u32,
    _p_buffer: *mut c_void,
    _c_buffers: u32,
) -> SecurityStatus {
    // SAFETY: `ph_credential` is either null or a valid pointer to a `SecHandle`, per the safety preconditions.
    unsafe { log_sec_handle("QueryCredentialsAttributesExA", ph_credential) };
    debug!(ul_attribute);

    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}

/// # Safety
///
/// `ph_credential` must be null or a valid pointer to a `SecHandle` structure.
#[instrument(skip_all)]
#[cfg_attr(windows, rename_symbol(to = "Rust_QueryCredentialsAttributesExW"))]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn QueryCredentialsAttributesExW(
    ph_credential: PCredHandle,
    ul_attribute: u32,
    _p_buffer: *mut c_void,
    _c_buffers: u32,
) -> SecurityStatus {
    // SAFETY: `ph_credential` is either null or a valid pointer to a `SecHandle`, per the safety preconditions.
    unsafe { log_sec_handle("QueryCredentialsAttributesExW", ph_credential) };
    debug!(ul_attribute);

    ErrorKind::UnsupportedFunction.to_u32().unwrap()
}
