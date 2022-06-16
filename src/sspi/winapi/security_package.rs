use std::convert::TryFrom;
use std::ptr;

use num_traits::ToPrimitive;
use winapi::ctypes::c_void;
use winapi::shared::sspi::{
    AcceptSecurityContext, AcquireCredentialsHandleW, CompleteAuthToken, CredHandle, CtxtHandle, DecryptMessage,
    DeleteSecurityContext, EncryptMessage, FreeContextBuffer, InitializeSecurityContextW, QueryContextAttributesW,
    SecBuffer, SecPkgContext_NamesW, SecPkgContext_PackageInfoW, SecPkgContext_Sizes, TimeStamp, SECPKG_ATTR_NAMES,
    SECPKG_ATTR_PACKAGE_INFO, SECPKG_ATTR_SIZES,
};
use winapi::um::wincrypt::CERT_TRUST_STATUS;

use super::{
    construct_buffer_desc, convert_winapi_status, file_time_to_system_time, str_to_win_wstring, wide_ptr_to_string,
    CredentialsGuard,
};
use crate::sspi::builders::{
    AcceptSecurityContextResult, AcquireCredentialsHandleResult, InitializeSecurityContextResult,
};
use crate::sspi::internal::SspiImpl;
use crate::sspi::{
    self, CertTrustErrorStatus, CertTrustInfoStatus, CertTrustStatus, ClientRequestFlags, ClientResponseFlags,
    ContextNames, ContextSizes, DecryptionFlags, EncryptionFlags, FilledAcceptSecurityContext,
    FilledAcquireCredentialsHandle, FilledInitializeSecurityContext, PackageInfo, SecurityBuffer, SecurityBufferType,
    SecurityPackageType, SecurityStatus, ServerRequestFlags, ServerResponseFlags, Sspi,
};

const SECPKG_ATTR_CERT_TRUST_STATUS: u32 = 0x8000_0084;

/// Represents a Windows-provided SSP that doesn't have a wrapper.
///
/// Using the methods of this structure, it is possible to get a Windows-provided SSP even if
/// it doesn't have a wrapper or a platform independent implementation. It is still recommended
/// to use a wrapper if one is available.
pub struct SecurityPackage {
    context: Option<SecurityContext>,
    package_type: SecurityPackageType,
}

impl SecurityPackage {
    /// Creates the `SecurityPackage` from a string. You can get any available Windows-provided
    /// SSPs using this method.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(windows)]
    /// # mod win {
    /// #     use sspi::{winapi::SecurityPackage, SecurityPackageType};
    /// #
    /// #     fn main() {
    /// let negotiate = SecurityPackage::from_package_type(
    ///     SecurityPackageType::Other(String::from("Negotiate"))
    /// );
    /// #     }
    /// # }
    /// ```
    pub fn from_package_type(package_type: SecurityPackageType) -> Self {
        Self {
            context: None,
            package_type,
        }
    }

    /// Enables an application to query a security package for certain attributes of a security context.
    ///
    /// # MSDN
    ///
    /// * [QueryContextAttributes function](https://docs.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--general)
    fn query_context_attributes<T>(&mut self, attribute: u32, buffer: &mut T) -> sspi::Result<SecurityStatus> {
        let context = self
            .context
            .as_mut()
            .expect("QueryContextAttributes cannot be fired without context");

        unsafe {
            convert_winapi_status(QueryContextAttributesW(
                &mut context.0 as *mut _,
                attribute,
                buffer as *mut _ as *mut _,
            ))
        }
    }
}

impl SspiImpl for SecurityPackage {
    type CredentialsHandle = CredentialsGuard;
    type AuthenticationData = *mut c_void;

    fn acquire_credentials_handle_impl(
        &mut self,
        mut builder: FilledAcquireCredentialsHandle<'_, Self::CredentialsHandle, Self::AuthenticationData>,
    ) -> sspi::Result<AcquireCredentialsHandleResult<Self::CredentialsHandle>> {
        let principal_name_utf16 = builder.principal_name.map(str_to_win_wstring);
        let principal_name = principal_name_utf16
            .map(|mut v| v.as_mut_ptr())
            .unwrap_or(ptr::null_mut());

        let mut package_name = str_to_win_wstring(self.package_type.to_string().as_str());
        let mut credentials_handle = CredHandle::default();

        let logon_id = as_mut_ptr_or_null(builder.logon_id.as_mut());
        let mut expiry = TimeStamp::default();
        let identity = if let Some(auth_data) = builder.auth_data {
            *auth_data
        } else {
            ptr::null_mut()
        };

        unsafe {
            convert_winapi_status(AcquireCredentialsHandleW(
                principal_name,
                package_name.as_mut_ptr(),
                builder.credential_use.to_u32().unwrap(),
                logon_id as *mut _,
                identity,
                None,
                ptr::null_mut(),
                &mut credentials_handle as *mut _,
                &mut expiry as *mut _,
            ))?;
        }

        Ok(AcquireCredentialsHandleResult {
            credentials_handle: CredentialsGuard(credentials_handle),
            expiry: Some(file_time_to_system_time(expiry)),
        })
    }

    fn initialize_security_context_impl<'a>(
        &mut self,
        builder: &mut FilledInitializeSecurityContext<'a, Self::CredentialsHandle>,
    ) -> sspi::Result<InitializeSecurityContextResult> {
        let mut context_to_set = None;
        let (context, context_new) = if let Some(ref mut context) = self.context {
            (&mut context.0 as *mut _, &mut context.0 as *mut _)
        } else {
            context_to_set = Some(CtxtHandle::default());

            (ptr::null_mut(), context_to_set.as_mut().unwrap() as *mut _)
        };

        let credentials = as_mut_ptr_or_null(builder.credentials_handle.as_ref().map(|v| v.0).as_mut());
        let target_name_utf16 = builder.target_name.map(str_to_win_wstring);
        let target_name = target_name_utf16.map(|mut v| v.as_mut_ptr()).unwrap_or(ptr::null_mut());

        let (input_buffer_descriptor, _input_buffers) = if let Some(input) = builder.input.as_mut() {
            let mut input_buffers = buffers_as_winapi(input);
            let mut input_buffer_descriptor = construct_buffer_desc(input_buffers.as_mut());

            (&mut input_buffer_descriptor as *mut _, Some(input_buffers))
        } else {
            (ptr::null_mut(), None)
        };

        let with_allocate_memory = builder
            .context_requirements
            .contains(ClientRequestFlags::ALLOCATE_MEMORY);
        let mut output_buffers = map_output_buffers(with_allocate_memory, builder.output);
        let mut output_buffer_descriptor = construct_buffer_desc(output_buffers.as_mut());

        let mut context_attributes = 0;
        let mut expiry = TimeStamp::default();

        let status = unsafe {
            convert_winapi_status(InitializeSecurityContextW(
                credentials,
                context,
                target_name,
                builder.context_requirements.bits(),
                0,
                builder.target_data_representation.to_u32().unwrap(),
                input_buffer_descriptor,
                0,
                context_new,
                &mut output_buffer_descriptor as *mut _,
                &mut context_attributes as *mut _,
                &mut expiry as *mut _,
            ))?
        };

        if let Some(context_to_set) = context_to_set {
            self.context = Some(SecurityContext(context_to_set));
        }

        if with_allocate_memory {
            builder
                .output
                .swap_with_slice(&mut from_winapi_buffers(output_buffers.as_ref())?);
        }

        Ok(InitializeSecurityContextResult {
            status,
            flags: ClientResponseFlags::from_bits_truncate(context_attributes),
            expiry: Some(file_time_to_system_time(expiry)),
        })
    }

    fn accept_security_context_impl(
        &mut self,
        builder: FilledAcceptSecurityContext<'_, Self::AuthenticationData, Self::CredentialsHandle>,
    ) -> sspi::Result<AcceptSecurityContextResult> {
        let mut context_to_set = None;
        let (context, context_new) = if let Some(ref mut context) = self.context {
            (&mut context.0 as *mut _, &mut context.0 as *mut _)
        } else {
            context_to_set = Some(CtxtHandle::default());

            (ptr::null_mut(), context_to_set.as_mut().unwrap() as *mut _)
        };

        let credentials = as_mut_ptr_or_null(builder.credentials_handle.map(|v| v.0).as_mut());

        let (input_buffer_descriptor, _input_buffers) = if let Some(input) = builder.input {
            let mut input_buffers = buffers_as_winapi(input);
            let mut input_buffer_descriptor = construct_buffer_desc(input_buffers.as_mut());

            (&mut input_buffer_descriptor as *mut _, Some(input_buffers))
        } else {
            (ptr::null_mut(), None)
        };

        let with_allocate_memory = builder
            .context_requirements
            .contains(ServerRequestFlags::ALLOCATE_MEMORY);
        let mut output_buffers = map_output_buffers(with_allocate_memory, builder.output);
        let mut output_buffer_descriptor = construct_buffer_desc(output_buffers.as_mut());

        let mut context_attributes = 0;
        let mut expiry = TimeStamp::default();

        let status = unsafe {
            convert_winapi_status(AcceptSecurityContext(
                credentials,
                context,
                input_buffer_descriptor,
                builder.context_requirements.bits(),
                builder.target_data_representation.to_u32().unwrap(),
                context_new,
                &mut output_buffer_descriptor as *mut _,
                &mut context_attributes as *mut _,
                &mut expiry as *mut _,
            ))?
        };

        if let Some(context_to_set) = context_to_set {
            self.context = Some(SecurityContext(context_to_set));
        }

        if with_allocate_memory {
            builder
                .output
                .swap_with_slice(&mut from_winapi_buffers(output_buffers.as_ref())?);
        }

        Ok(AcceptSecurityContextResult {
            status,
            flags: ServerResponseFlags::from_bits_truncate(context_attributes),
            expiry: Some(file_time_to_system_time(expiry)),
        })
    }
}

impl Sspi for SecurityPackage {
    fn complete_auth_token(&mut self, token: &mut [SecurityBuffer]) -> sspi::Result<SecurityStatus> {
        let context = self
            .context
            .as_mut()
            .expect("CompleteAuthToken cannot be fired without context");

        let mut output_buffers = buffers_as_winapi(token);
        let mut output_buffer_descriptor = construct_buffer_desc(&mut output_buffers);

        unsafe {
            convert_winapi_status(CompleteAuthToken(
                &mut context.0 as *mut _,
                &mut output_buffer_descriptor as *mut _,
            ))
        }
    }

    fn encrypt_message(
        &mut self,
        flags: EncryptionFlags,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> sspi::Result<SecurityStatus> {
        let context = self
            .context
            .as_mut()
            .expect("EncryptMessage cannot be fired without context");

        let mut output_buffers = buffers_as_winapi(message);
        let mut output_buffer_descriptor = construct_buffer_desc(&mut output_buffers);

        unsafe {
            convert_winapi_status(EncryptMessage(
                &mut context.0 as *mut _,
                flags.bits(),
                &mut output_buffer_descriptor as *mut _,
                sequence_number,
            ))
        }
    }

    fn decrypt_message(
        &mut self,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> sspi::Result<DecryptionFlags> {
        let context = self
            .context
            .as_mut()
            .expect("EncryptMessage cannot be fired without context");

        let mut output_buffers = buffers_as_winapi(message);
        let mut output_buffer_descriptor = construct_buffer_desc(&mut output_buffers);

        let mut flags = 0;

        unsafe {
            convert_winapi_status(DecryptMessage(
                &mut context.0 as *mut _,
                &mut output_buffer_descriptor as *mut _,
                sequence_number,
                &mut flags as *mut _,
            ))?
        };

        Ok(DecryptionFlags::from_bits_truncate(flags))
    }

    fn query_context_sizes(&mut self) -> sspi::Result<ContextSizes> {
        let mut buffer = SecPkgContext_Sizes::default();
        self.query_context_attributes(SECPKG_ATTR_SIZES, &mut buffer)?;

        Ok(ContextSizes {
            max_token: buffer.cbMaxToken,
            max_signature: buffer.cbMaxSignature,
            block: buffer.cbBlockSize,
            security_trailer: buffer.cbSecurityTrailer,
        })
    }

    fn query_context_names(&mut self) -> sspi::Result<ContextNames> {
        let mut buffer = SecPkgContext_NamesW::default();
        self.query_context_attributes(SECPKG_ATTR_NAMES, &mut buffer)?;
        let username = WideStringGuard(buffer.sUserName);

        let username = unsafe { wide_ptr_to_string(username.0)? };

        let mut names = username.split('\\').collect::<Vec<_>>();

        let (username, domain) = if names.len() > 1 {
            (names.remove(1).to_string(), Some(names.remove(0).to_string()))
        } else {
            (names.remove(0).to_string(), None)
        };

        Ok(ContextNames { username, domain })
    }

    fn query_context_package_info(&mut self) -> sspi::Result<PackageInfo> {
        let mut buffer = SecPkgContext_PackageInfoW::default();
        self.query_context_attributes(SECPKG_ATTR_PACKAGE_INFO, &mut buffer)?;

        unsafe { PackageInfo::try_from(&(*buffer.PackageInfo)) }
    }

    fn query_context_cert_trust_status(&mut self) -> sspi::Result<CertTrustStatus> {
        let mut buffer = CERT_TRUST_STATUS::default();
        self.query_context_attributes(SECPKG_ATTR_CERT_TRUST_STATUS, &mut buffer)?;

        Ok(CertTrustStatus {
            error_status: CertTrustErrorStatus::from_bits_truncate(buffer.dwErrorStatus),
            info_status: CertTrustInfoStatus::from_bits_truncate(buffer.dwInfoStatus),
        })
    }
}

fn as_mut_ptr_or_null<T>(value: Option<&mut T>) -> *mut T {
    value.map(|v| v as *mut _).unwrap_or(ptr::null_mut())
}

fn map_output_buffers(with_allocate_memory: bool, output: &mut [SecurityBuffer]) -> Vec<SecBuffer> {
    if with_allocate_memory {
        vec![SecBuffer {
            BufferType: SecurityBufferType::Token.to_u32().unwrap(),
            cbBuffer: 0,
            pvBuffer: ptr::null_mut(),
        }]
    } else {
        buffers_as_winapi(output)
    }
}

fn buffers_as_winapi(buffers: &mut [SecurityBuffer]) -> Vec<SecBuffer> {
    buffers.iter_mut().map(SecBuffer::from).collect::<Vec<SecBuffer>>()
}

fn from_winapi_buffers(buffers: &[SecBuffer]) -> sspi::Result<Vec<SecurityBuffer>> {
    buffers
        .iter()
        .map(SecurityBuffer::try_from)
        .collect::<sspi::Result<Vec<_>>>()
}

struct SecurityContext(CtxtHandle);

impl Drop for SecurityContext {
    fn drop(&mut self) {
        unsafe {
            DeleteSecurityContext(&mut self.0 as *mut _);
        }
    }
}

struct WideStringGuard(*mut u16);

impl Drop for WideStringGuard {
    fn drop(&mut self) {
        unsafe {
            FreeContextBuffer(self.0 as *mut _ as *mut _);
        }
    }
}
