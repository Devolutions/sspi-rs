use std::ffi::CStr;
use std::ptr::{self, null, null_mut};

use ffi_types::sspi::{
    CertTrustStatus, SECPKG_ATTR_CERT_TRUST_STATUS, SECPKG_ATTR_PACKAGE_INFO, SECPKG_ATTR_SERVER_AUTH_FLAGS,
    SECPKG_ATTR_SIZES, SecPkgContextFlags, SecPkgContextSizes,
};
use libc::{c_ulonglong, c_void};
use num_traits::ToPrimitive;
use sspi::SecurityStatus::ContinueNeeded;
use sspi::credssp::SspiContext;
use sspi::log_capture::LogCapture;
use sspi::{
    AuthIdentityBuffers, CredentialsBuffers, ErrorKind, Ntlm, PackageCapabilities, SecurityStatus, U16CString,
    Utf16String, Utf16StringExt,
};

use crate::sspi::common::{AcceptSecurityContext, DeleteSecurityContext, FreeContextBuffer, FreeCredentialsHandle};
use crate::sspi::credentials_attributes::CredentialsAttributes;
use crate::sspi::sec_buffer::{SecBuffer, SecBufferDesc};
use crate::sspi::sec_handle::{
    AcquireCredentialsHandleA, AcquireCredentialsHandleW, CredentialsHandle, CredentialsRegistry,
    InitializeSecurityContextA, InitializeSecurityContextW, MAX_RELEASED_CREDENTIALS, QueryContextAttributesA,
    QueryContextAttributesW, SecHandle, SecurityPackageId, SetCredentialsAttributesW, SspiHandle,
    credentials_by_handle,
};
use crate::sspi::sec_pkg_info::{
    EnumerateSecurityPackagesA, EnumerateSecurityPackagesW, PSecPkgInfoA, PSecPkgInfoW, QuerySecurityPackageInfoA,
    QuerySecurityPackageInfoW, SecPkgInfoA, SecPkgInfoW,
};
use crate::sspi::sec_winnt_auth_identity::{
    SEC_WINNT_AUTH_IDENTITY_ANSI, SEC_WINNT_AUTH_IDENTITY_UNICODE, SEC_WINNT_AUTH_IDENTITY_VERSION,
    SecWinntAuthIdentityA, SecWinntAuthIdentityExW, SecWinntAuthIdentityW,
};
use crate::utils::into_raw_ptr;

extern "system" fn dummy(_: *mut c_void, _: *mut c_void, _: u32, _: *mut *mut c_void, _: *mut i32) {}

/// Checks whether the status is one of the security context establishment statuses.
fn is_handshake_status(status: u32) -> bool {
    [
        SecurityStatus::Ok,
        ContinueNeeded,
        SecurityStatus::CompleteNeeded,
        SecurityStatus::CompleteAndContinue,
    ]
    .iter()
    .any(|expected| status == expected.to_u32().expect("SecurityStatus is castable to u32"))
}

/// Queries the `SECPKG_ATTR_SIZES` attribute and asserts the call succeeds.
fn query_context_sizes(sec_context: &mut SecHandle) -> SecPkgContextSizes {
    let mut sizes = SecPkgContextSizes {
        cb_max_token: 0,
        cb_max_signature: 0,
        cb_block_size: 0,
        cb_security_trailer: 0,
    };

    let status = unsafe { QueryContextAttributesW(sec_context, SECPKG_ATTR_SIZES, ptr::from_mut(&mut sizes).cast()) };
    assert_eq!(status, 0);

    sizes
}

/// Asserts that the NTLM security context reports the expected sizes.
///
/// Used to ensure the established security context is usable.
fn assert_ntlm_context_sizes(sec_context: &mut SecHandle) {
    let sizes = query_context_sizes(sec_context);
    assert_eq!(
        (
            sizes.cb_max_token,
            sizes.cb_max_signature,
            sizes.cb_block_size,
            sizes.cb_security_trailer
        ),
        (2010, 16, 0, 16)
    );
}

const PACKAGE_ID_NONE: u16 = 0xFFFF;

const SECURITY_NATIVE_DREP: u32 = 0x10;
const SECPKG_CRED_INBOUND: u32 = 1;
const SECPKG_CRED_OUTBOUND: u32 = 2;
const SECBUFFER_TOKEN: u32 = 2;

/// Maximum number of the security context initialization steps.
///
/// Used to avoid infinite loops in tests in case the handshake never converges.
const MAX_AUTH_STEPS: usize = 10;

/// Creates a zeroed handle, as expected by the `*Handle` out-parameters.
fn empty_handle() -> SecHandle {
    SecHandle {
        dw_lower: 0,
        dw_upper: 0,
    }
}

/// Turns the allocated object into a raw pointer address suitable for [SecHandle] fields.
fn into_sec_handle_field(ptr: *mut impl Sized) -> c_ulonglong {
    ptr.expose_provenance()
        .try_into()
        .expect("ptr address must fit into c_ulonglong")
}

/// Creates a security context handle with the NTLM security context inside.
///
/// Simulates the handle created by the `p_ctxt_handle_to_sspi_context` function. The returned
/// handle must be released using the `DeleteSecurityContext` function.
fn ntlm_sec_handle() -> SecHandle {
    SecHandle {
        dw_lower: SecurityPackageId::Ntlm.into(),
        dw_upper: into_sec_handle_field(into_raw_ptr(SspiHandle::new(SspiContext::Ntlm(Ntlm::new())))),
    }
}

/// Creates a security context handle with the established Kerberos security context inside.
///
/// Simulates the handle created by the `p_ctxt_handle_to_sspi_context` function. The returned
/// handle must be released using the `DeleteSecurityContext` function.
fn kerberos_sec_handle() -> SecHandle {
    // We use the Kerberos fake_client because some context attributes can be queried only
    // on an established security context.
    let kerberos_client = sspi::kerberos::test_data::fake_client();

    SecHandle {
        dw_lower: SecurityPackageId::Kerberos.into(),
        dw_upper: into_sec_handle_field(into_raw_ptr(SspiHandle::new(SspiContext::Kerberos(kerberos_client)))),
    }
}

/// Creates a security context handle with the CredSSP security context inside.
///
/// Simulates the handle created by the `p_ctxt_handle_to_sspi_context` function. The returned
/// handle must be released using the `DeleteSecurityContext` function.
#[cfg(feature = "tsssp")]
fn credssp_sec_handle() -> SecHandle {
    use sspi::credssp::sspi_cred_ssp::SspiCredSsp;

    let credssp = SspiCredSsp::new_client(SspiContext::Ntlm(Ntlm::new())).expect("CredSSP client creation");

    SecHandle {
        dw_lower: SecurityPackageId::CredSsp.into(),
        dw_upper: into_sec_handle_field(into_raw_ptr(SspiHandle::new(SspiContext::CredSsp(credssp)))),
    }
}

fn initialize_negotiate_security_context_with_package_list(user: &str, pkg_list: &str) -> u32 {
    let mut pkg_name = "Negotiate\0".encode_utf16().collect::<Vec<_>>();
    let mut pkg_info: PSecPkgInfoW = null_mut::<SecPkgInfoW>();

    let status = unsafe { QuerySecurityPackageInfoW(pkg_name.as_ptr(), &mut pkg_info) };
    assert_eq!(status, 0);

    // We left all `println`s on purpose to simulate any memory access to the allocated memory.
    println!("{:?}", unsafe { &*pkg_info });
    let name_ptr = unsafe { (*pkg_info).name };
    println!("{:?}", unsafe { Utf16String::from_pcwstr(name_ptr) });
    let comment_ptr = unsafe { (*pkg_info).comment };
    println!("{:?}", unsafe { Utf16String::from_pcwstr(comment_ptr) });

    let cb_max_token = unsafe { (*pkg_info).cb_max_token };

    assert_eq!(unsafe { FreeContextBuffer(pkg_info.cast()) }, 0);

    let user = user.encode_utf16().collect::<Vec<_>>();
    let domain = "domain".encode_utf16().collect::<Vec<_>>();
    let password = "password".encode_utf16().collect::<Vec<_>>();

    let pkg_list = pkg_list.encode_utf16().collect::<Vec<_>>();

    let mut credentials = SecWinntAuthIdentityExW {
        version: SEC_WINNT_AUTH_IDENTITY_VERSION,
        length: size_of::<SecWinntAuthIdentityExW>()
            .try_into()
            .expect("size of SecWinntAuthIdentityExW is a valid u32"),
        user: user.as_ptr(),
        user_length: user.len().try_into().expect("user length is a valid u32"),
        domain: domain.as_ptr(),
        domain_length: domain.len().try_into().expect("domain length is a valid u32"),
        password: password.as_ptr(),
        password_length: password.len().try_into().expect("password length is a valid u32"),
        flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
        package_list: pkg_list.as_ptr(),
        package_list_length: pkg_list.len().try_into().expect("package list length is a valid u32"),
    };

    let mut cred_handle = empty_handle();

    let status = unsafe {
        AcquireCredentialsHandleW(
            null_mut(),
            pkg_name.as_mut_ptr(),
            SECPKG_CRED_OUTBOUND,
            null::<c_void>(),
            (&raw mut credentials).cast(),
            dummy,
            null::<c_void>(),
            &mut cred_handle,
            null_mut(),
        )
    };
    assert_eq!(status, 0);

    let mut sec_context = empty_handle();
    let mut new_sec_context = empty_handle();
    let mut target_name = "TERMSRV/test_user@example.com\0".encode_utf16().collect::<Vec<_>>();
    let mut attrs = 0;

    let mut out_buffer = vec![0; cb_max_token.try_into().expect("cb_max_token is a valid usize")];
    let mut out_sec_buffer = SecBuffer {
        cb_buffer: cb_max_token,
        buffer_type: SECBUFFER_TOKEN,
        pv_buffer: out_buffer.as_mut_ptr(),
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

    let initialize_status = unsafe {
        InitializeSecurityContextW(
            &mut cred_handle,
            &mut sec_context,
            target_name.as_mut_ptr(),
            0,
            0,
            SECURITY_NATIVE_DREP,
            &mut in_buffer_desk,
            0,
            &mut new_sec_context,
            &mut out_buffer_desk,
            &mut attrs,
            null_mut(),
        )
    };

    assert_eq!(unsafe { FreeCredentialsHandle(&mut cred_handle) }, 0);

    if initialize_status == ContinueNeeded.to_u32().unwrap() {
        assert_eq!(unsafe { DeleteSecurityContext(&mut new_sec_context) }, 0);
    }

    initialize_status
}

#[test]
fn initialize_negotiate_security_context_fail() {
    let status = initialize_negotiate_security_context_with_package_list("user_fail", "N");
    assert_eq!(status, ErrorKind::NoCredentials.to_u32().unwrap());
}

#[test]
fn initialize_negotiate_security_context_success() {
    let status = initialize_negotiate_security_context_with_package_list("user_success", "NTLM,N");
    assert_eq!(status, ContinueNeeded.to_u32().unwrap());
}

/// Performs a full NTLM handshake using the wide FFI functions: the client
/// (`InitializeSecurityContextW`) and the server (`AcceptSecurityContext`) exchange security
/// tokens until both security contexts are established.
#[cfg(not(miri))]
#[test]
fn initialize_security_context_w() {
    const PASSWORD: &str = "password";
    let capture = LogCapture::start(tracing::Level::DEBUG);
    LogCapture::record_secret("password", PASSWORD.as_bytes());

    let mut pkg_name = "NTLM\0".encode_utf16().collect::<Vec<_>>();
    let mut pkg_info_ptr: PSecPkgInfoW = null_mut::<SecPkgInfoW>();

    let status = unsafe { QuerySecurityPackageInfoW(pkg_name.as_ptr(), &mut pkg_info_ptr) };
    assert_eq!(status, 0);

    let pkg_info = unsafe { pkg_info_ptr.as_mut() }.expect("pkg_info is not null");

    // We left all `println`s on purpose:
    // to simulate any memory access to the allocated memory.
    println!("{pkg_info:?}");
    println!(
        "{:?}",
        unsafe { U16CString::from_ptr_str(pkg_info.name) }
            .to_string()
            .expect("package name returned by QuerySecurityPackageInfoW is valid UTF-16")
    );
    println!(
        "{:?}",
        unsafe { U16CString::from_ptr_str(pkg_info.comment) }
            .to_string()
            .expect("package comment returned by QuerySecurityPackageInfoW is valid UTF-16")
    );

    let cb_max_token = pkg_info.cb_max_token;

    let pv_context_buffer = pkg_info_ptr.cast();
    assert_eq!(unsafe { FreeContextBuffer(pv_context_buffer) }, 0);

    let mut pc_packages = 0;
    let mut packages: PSecPkgInfoW = null_mut::<SecPkgInfoW>();

    let status = unsafe { EnumerateSecurityPackagesW(&mut pc_packages, &mut packages) };
    assert_eq!(status, 0);

    for i in 0..usize::try_from(pc_packages).expect("pc_packages is a valid usize") {
        let pkg_info = unsafe { packages.add(i) };
        let pkg_info = unsafe { pkg_info.as_ref() }.expect("pkg_info is not null");

        println!("{pkg_info:?}");
        println!(
            "{:?}",
            unsafe { U16CString::from_ptr_str(pkg_info.name) }
                .to_string()
                .expect("package name returned by EnumerateSecurityPackagesW is valid UTF-16")
        );
        println!(
            "{:?}",
            unsafe { U16CString::from_ptr_str(pkg_info.comment) }
                .to_string()
                .expect("package comment returned by EnumerateSecurityPackagesW is valid UTF-16")
        );
    }

    assert_eq!(unsafe { FreeContextBuffer(packages.cast()) }, 0);

    let user = "user".encode_utf16().collect::<Vec<_>>();
    let domain = "domain".encode_utf16().collect::<Vec<_>>();
    let password = PASSWORD.encode_utf16().collect::<Vec<_>>();

    let user_length = user.len().try_into().expect("user length is a valid u32");
    let domain_length = domain.len().try_into().expect("domain length is a valid u32");
    let password_length = password.len().try_into().expect("password length is a valid u32");
    let credentials = SecWinntAuthIdentityW {
        user: user.as_ptr(),
        user_length,
        domain: domain.as_ptr(),
        domain_length,
        password: password.as_ptr(),
        password_length,
        flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
    };

    let mut client_cred_handle = empty_handle();
    let mut server_cred_handle = empty_handle();

    let status = unsafe {
        AcquireCredentialsHandleW(
            null_mut(),
            pkg_name.as_mut_ptr(),
            SECPKG_CRED_OUTBOUND,
            null::<c_void>(),
            ptr::from_ref(&credentials).cast(),
            dummy,
            null::<c_void>(),
            &mut client_cred_handle,
            null_mut(),
        )
    };
    assert_eq!(status, 0);

    let status = unsafe {
        AcquireCredentialsHandleW(
            null_mut(),
            pkg_name.as_mut_ptr(),
            SECPKG_CRED_INBOUND,
            null::<c_void>(),
            ptr::from_ref(&credentials).cast(),
            dummy,
            null::<c_void>(),
            &mut server_cred_handle,
            null_mut(),
        )
    };
    assert_eq!(status, 0);

    let mut client_sec_context = empty_handle();
    let mut server_sec_context = empty_handle();

    let mut target_name = "TERMSRV/some@example.com\0".encode_utf16().collect::<Vec<_>>();
    let mut attrs = 0;

    let mut client_out_buffer = vec![0; usize::try_from(cb_max_token).expect("cb_max_token is a valid usize")];
    let mut client_out_sec_buffer = SecBuffer {
        cb_buffer: cb_max_token,
        buffer_type: SECBUFFER_TOKEN,
        pv_buffer: client_out_buffer.as_mut_ptr(),
    };
    let mut client_out_buffer_desc = SecBufferDesc {
        ul_version: 0,
        c_buffers: 1,
        p_buffers: &mut client_out_sec_buffer,
    };

    let mut server_out_buffer = vec![0; usize::try_from(cb_max_token).expect("cb_max_token is a valid usize")];
    let mut server_out_sec_buffer = SecBuffer {
        cb_buffer: cb_max_token,
        buffer_type: SECBUFFER_TOKEN,
        pv_buffer: server_out_buffer.as_mut_ptr(),
    };
    let mut server_out_buffer_desc = SecBufferDesc {
        ul_version: 0,
        c_buffers: 1,
        p_buffers: &mut server_out_sec_buffer,
    };

    for iteration in 1..=MAX_AUTH_STEPS {
        // Client side.
        let mut client_new_sec_context = empty_handle();

        let client_status = unsafe {
            InitializeSecurityContextW(
                &mut client_cred_handle,
                &mut client_sec_context,
                target_name.as_mut_ptr(),
                0,
                0,
                SECURITY_NATIVE_DREP,
                &mut server_out_buffer_desc,
                0,
                &mut client_new_sec_context,
                &mut client_out_buffer_desc,
                &mut attrs,
                null_mut(),
            )
        };

        if iteration == 1 {
            // The NTLM client always needs at least one more token exchange after the negotiate message.
            assert_eq!(client_status, ContinueNeeded.to_u32().unwrap());
        }
        assert!(
            is_handshake_status(client_status),
            "unexpected InitializeSecurityContextW status: {client_status:#x?}"
        );
        assert!(!client_out_buffer_desc.p_buffers.is_null());

        if client_new_sec_context.dw_lower != 0 || client_new_sec_context.dw_upper != 0 {
            client_sec_context = client_new_sec_context;
        }

        // Server side.
        let mut server_new_sec_context = empty_handle();

        let server_status = unsafe {
            AcceptSecurityContext(
                &mut server_cred_handle,
                &mut server_sec_context,
                &mut client_out_buffer_desc,
                0,
                SECURITY_NATIVE_DREP,
                &mut server_new_sec_context,
                &mut server_out_buffer_desc,
                &mut attrs,
                null_mut(),
            )
        };

        assert!(
            is_handshake_status(server_status),
            "unexpected AcceptSecurityContext status: {server_status:#x?}"
        );
        assert!(!server_out_buffer_desc.p_buffers.is_null());

        if server_new_sec_context.dw_lower != 0 || server_new_sec_context.dw_upper != 0 {
            server_sec_context = server_new_sec_context;
        }

        if client_status == SecurityStatus::Ok.to_u32().unwrap()
            && server_status == SecurityStatus::CompleteNeeded.to_u32().unwrap()
        {
            let status =
                unsafe { crate::sspi::common::CompleteAuthToken(&mut server_sec_context, &mut server_out_buffer_desc) };
            assert_eq!(status, 0);

            // Both security contexts are established: they must be usable.
            assert_ntlm_context_sizes(&mut client_sec_context);
            assert_ntlm_context_sizes(&mut server_sec_context);

            assert_eq!(unsafe { DeleteSecurityContext(&mut client_sec_context) }, 0);

            assert_eq!(unsafe { DeleteSecurityContext(&mut server_sec_context) }, 0);

            assert_eq!(unsafe { FreeCredentialsHandle(&mut client_cred_handle) }, 0);

            assert_eq!(unsafe { FreeCredentialsHandle(&mut server_cred_handle) }, 0);

            capture.assert_no_secrets();
            return;
        }
    }

    panic!("the security context has not been established in {MAX_AUTH_STEPS} iterations");
}

/// The same as the [initialize_security_context_w] test but using the ANSI FFI functions.
#[cfg(not(miri))]
#[test]
fn initialize_security_context_a() {
    const PASSWORD: &str = "password";
    let capture = LogCapture::start(tracing::Level::DEBUG);
    LogCapture::record_secret("password", PASSWORD.as_bytes());

    let pkg_name = "NTLM\0";
    let mut pkg_info_ptr: PSecPkgInfoA = null_mut::<SecPkgInfoA>();

    let status = unsafe { QuerySecurityPackageInfoA(pkg_name.as_ptr().cast(), &mut pkg_info_ptr) };
    assert_eq!(status, 0);

    let pkg_info = unsafe { pkg_info_ptr.as_mut() }.expect("pkg_info is not null");

    // We left all `println`s on purpose:
    // to simulate any memory access to the allocated memory.
    println!("{pkg_info:?}");
    println!("{:?}", unsafe { CStr::from_ptr(pkg_info.name) });
    println!("{:?}", unsafe { CStr::from_ptr(pkg_info.comment) });

    let cb_max_token = pkg_info.cb_max_token;

    let pv_context_buffer = pkg_info_ptr.cast();
    assert_eq!(unsafe { FreeContextBuffer(pv_context_buffer) }, 0);

    let mut pc_packages = 0;
    let mut packages: PSecPkgInfoA = null_mut::<SecPkgInfoA>();

    let status = unsafe { EnumerateSecurityPackagesA(&mut pc_packages, &mut packages) };
    assert_eq!(status, 0);

    for i in 0..usize::try_from(pc_packages).expect("pc_packages is a valid usize") {
        let pkg_info = unsafe { packages.add(i) };
        let pkg_info = unsafe { pkg_info.as_ref() }.expect("pkg_info is not null");

        println!("{pkg_info:?}");
        println!("{:?}", unsafe { CStr::from_ptr(pkg_info.name) });
        println!("{:?}", unsafe { CStr::from_ptr(pkg_info.comment) });
    }

    assert_eq!(unsafe { FreeContextBuffer(packages.cast()) }, 0);

    let user = "user";
    let domain = "domain";
    let password = PASSWORD;

    let user_length = user.len().try_into().expect("user length is a valid u32");
    let domain_length = domain.len().try_into().expect("domain length is a valid u32");
    let password_length = password.len().try_into().expect("password length is a valid u32");
    let credentials = SecWinntAuthIdentityA {
        user: user.as_ptr().cast(),
        user_length,
        domain: domain.as_ptr().cast(),
        domain_length,
        password: password.as_ptr().cast(),
        password_length,
        flags: SEC_WINNT_AUTH_IDENTITY_ANSI,
    };

    let mut client_cred_handle = empty_handle();
    let mut server_cred_handle = empty_handle();

    let status = unsafe {
        AcquireCredentialsHandleA(
            null_mut(),
            pkg_name.as_ptr().cast(),
            SECPKG_CRED_OUTBOUND,
            null::<c_void>(),
            ptr::from_ref(&credentials).cast(),
            dummy,
            null::<c_void>(),
            &mut client_cred_handle,
            null_mut(),
        )
    };
    assert_eq!(status, 0);

    let status = unsafe {
        AcquireCredentialsHandleA(
            null_mut(),
            pkg_name.as_ptr().cast(),
            SECPKG_CRED_INBOUND,
            null::<c_void>(),
            ptr::from_ref(&credentials).cast(),
            dummy,
            null::<c_void>(),
            &mut server_cred_handle,
            null_mut(),
        )
    };
    assert_eq!(status, 0);

    let mut client_sec_context = empty_handle();
    let mut server_sec_context = empty_handle();

    let target_name = "TERMSRV/some@example.com\0";
    let mut attrs = 0;

    let mut client_out_buffer = vec![0; usize::try_from(cb_max_token).expect("cb_max_token is a valid usize")];
    let mut client_out_sec_buffer = SecBuffer {
        cb_buffer: cb_max_token,
        buffer_type: SECBUFFER_TOKEN,
        pv_buffer: client_out_buffer.as_mut_ptr(),
    };
    let mut client_out_buffer_desc = SecBufferDesc {
        ul_version: 0,
        c_buffers: 1,
        p_buffers: &mut client_out_sec_buffer,
    };

    let mut server_out_buffer = vec![0; usize::try_from(cb_max_token).expect("cb_max_token is a valid usize")];
    let mut server_out_sec_buffer = SecBuffer {
        cb_buffer: cb_max_token,
        buffer_type: SECBUFFER_TOKEN,
        pv_buffer: server_out_buffer.as_mut_ptr(),
    };
    let mut server_out_buffer_desc = SecBufferDesc {
        ul_version: 0,
        c_buffers: 1,
        p_buffers: &mut server_out_sec_buffer,
    };

    for iteration in 1..=MAX_AUTH_STEPS {
        // Client side.
        let mut client_new_sec_context = empty_handle();

        let client_status = unsafe {
            InitializeSecurityContextA(
                &mut client_cred_handle,
                &mut client_sec_context,
                target_name.as_ptr().cast(),
                0,
                0,
                SECURITY_NATIVE_DREP,
                &mut server_out_buffer_desc,
                0,
                &mut client_new_sec_context,
                &mut client_out_buffer_desc,
                &mut attrs,
                null_mut(),
            )
        };

        if iteration == 1 {
            // The NTLM client always needs at least one more token exchange after the negotiate message.
            assert_eq!(client_status, ContinueNeeded.to_u32().unwrap());
        }
        assert!(
            is_handshake_status(client_status),
            "unexpected InitializeSecurityContextA status: {client_status:#x?}"
        );
        assert!(!client_out_buffer_desc.p_buffers.is_null());

        if client_new_sec_context.dw_lower != 0 || client_new_sec_context.dw_upper != 0 {
            client_sec_context = client_new_sec_context;
        }

        // Server side.
        let mut server_new_sec_context = empty_handle();

        let server_status = unsafe {
            AcceptSecurityContext(
                &mut server_cred_handle,
                &mut server_sec_context,
                &mut client_out_buffer_desc,
                0,
                SECURITY_NATIVE_DREP,
                &mut server_new_sec_context,
                &mut server_out_buffer_desc,
                &mut attrs,
                null_mut(),
            )
        };

        assert!(
            is_handshake_status(server_status),
            "unexpected AcceptSecurityContext status: {server_status:#x?}"
        );
        assert!(!server_out_buffer_desc.p_buffers.is_null());

        if server_new_sec_context.dw_lower != 0 || server_new_sec_context.dw_upper != 0 {
            server_sec_context = server_new_sec_context;
        }

        if client_status == SecurityStatus::Ok.to_u32().unwrap()
            && server_status == SecurityStatus::CompleteNeeded.to_u32().unwrap()
        {
            let status =
                unsafe { crate::sspi::common::CompleteAuthToken(&mut server_sec_context, &mut server_out_buffer_desc) };
            assert_eq!(status, 0);

            // Both security contexts are established: they must be usable.
            assert_ntlm_context_sizes(&mut client_sec_context);
            assert_ntlm_context_sizes(&mut server_sec_context);

            assert_eq!(unsafe { DeleteSecurityContext(&mut client_sec_context) }, 0);

            assert_eq!(unsafe { DeleteSecurityContext(&mut server_sec_context) }, 0);

            assert_eq!(unsafe { FreeCredentialsHandle(&mut client_cred_handle) }, 0);

            assert_eq!(unsafe { FreeCredentialsHandle(&mut server_cred_handle) }, 0);

            capture.assert_no_secrets();
            return;
        }
    }

    panic!("the security context has not been established in {MAX_AUTH_STEPS} iterations");
}

/// Also run it under [Miri](https://github.com/rust-lang/miri): `cargo +nightly miri test`.
#[test]
fn acquire_credentials_handle_w_null_credentials() {
    let pkg_name = "NTLM\0".encode_utf16().collect::<Vec<_>>();

    let user = "user".encode_utf16().collect::<Vec<_>>();
    let domain = "domain".encode_utf16().collect::<Vec<_>>();
    let password = "password".encode_utf16().collect::<Vec<_>>();

    let user_length = user.len().try_into().expect("user length is a valid u32");
    let domain_length = domain.len().try_into().expect("domain length is a valid u32");
    let password_length = password.len().try_into().expect("password length is a valid u32");
    let credentials = vec![
        SecWinntAuthIdentityW {
            user: null(),
            user_length: 0,
            domain: domain.as_ptr(),
            domain_length,
            password: password.as_ptr(),
            password_length,
            flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
        },
        SecWinntAuthIdentityW {
            user: user.as_ptr(),
            user_length,
            domain: null(),
            domain_length: 0,
            password: password.as_ptr(),
            password_length,
            flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
        },
        SecWinntAuthIdentityW {
            user: user.as_ptr(),
            user_length,
            domain: domain.as_ptr(),
            domain_length,
            password: null(),
            password_length: 0,
            flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
        },
    ];

    for credentials in credentials {
        let mut cred_handle = empty_handle();

        let status = unsafe {
            AcquireCredentialsHandleW(
                null_mut(),
                pkg_name.as_ptr().cast(),
                SECPKG_CRED_OUTBOUND,
                null::<c_void>(),
                ptr::from_ref(&credentials).cast(),
                dummy,
                null::<c_void>(),
                &mut cred_handle,
                null_mut(),
            )
        };
        assert_eq!(status, 0);

        assert_eq!(unsafe { FreeCredentialsHandle(&mut cred_handle) }, 0);
    }
}

/// Also run it under [Miri](https://github.com/rust-lang/miri): `cargo +nightly miri test`.
#[test]
fn acquire_credentials_handle_w_empty_credentials() {
    let pkg_name = "NTLM\0".encode_utf16().collect::<Vec<_>>();

    let user = "".encode_utf16().collect::<Vec<_>>();
    let domain = "".encode_utf16().collect::<Vec<_>>();
    let password = "".encode_utf16().collect::<Vec<_>>();

    let user_length = user.len().try_into().expect("user length is a valid u32");
    let domain_length = domain.len().try_into().expect("domain length is a valid u32");
    let password_length = password.len().try_into().expect("password length is a valid u32");
    let credentials = SecWinntAuthIdentityW {
        user: user.as_ptr(),
        user_length,
        domain: domain.as_ptr(),
        domain_length,
        password: password.as_ptr(),
        password_length,
        flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
    };

    let mut cred_handle = empty_handle();

    let status = unsafe {
        AcquireCredentialsHandleW(
            null_mut(),
            pkg_name.as_ptr().cast(),
            SECPKG_CRED_OUTBOUND,
            null::<c_void>(),
            ptr::from_ref(&credentials).cast(),
            dummy,
            null::<c_void>(),
            &mut cred_handle,
            null_mut(),
        )
    };
    assert_eq!(status, 0);

    assert_eq!(unsafe { FreeCredentialsHandle(&mut cred_handle) }, 0);
}

/// Also run it under [Miri](https://github.com/rust-lang/miri): `cargo +nightly miri test`.
#[test]
fn acquire_credentials_handle_a_null_credentials() {
    let pkg_name = "NTLM\0";

    let user = "user";
    let domain = "domain";
    let password = "password";

    let user_length = user.len().try_into().expect("user length is a valid u32");
    let domain_length = domain.len().try_into().expect("domain length is a valid u32");
    let password_length = password.len().try_into().expect("password length is a valid u32");
    let credentials = vec![
        SecWinntAuthIdentityA {
            user: null(),
            user_length: 0,
            domain: domain.as_ptr().cast(),
            domain_length,
            password: password.as_ptr().cast(),
            password_length,
            flags: SEC_WINNT_AUTH_IDENTITY_ANSI,
        },
        SecWinntAuthIdentityA {
            user: user.as_ptr().cast(),
            user_length,
            domain: null(),
            domain_length: 0,
            password: password.as_ptr().cast(),
            password_length,
            flags: SEC_WINNT_AUTH_IDENTITY_ANSI,
        },
        SecWinntAuthIdentityA {
            user: user.as_ptr().cast(),
            user_length,
            domain: domain.as_ptr().cast(),
            domain_length,
            password: null(),
            password_length: 0,
            flags: SEC_WINNT_AUTH_IDENTITY_ANSI,
        },
    ];

    for credentials in credentials {
        let mut cred_handle = empty_handle();

        let status = unsafe {
            AcquireCredentialsHandleA(
                null_mut(),
                pkg_name.as_ptr().cast(),
                SECPKG_CRED_OUTBOUND,
                null::<c_void>(),
                ptr::from_ref(&credentials).cast(),
                dummy,
                null::<c_void>(),
                &mut cred_handle,
                null_mut(),
            )
        };
        assert_eq!(status, 0);

        assert_eq!(unsafe { FreeCredentialsHandle(&mut cred_handle) }, 0);
    }
}

/// Also run it under [Miri](https://github.com/rust-lang/miri): `cargo +nightly miri test`.
#[test]
fn acquire_credentials_handle_a_empty_credentials() {
    let pkg_name = "NTLM\0";

    let user = "";
    let domain = "";
    let password = "";

    let user_length = user.len().try_into().expect("user length is a valid u32");
    let domain_length = domain.len().try_into().expect("domain length is a valid u32");
    let password_length = password.len().try_into().expect("password length is a valid u32");
    let credentials = SecWinntAuthIdentityA {
        user: user.as_ptr().cast(),
        user_length,
        domain: domain.as_ptr().cast(),
        domain_length,
        password: password.as_ptr().cast(),
        password_length,
        flags: SEC_WINNT_AUTH_IDENTITY_ANSI,
    };

    let mut cred_handle = empty_handle();

    let status = unsafe {
        AcquireCredentialsHandleA(
            null_mut(),
            pkg_name.as_ptr().cast(),
            SECPKG_CRED_OUTBOUND,
            null::<c_void>(),
            ptr::from_ref(&credentials).cast(),
            dummy,
            null::<c_void>(),
            &mut cred_handle,
            null_mut(),
        )
    };
    assert_eq!(status, 0);

    assert_eq!(unsafe { FreeCredentialsHandle(&mut cred_handle) }, 0);
}

#[test]
fn query_context_session_key() {
    use std::slice::from_raw_parts;

    use ffi_types::sspi::SecPkgContextSessionKey;

    use crate::sspi::sec_handle::SECPKG_ATTR_SESSION_KEY;

    // We use the Kerberos fake_client because we need an established security context
    // to query the session key.
    let mut sec_handle = kerberos_sec_handle();

    let mut session_key = SecPkgContextSessionKey {
        session_key_len: 0,
        session_key: null_mut(),
    };

    let status = unsafe {
        QueryContextAttributesW(
            &mut sec_handle,
            SECPKG_ATTR_SESSION_KEY,
            ptr::from_mut(&mut session_key).cast(),
        )
    };
    assert_eq!(status, 0);

    // Print the session key
    let key = unsafe {
        from_raw_parts(
            session_key.session_key,
            session_key
                .session_key_len
                .try_into()
                .expect("session key length is a valid usize"),
        )
    };
    println!("Session key length: {}", session_key.session_key_len);
    println!("Session key: {:02x?}", key);

    // Free the key buffer using FreeContextBuffer
    assert_eq!(unsafe { FreeContextBuffer(session_key.session_key.cast()) }, 0);

    assert_eq!(unsafe { DeleteSecurityContext(&mut sec_handle) }, 0);
}

#[test]
fn query_context_names() {
    use ffi_types::sspi::{SecPkgContextNamesA, SecPkgContextNamesW};

    use crate::sspi::sec_handle::SECPKG_ATTR_NAMES;

    // We use the Kerberos fake_client because we need an established security context
    // to query the names.
    let mut sec_handle = kerberos_sec_handle();

    let mut names_w = SecPkgContextNamesW { user_name: null_mut() };

    let status =
        unsafe { QueryContextAttributesW(&mut sec_handle, SECPKG_ATTR_NAMES, ptr::from_mut(&mut names_w).cast()) };
    assert_eq!(status, 0);
    assert!(!names_w.user_name.is_null());

    let username_w = unsafe { U16CString::from_ptr_str(names_w.user_name) }
        .to_string()
        .expect("username should be valid UTF-16");
    println!("Username (wide): {}", username_w);

    assert_eq!(unsafe { FreeContextBuffer(names_w.user_name.cast()) }, 0);

    let mut names_a = SecPkgContextNamesA { user_name: null_mut() };

    let status =
        unsafe { QueryContextAttributesA(&mut sec_handle, SECPKG_ATTR_NAMES, ptr::from_mut(&mut names_a).cast()) };
    assert_eq!(status, 0);
    assert!(!names_a.user_name.is_null());

    let username_a = unsafe { CStr::from_ptr(names_a.user_name) }
        .to_str()
        .expect("username should be valid UTF-8");
    println!("Username (ANSI): {}", username_a);

    assert_eq!(unsafe { FreeContextBuffer(names_a.user_name.cast()) }, 0);

    assert_eq!(unsafe { DeleteSecurityContext(&mut sec_handle) }, 0);
}

fn acquire_ntlm_credentials_handle(user: &str, domain: &str) -> SecHandle {
    acquire_ntlm_credentials_handle_with_password(user, domain, "password")
}

fn acquire_ntlm_credentials_handle_with_password(user: &str, domain: &str, password: &str) -> SecHandle {
    let pkg_name = "NTLM\0".encode_utf16().collect::<Vec<_>>();

    let user = user.encode_utf16().collect::<Vec<_>>();
    let domain = domain.encode_utf16().collect::<Vec<_>>();
    let password = password.encode_utf16().collect::<Vec<_>>();

    let credentials = SecWinntAuthIdentityW {
        user: user.as_ptr(),
        user_length: user.len().try_into().expect("user length is a valid u32"),
        domain: domain.as_ptr(),
        domain_length: domain.len().try_into().expect("domain length is a valid u32"),
        password: password.as_ptr(),
        password_length: password.len().try_into().expect("password length is a valid u32"),
        flags: SEC_WINNT_AUTH_IDENTITY_UNICODE,
    };

    let mut cred_handle = empty_handle();

    let status = unsafe {
        AcquireCredentialsHandleW(
            null_mut(),
            pkg_name.as_ptr(),
            SECPKG_CRED_OUTBOUND,
            null::<c_void>(),
            ptr::from_ref(&credentials).cast(),
            dummy,
            null::<c_void>(),
            &mut cred_handle,
            null_mut(),
        )
    };
    assert_eq!(status, 0);

    cred_handle
}

fn free_credentials_handle(cred_handle: &mut SecHandle) {
    assert_eq!(unsafe { FreeCredentialsHandle(cred_handle) }, 0);
}

fn initialize_ntlm_security_context(cred_handle: &mut SecHandle) -> u32 {
    const OUTPUT_LEN: usize = 4096;
    let target = "TERMSRV/example.com\0".encode_utf16().collect::<Vec<_>>();
    let mut output = vec![0; OUTPUT_LEN];
    let mut buffer = SecBuffer {
        cb_buffer: OUTPUT_LEN.try_into().unwrap(),
        buffer_type: SECBUFFER_TOKEN,
        pv_buffer: output.as_mut_ptr().cast(),
    };
    let mut buffer_desc = SecBufferDesc {
        ul_version: 0,
        c_buffers: 1,
        p_buffers: &mut buffer,
    };
    let mut context = empty_handle();
    let mut new_context = empty_handle();
    let mut attrs = 0;
    let status = unsafe {
        InitializeSecurityContextW(
            cred_handle,
            &mut context,
            target.as_ptr(),
            0,
            0,
            SECURITY_NATIVE_DREP,
            null_mut(),
            0,
            &mut new_context,
            &mut buffer_desc,
            &mut attrs,
            null_mut(),
        )
    };
    if status == ContinueNeeded.to_u32().unwrap() {
        assert_eq!(unsafe { DeleteSecurityContext(&mut new_context) }, 0);
    }
    status
}

fn registry_credentials(user: &str) -> CredentialsHandle {
    CredentialsHandle {
        credentials: CredentialsBuffers::AuthIdentity(AuthIdentityBuffers::new(
            Utf16String::from_str(user),
            Utf16String::from_str("domain"),
            Utf16String::from_str("password"),
        )),
        security_package_name: "NTLM".to_owned(),
        attributes: CredentialsAttributes::default(),
    }
}

#[test]
fn acquire_credentials_handle_is_distinct_while_live() {
    let mut first = acquire_ntlm_credentials_handle("stable_user", "stable_domain");
    let mut second = acquire_ntlm_credentials_handle("stable_user", "stable_domain");
    let mut third = acquire_ntlm_credentials_handle("stable_user", "stable_domain");

    assert_ne!(first.dw_lower, second.dw_lower);
    assert_ne!(second.dw_lower, third.dw_lower);
    assert_ne!(first.dw_lower, third.dw_lower);

    let second_handle = second.dw_lower;
    free_credentials_handle(&mut first);
    assert!(credentials_by_handle(second_handle).unwrap().is_some());
    assert_eq!(
        unsafe { FreeCredentialsHandle(&mut first) },
        ErrorKind::InvalidHandle.to_u32().unwrap()
    );

    free_credentials_handle(&mut second);
    free_credentials_handle(&mut third);
}

#[test]
fn acquiring_same_user_with_different_password_does_not_replace_credentials_or_attributes() {
    let mut bad = acquire_ntlm_credentials_handle_with_password("same_user", "same_domain", "badpass");
    let mut workstation = "first-workstation\0".encode_utf16().collect::<Vec<_>>();
    assert_eq!(
        unsafe { SetCredentialsAttributesW(&mut bad, 1, workstation.as_mut_ptr().cast(), 0) },
        0
    );

    let mut good = acquire_ntlm_credentials_handle_with_password("same_user", "same_domain", "goodpass");
    assert_ne!(bad.dw_lower, good.dw_lower);

    let bad_credentials = credentials_by_handle(bad.dw_lower).unwrap().unwrap();
    let good_credentials = credentials_by_handle(good.dw_lower).unwrap().unwrap();
    assert_eq!(
        bad_credentials
            .credentials
            .as_auth_identity()
            .unwrap()
            .password
            .as_ref()
            .0,
        Utf16String::from_str("badpass")
    );
    assert_eq!(
        good_credentials
            .credentials
            .as_auth_identity()
            .unwrap()
            .password
            .as_ref()
            .0,
        Utf16String::from_str("goodpass")
    );
    assert_eq!(
        bad_credentials.attributes.workstation.as_deref(),
        Some("first-workstation")
    );
    assert_eq!(good_credentials.attributes.workstation, None);

    let bad_handle = bad.dw_lower;
    free_credentials_handle(&mut bad);
    assert!(credentials_by_handle(bad_handle).unwrap().is_none());
    assert!(credentials_by_handle(good.dw_lower).unwrap().is_some());
    free_credentials_handle(&mut good);

    let mut reacquired_good = acquire_ntlm_credentials_handle_with_password("same_user", "same_domain", "goodpass");
    assert_ne!(reacquired_good.dw_lower, bad_handle);
    assert!(credentials_by_handle(bad_handle).unwrap().is_none());
    free_credentials_handle(&mut reacquired_good);
}

#[test]
fn initialize_security_context_rejects_freed_copy_with_a_different_password_live() {
    let mut bad = acquire_ntlm_credentials_handle_with_password("copied_user", "domain", "badpass");
    let mut stale = SecHandle {
        dw_lower: bad.dw_lower,
        dw_upper: bad.dw_upper,
    };
    let mut good = acquire_ntlm_credentials_handle_with_password("copied_user", "domain", "goodpass");
    free_credentials_handle(&mut bad);

    assert_eq!(
        initialize_ntlm_security_context(&mut stale),
        ErrorKind::InvalidHandle.to_u32().unwrap()
    );
    assert_eq!(
        initialize_ntlm_security_context(&mut good),
        ContinueNeeded.to_u32().unwrap()
    );
    free_credentials_handle(&mut good);
}

#[test]
fn initialize_security_context_rejects_freed_copy_while_identical_credentials_are_live() {
    let mut first = acquire_ntlm_credentials_handle("same_secret_user", "domain");
    let mut stale = SecHandle {
        dw_lower: first.dw_lower,
        dw_upper: first.dw_upper,
    };
    let mut second = acquire_ntlm_credentials_handle("same_secret_user", "domain");
    free_credentials_handle(&mut first);

    assert_eq!(
        initialize_ntlm_security_context(&mut stale),
        ErrorKind::InvalidHandle.to_u32().unwrap()
    );
    assert_eq!(
        initialize_ntlm_security_context(&mut second),
        ContinueNeeded.to_u32().unwrap()
    );
    free_credentials_handle(&mut second);
}

#[test]
fn initialize_security_context_accepts_reactivated_freed_copy() {
    let mut first = acquire_ntlm_credentials_handle("reactivated_user", "domain");
    let mut stale = SecHandle {
        dw_lower: first.dw_lower,
        dw_upper: first.dw_upper,
    };
    free_credentials_handle(&mut first);

    let mut second = acquire_ntlm_credentials_handle("reactivated_user", "domain");
    assert_eq!(stale.dw_lower, second.dw_lower);
    assert_eq!(
        initialize_ntlm_security_context(&mut stale),
        ContinueNeeded.to_u32().unwrap()
    );
    free_credentials_handle(&mut second);
}

#[test]
fn released_handle_reuse_ignores_changed_package_list() {
    let mut registry = CredentialsRegistry::default();
    let mut first_credentials = registry_credentials("package_list_user");
    first_credentials.attributes.package_list = Some("NTLM".to_owned());
    let first = registry.register(first_credentials).unwrap();
    assert!(registry.release(first));

    let second = registry.register(registry_credentials("package_list_user")).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        registry.live.get(&second).unwrap().credentials.attributes.package_list,
        None
    );
}

#[test]
fn released_handle_cache_evicts_oldest_entry_at_capacity() {
    let mut registry = CredentialsRegistry::default();
    let oldest = registry.register(registry_credentials("evicted_user")).unwrap();
    assert!(registry.release(oldest));

    for index in 0..MAX_RELEASED_CREDENTIALS - 1 {
        let handle = registry
            .register(registry_credentials(&format!("cache_user_{index}")))
            .unwrap();
        assert!(registry.release(handle));
    }
    assert_eq!(registry.released.len(), MAX_RELEASED_CREDENTIALS);
    assert_eq!(registry.released.front().unwrap().1, oldest);

    let newest = registry
        .register(registry_credentials(&format!(
            "cache_user_{}",
            MAX_RELEASED_CREDENTIALS - 1
        )))
        .unwrap();
    assert!(registry.release(newest));
    assert_eq!(registry.released.len(), MAX_RELEASED_CREDENTIALS);
    assert!(registry.released.iter().all(|(_, handle)| *handle != oldest));

    let reused = registry
        .register(registry_credentials(&format!(
            "cache_user_{}",
            MAX_RELEASED_CREDENTIALS - 1
        )))
        .unwrap();
    assert_eq!(reused, newest);
    assert_ne!(registry.register(registry_credentials("evicted_user")).unwrap(), oldest);
}

#[test]
fn acquire_credentials_handle_is_stable_after_free() {
    let mut cred_handle = acquire_ntlm_credentials_handle("freed_user", "freed_domain");
    let expected_handle = cred_handle.dw_lower;
    free_credentials_handle(&mut cred_handle);

    for _ in 0..3 {
        let mut cred_handle = acquire_ntlm_credentials_handle("freed_user", "freed_domain");
        assert_eq!(cred_handle.dw_lower, expected_handle);
        free_credentials_handle(&mut cred_handle);
    }
}

#[test]
fn acquire_credentials_handle_differs_for_different_credentials() {
    let mut handles = ["user1", "user2", "user3"]
        .into_iter()
        .map(|user| acquire_ntlm_credentials_handle(user, "different_domain"))
        .collect::<Vec<_>>();

    let raw_handles = handles.iter().map(|handle| handle.dw_lower).collect::<Vec<_>>();
    for (index, handle) in raw_handles.iter().enumerate() {
        assert!(
            !raw_handles[index + 1..].contains(handle),
            "credentials handles must be different for different credentials: {raw_handles:?}"
        );
    }

    handles.iter_mut().for_each(free_credentials_handle);
}

#[test]
fn initialize_security_context_dw_lower_is_stable() {
    const OUT_BUFFER_LEN: usize = 4096;

    let mut cred_handle = acquire_ntlm_credentials_handle("context_user", "context_domain");

    let mut dw_lowers = Vec::new();

    for _ in 0..3 {
        let mut sec_context = empty_handle();
        let mut new_sec_context = empty_handle();
        let mut target_name = "TERMSRV/some@example.com\0".encode_utf16().collect::<Vec<_>>();
        let mut attrs = 0;

        let mut out_buffer = vec![0_u8; OUT_BUFFER_LEN];
        let mut out_sec_buffer = SecBuffer {
            cb_buffer: OUT_BUFFER_LEN.try_into().expect("out buffer length is a valid u32"),
            buffer_type: SECBUFFER_TOKEN,
            pv_buffer: out_buffer.as_mut_ptr().cast(),
        };
        let mut out_buffer_desc = SecBufferDesc {
            ul_version: 0,
            c_buffers: 1,
            p_buffers: &mut out_sec_buffer,
        };
        let mut in_buffer_desc = SecBufferDesc {
            ul_version: 0,
            c_buffers: 0,
            p_buffers: null_mut::<SecBuffer>(),
        };

        let status = unsafe {
            InitializeSecurityContextW(
                &mut cred_handle,
                &mut sec_context,
                target_name.as_mut_ptr(),
                0,
                0,
                SECURITY_NATIVE_DREP,
                &mut in_buffer_desc,
                0,
                &mut new_sec_context,
                &mut out_buffer_desc,
                &mut attrs,
                null_mut(),
            )
        };
        assert_eq!(status, ContinueNeeded.to_u32().unwrap());

        dw_lowers.push(new_sec_context.dw_lower);

        assert_eq!(unsafe { DeleteSecurityContext(&mut new_sec_context) }, 0);
    }

    assert!(
        dw_lowers.windows(2).all(|pair| pair[0] == pair[1]),
        "security context dw_lower must be the same for every context of the same package: {dw_lowers:?}"
    );

    free_credentials_handle(&mut cred_handle);
}

#[test]
fn query_context_attributes_sizes() {
    let mut ntlm_client_context = ntlm_sec_handle();
    assert_ntlm_context_sizes(&mut ntlm_client_context);
    assert_eq!(unsafe { DeleteSecurityContext(&mut ntlm_client_context) }, 0);

    let mut kerberos_client_context = kerberos_sec_handle();
    let sizes = query_context_sizes(&mut kerberos_client_context);
    assert_eq!(
        (
            sizes.cb_max_token,
            sizes.cb_max_signature,
            sizes.cb_block_size,
            sizes.cb_security_trailer
        ),
        (sspi::kerberos::PACKAGE_INFO.max_token_len, 16, 0, 60)
    );
    assert_eq!(unsafe { DeleteSecurityContext(&mut kerberos_client_context) }, 0);

    #[cfg(feature = "tsssp")]
    {
        let mut credssp_client_context = credssp_sec_handle();
        assert_ntlm_context_sizes(&mut credssp_client_context);
        assert_eq!(unsafe { DeleteSecurityContext(&mut credssp_client_context) }, 0);
    }
}

/// The `SECPKG_ATTR_SERVER_AUTH_FLAGS` attribute is used only by the CredSSP security package,
/// but our implementation does not depend on the security context type: the flags value is
/// always written into the caller-provided [SecPkgContextFlags] structure.
#[test]
fn query_context_attributes_server_auth_flags() {
    let mut flags = SecPkgContextFlags { flags: 0xffff_ffff };

    let mut ntlm_client_context = ntlm_sec_handle();

    let status = unsafe {
        QueryContextAttributesW(
            &mut ntlm_client_context,
            SECPKG_ATTR_SERVER_AUTH_FLAGS,
            ptr::from_mut(&mut flags).cast(),
        )
    };
    assert_eq!(status, 0);
    assert_eq!(flags.flags, 0);

    assert_eq!(unsafe { DeleteSecurityContext(&mut ntlm_client_context) }, 0);

    #[cfg(feature = "tsssp")]
    {
        let mut flags = SecPkgContextFlags { flags: 0xffff_ffff };

        let mut credssp_client_context = credssp_sec_handle();

        let status = unsafe {
            QueryContextAttributesW(
                &mut credssp_client_context,
                SECPKG_ATTR_SERVER_AUTH_FLAGS,
                ptr::from_mut(&mut flags).cast(),
            )
        };
        assert_eq!(status, 0);
        assert_eq!(flags.flags, 0);

        assert_eq!(unsafe { DeleteSecurityContext(&mut credssp_client_context) }, 0);
    }
}

#[test]
fn query_context_attributes_cert_trust_status() {
    let mut cert_trust_status = CertTrustStatus {
        dw_error_status: 0,
        dw_info_status: 0,
    };

    // Neither NTLM nor Kerberos support the `SECPKG_ATTR_CERT_TRUST_STATUS` attribute.
    let mut ntlm_client_context = ntlm_sec_handle();

    let status = unsafe {
        QueryContextAttributesW(
            &mut ntlm_client_context,
            SECPKG_ATTR_CERT_TRUST_STATUS,
            ptr::from_mut(&mut cert_trust_status).cast(),
        )
    };
    assert_eq!(
        status,
        ErrorKind::UnsupportedFunction
            .to_u32()
            .expect("ErrorKind is castable to u32")
    );

    assert_eq!(unsafe { DeleteSecurityContext(&mut ntlm_client_context) }, 0);

    #[cfg(feature = "tsssp")]
    {
        use sspi::{CertTrustErrorStatus, CertTrustInfoStatus};

        let mut credssp_client_context = credssp_sec_handle();

        let status = unsafe {
            QueryContextAttributesW(
                &mut credssp_client_context,
                SECPKG_ATTR_CERT_TRUST_STATUS,
                ptr::from_mut(&mut cert_trust_status).cast(),
            )
        };
        assert_eq!(status, 0);

        assert_eq!(cert_trust_status.dw_error_status, CertTrustErrorStatus::NO_ERROR.bits());
        assert_eq!(
            cert_trust_status.dw_info_status,
            CertTrustInfoStatus::IS_SELF_SIGNED.bits()
        );

        assert_eq!(unsafe { DeleteSecurityContext(&mut credssp_client_context) }, 0);
    }
}

/// Queries the `SECPKG_ATTR_PACKAGE_INFO` attribute using both the W and A entry points
/// and asserts the returned package info.
///
/// The caller owns the `SecPkgContext_PackageInfo` structure which contains only a pointer to
/// the package info allocated by the security package. So, the caller must free it using the
/// `FreeContextBuffer` function.
fn check_context_package_info(sec_context: &mut SecHandle, package_name: &str, comment: &str, max_token_len: u32) {
    check_context_package_info_w(sec_context, package_name, comment, max_token_len);
    check_context_package_info_a(sec_context, package_name, comment, max_token_len);
}

fn check_context_package_info_w(sec_context: &mut SecHandle, package_name: &str, comment: &str, max_token_len: u32) {
    let mut package_info: PSecPkgInfoW = null_mut::<SecPkgInfoW>();

    let status = unsafe {
        QueryContextAttributesW(
            sec_context,
            SECPKG_ATTR_PACKAGE_INFO,
            ptr::from_mut(&mut package_info).cast(),
        )
    };
    assert_eq!(status, 0);

    let package_info_ref = unsafe { package_info.as_ref() }.expect("package_info is not null");

    assert_eq!(package_info_ref.f_capabilities, PackageCapabilities::empty().bits());
    assert_eq!(package_info_ref.w_rpc_id, PACKAGE_ID_NONE);
    assert_eq!(package_info_ref.cb_max_token, max_token_len);
    assert_eq!(
        unsafe { U16CString::from_ptr_str(package_info_ref.name) }
            .to_string()
            .expect("package name must be valid UTF-16"),
        package_name
    );
    assert_eq!(
        unsafe { U16CString::from_ptr_str(package_info_ref.comment) }
            .to_string()
            .expect("package comment must be valid UTF-16"),
        comment
    );

    assert_eq!(unsafe { FreeContextBuffer(package_info.cast()) }, 0);
}

fn check_context_package_info_a(sec_context: &mut SecHandle, package_name: &str, comment: &str, max_token_len: u32) {
    let mut package_info: PSecPkgInfoA = null_mut::<SecPkgInfoA>();

    let status = unsafe {
        QueryContextAttributesA(
            sec_context,
            SECPKG_ATTR_PACKAGE_INFO,
            ptr::from_mut(&mut package_info).cast(),
        )
    };
    assert_eq!(status, 0);

    let package_info_ref = unsafe { package_info.as_ref() }.expect("package_info is not null");

    assert_eq!(package_info_ref.f_capabilities, PackageCapabilities::empty().bits());
    assert_eq!(package_info_ref.w_rpc_id, PACKAGE_ID_NONE);
    assert_eq!(package_info_ref.cb_max_token, max_token_len);
    assert_eq!(
        unsafe { CStr::from_ptr(package_info_ref.name) }
            .to_str()
            .expect("package name must be valid UTF-8"),
        package_name
    );
    assert_eq!(
        unsafe { CStr::from_ptr(package_info_ref.comment) }
            .to_str()
            .expect("package comment must be valid UTF-8"),
        comment
    );

    assert_eq!(unsafe { FreeContextBuffer(package_info.cast()) }, 0);
}

#[test]
fn query_context_attributes_package_info() {
    let mut ntlm_client_context = ntlm_sec_handle();
    check_context_package_info(&mut ntlm_client_context, "NTLM", "NTLM Security Package", 0xb48);
    assert_eq!(unsafe { DeleteSecurityContext(&mut ntlm_client_context) }, 0);

    let mut kerberos_client_context = kerberos_sec_handle();
    check_context_package_info(
        &mut kerberos_client_context,
        "Kerberos",
        "Kerberos Security Package",
        0xbb80,
    );
    assert_eq!(unsafe { DeleteSecurityContext(&mut kerberos_client_context) }, 0);

    #[cfg(feature = "tsssp")]
    {
        let mut credssp_client_context = credssp_sec_handle();
        check_context_package_info(
            &mut credssp_client_context,
            "CREDSSP",
            "CredSsp security package",
            0xbb81,
        );
        assert_eq!(unsafe { DeleteSecurityContext(&mut credssp_client_context) }, 0);
    }
}

#[test]
fn query_context_attributes_unsupported_attribute() {
    // We don't care about the buffer type: the attribute is not supported anyway.
    let mut buffer = 0_u32;

    let mut ntlm_client_context = ntlm_sec_handle();

    let status = unsafe {
        QueryContextAttributesW(
            &mut ntlm_client_context,
            0x50, // Unsupported attribute.
            ptr::from_mut(&mut buffer).cast(),
        )
    };
    assert_eq!(
        status,
        ErrorKind::UnsupportedFunction
            .to_u32()
            .expect("ErrorKind is castable to u32")
    );

    assert_eq!(unsafe { DeleteSecurityContext(&mut ntlm_client_context) }, 0);
}

#[test]
fn query_context_attributes_null_buffer() {
    let mut ntlm_client_context = ntlm_sec_handle();

    let status = unsafe { QueryContextAttributesW(&mut ntlm_client_context, SECPKG_ATTR_PACKAGE_INFO, null_mut()) };
    assert_eq!(
        status,
        ErrorKind::InvalidParameter
            .to_u32()
            .expect("ErrorKind is castable to u32")
    );

    assert_eq!(unsafe { DeleteSecurityContext(&mut ntlm_client_context) }, 0);
}

#[test]
fn initialize_security_context_should_fail_with_invalid_parameter() {
    let pkg_name = "NTLM\0".encode_utf16().collect::<Vec<_>>();
    let mut pkg_info_ptr: PSecPkgInfoW = null_mut::<SecPkgInfoW>();

    let status = unsafe { QuerySecurityPackageInfoW(pkg_name.as_ptr(), &mut pkg_info_ptr) };
    assert_eq!(status, 0);

    let cb_max_token = unsafe { pkg_info_ptr.as_ref() }
        .expect("pkg_info is not null")
        .cb_max_token;

    assert_eq!(unsafe { FreeContextBuffer(pkg_info_ptr.cast()) }, 0);

    let mut target_name = "TERMSRV/some@example.com\0".encode_utf16().collect::<Vec<_>>();
    let mut attrs = 0;

    let mut new_sec_context = empty_handle();

    let mut out_buffer = vec![0; usize::try_from(cb_max_token).expect("cb_max_token is a valid usize")];
    let mut out_sec_buffer = SecBuffer {
        cb_buffer: cb_max_token,
        buffer_type: SECBUFFER_TOKEN,
        pv_buffer: out_buffer.as_mut_ptr(),
    };
    let mut out_buffer_desc = SecBufferDesc {
        ul_version: 0,
        c_buffers: 1,
        p_buffers: &mut out_sec_buffer,
    };

    // The credentials handle and the security context handle are both null.
    let status = unsafe {
        InitializeSecurityContextW(
            null_mut(),
            null_mut(),
            target_name.as_mut_ptr(),
            0,
            0,
            SECURITY_NATIVE_DREP,
            null_mut(),
            0,
            &mut new_sec_context,
            &mut out_buffer_desc,
            &mut attrs,
            null_mut(),
        )
    };

    assert_eq!(
        status,
        ErrorKind::InvalidParameter
            .to_u32()
            .expect("ErrorKind is castable to u32")
    );
}
