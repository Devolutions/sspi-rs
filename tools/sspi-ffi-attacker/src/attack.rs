use std::ffi::CStr;
use std::ptr::null;

use libc::c_void;

use crate::types::{
    InitSecurityInterfaceA, InitSecurityInterfaceW, PSecPkgInfoA, PSecPkgInfoW, PSecurityFunctionTableA,
    PSecurityFunctionTableW, SecBuffer, SecBufferDesc, SecHandle, SecWinntAuthIdentityA, SecWinntAuthIdentityW,
    SspiEncodeStringsAsAuthIdentityFn, SspiFreeAuthIdentityFn, SECURITY_INTEGER, SEC_CHAR, SEC_WCHAR,
};
use crate::utils::{c_w_str_to_string, get_library_fn, load_library};

pub unsafe fn init_w_table(path_to_library: &str) -> PSecurityFunctionTableW {
    let sspi_handle = load_library(path_to_library);

    let init_security_interface_w_fn = get_library_fn(sspi_handle, "InitSecurityInterfaceW\0");
    let init_security_interface_w_fn: InitSecurityInterfaceW =
        unsafe { std::mem::transmute(init_security_interface_w_fn) };

    let security_table = init_security_interface_w_fn();

    if security_table.is_null() {
        panic!("Can not load security table W");
    }

    security_table
}

pub unsafe fn init_a_table(path_to_library: &str) -> PSecurityFunctionTableA {
    let sspi_handle = load_library(path_to_library);

    let init_security_interface_a_fn = get_library_fn(sspi_handle, "InitSecurityInterfaceA\0");
    let init_security_interface_a_fn: InitSecurityInterfaceA =
        unsafe { std::mem::transmute(init_security_interface_a_fn) };

    let security_table = init_security_interface_a_fn();

    if security_table.is_null() {
        panic!("Can not load security table W");
    }

    security_table
}

pub unsafe fn attac_auth_identity(path_to_dll: &str) {
    let sspi_handle = load_library(path_to_dll);

    if sspi_handle.is_null() {
        panic!("Can not load library: {}", path_to_dll);
    }

    let encode_auth_identity_fn = get_library_fn(sspi_handle, "SspiEncodeStringsAsAuthIdentity\0");
    let encode_auth_identity_fn: SspiEncodeStringsAsAuthIdentityFn =
        unsafe { std::mem::transmute(encode_auth_identity_fn) };

    let username = "username\0".encode_utf16().collect::<Vec<_>>();
    let domain = "domain\0".encode_utf16().collect::<Vec<_>>();
    let credentials = "credentials\0".encode_utf16().collect::<Vec<_>>();
    let mut identity: *mut c_void = null::<c_void>() as *mut _;

    let status = encode_auth_identity_fn(username.as_ptr(), domain.as_ptr(), credentials.as_ptr(), &mut identity);

    if status != 0 {
        panic!("SspiEncodeStringsAsAuthIdentityFn failed: {}", status);
    }

    let encode_auth_identity_fn = get_library_fn(sspi_handle, "SspiFreeAuthIdentity\0");
    let free_auth_identity_fn: SspiFreeAuthIdentityFn = unsafe { std::mem::transmute(encode_auth_identity_fn) };

    let status = free_auth_identity_fn(identity);

    if status != 0 {
        panic!("SspiFreeAuthIdentity failed: {}", status);
    }

    println!("{:?}", identity);
}

pub unsafe fn attack_w(sec_w_table: PSecurityFunctionTableW) {
    let pkg_name = "NTLM\0".encode_utf16().collect::<Vec<_>>();
    let mut pkg_info: PSecPkgInfoW = null::<PSecPkgInfoW>() as *mut _;

    let status = ((*sec_w_table).QuerySecurityPackageInfoW)(pkg_name.as_ptr(), &mut pkg_info);

    if status != 0 {
        panic!("QuerySecurityPackageInfoW failed: {}", status);
    }

    println!("{:?}", *pkg_info);
    println!("{:?}", c_w_str_to_string((*pkg_info).Name));
    println!("{:?}", c_w_str_to_string((*pkg_info).Comment));

    let mut pc_packages = 0;
    let mut packages: PSecPkgInfoW = null::<PSecPkgInfoW>() as *mut _;
    let status = ((*sec_w_table).EnumerateSecurityPackagesW)(&mut pc_packages, &mut packages);

    if status != 0 {
        panic!("EnumerateSecurityPackagesW failed: {}", status);
    }

    for i in 0..pc_packages as usize {
        let pkg_info = packages.add(i);
        println!("{:?}", *pkg_info);
        println!("{:?}", c_w_str_to_string((*pkg_info).Name));
        println!("{:?}", c_w_str_to_string((*pkg_info).Comment));
    }

    let status = ((*sec_w_table).FreeContextBuffer)(packages as *mut _);

    if status != 0 {
        panic!("FreeContextBuffer failed: {}", status);
    }

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

    let mut cred_handle = SecHandle { dwLower: 0, dwUpper: 0 };

    let status = ((*sec_w_table).AcquireCredentialsHandleW)(
        null::<SEC_WCHAR>() as *mut _,
        pkg_name.as_ptr() as *mut _,
        2, /* SECPKG_CRED_OUTBOUND */
        null::<c_void>(),
        &credentials as *const _ as *const c_void,
        null::<c_void>() as *mut _,
        null::<c_void>(),
        &mut cred_handle,
        null::<SECURITY_INTEGER>() as *mut _,
    );

    if status != 0 {
        panic!("AcquireCredentialsHandleW failed: {}", status);
    }

    println!("cred handle: {:?}", cred_handle);

    let mut sec_context = SecHandle { dwLower: 0, dwUpper: 0 };
    let mut new_sec_context = SecHandle { dwLower: 0, dwUpper: 0 };
    let target_name = "TERMSRV/some@example.com\0".encode_utf16().collect::<Vec<_>>();
    let mut attrs = 0;

    let mut out_buffer = vec![0; (*pkg_info).cbMaxToken as usize];
    let mut out_sec_buffer = SecBuffer {
        cb_buffer: (*pkg_info).cbMaxToken as u32,
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
        p_buffers: null::<SecBuffer>() as *mut _,
    };

    let status = ((*sec_w_table).InitializeSecurityContextW)(
        &mut cred_handle,
        &mut sec_context,
        target_name.as_ptr() as *mut _,
        0,
        0,
        0x10, /* SECURITY_NATIVE_DREP */
        &mut in_buffer_desk,
        0,
        &mut new_sec_context,
        &mut out_buffer_desk,
        &mut attrs,
        null::<SECURITY_INTEGER>() as *mut _,
    );

    if status != 0x0009_0312
    /* CONTINUE_NEEDED */
    {
        panic!("InitializeSecurityContextW failed: {}", status);
    }

    let status = ((*sec_w_table).FreeContextBuffer)(pkg_info as *mut _);

    if status != 0 {
        panic!("FreeContextBuffer failed: {}", status);
    }

    let status = ((*sec_w_table).FreeCredentialsHandle)(&mut cred_handle);

    if status != 0 {
        panic!("FreeCredentialsHandle failed: {}", status);
    }

    let status = ((*sec_w_table).DeleteSecurityContext)(&mut new_sec_context);

    if status != 0 {
        panic!("DeleteSecurityContext failed: {}", status);
    }
}

pub unsafe fn attack_a(sec_a_table: PSecurityFunctionTableA) {
    let pkg_name = "NTLM\0";
    let mut pkg_info: PSecPkgInfoA = null::<PSecPkgInfoA>() as *mut _;

    let status = ((*sec_a_table).QuerySecurityPackageInfoA)(pkg_name.as_ptr() as *const _, &mut pkg_info);

    if status != 0 {
        panic!("QuerySecurityPackageInfoA failed: {}", status);
    }

    println!("{:?}", *pkg_info);
    println!("{:?}", CStr::from_ptr((*pkg_info).Name));
    println!("{:?}", CStr::from_ptr((*pkg_info).Comment));

    let mut pc_packages = 0;
    let mut packages: PSecPkgInfoA = null::<PSecPkgInfoA>() as *mut _;
    let status = ((*sec_a_table).EnumerateSecurityPackagesA)(&mut pc_packages, &mut packages);

    if status != 0 {
        panic!("EnumerateSecurityPackagesA failed: {}", status);
    }

    for i in 0..pc_packages as usize {
        let pkg_info = packages.add(i);
        println!("{:?}", *pkg_info);
        println!("{:?}", CStr::from_ptr((*pkg_info).Name));
        println!("{:?}", CStr::from_ptr((*pkg_info).Comment));
    }

    let status = ((*sec_a_table).FreeContextBuffer)(packages as *mut _);

    if status != 0 {
        panic!("FreeContextBuffer failed: {}", status);
    }

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
        flags: 0,
    };

    let mut cred_handle = SecHandle { dwLower: 0, dwUpper: 0 };

    let status = ((*sec_a_table).AcquireCredentialsHandleA)(
        null::<SEC_CHAR>() as *mut _,
        pkg_name.as_ptr() as *mut _,
        2, /* SECPKG_CRED_OUTBOUND */
        null::<c_void>(),
        &credentials as *const _ as *const c_void,
        null::<c_void>() as *mut _,
        null::<c_void>(),
        &mut cred_handle,
        null::<SECURITY_INTEGER>() as *mut _,
    );

    if status != 0 {
        panic!("AcquireCredentialsHandleA failed: {}", status);
    }

    println!("cred handle: {:?}", cred_handle);

    let mut sec_context = SecHandle { dwLower: 0, dwUpper: 0 };
    let mut new_sec_context = SecHandle { dwLower: 0, dwUpper: 0 };
    let target_name = "TERMSRV/some@example.com\0";
    let mut attrs = 0;

    let mut out_buffer = vec![0; (*pkg_info).cbMaxToken as usize];
    let mut out_sec_buffer = SecBuffer {
        cb_buffer: (*pkg_info).cbMaxToken as u32,
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
        p_buffers: null::<SecBuffer>() as *mut _,
    };

    let status = ((*sec_a_table).InitializeSecurityContextA)(
        &mut cred_handle,
        &mut sec_context,
        target_name.as_ptr() as *mut _,
        0,
        0,
        0x10, /* SECURITY_NATIVE_DREP */
        &mut in_buffer_desk,
        0,
        &mut new_sec_context,
        &mut out_buffer_desk,
        &mut attrs,
        null::<SECURITY_INTEGER>() as *mut _,
    );

    if status != 0x0009_0312
    /* CONTINUE_NEEDED */
    {
        panic!("InitializeSecurityContextA failed: {}", status);
    }

    let status = ((*sec_a_table).FreeContextBuffer)(pkg_info as *mut _);

    if status != 0 {
        panic!("FreeContextBuffer failed: {}", status);
    }

    let status = ((*sec_a_table).FreeCredentialsHandle)(&mut cred_handle);

    if status != 0 {
        panic!("FreeCredentialsHandle failed: {}", status);
    }

    let status = ((*sec_a_table).DeleteSecurityContext)(&mut new_sec_context);

    if status != 0 {
        panic!("DeleteSecurityContext failed: {}", status);
    }
}
