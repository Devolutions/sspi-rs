//! C-compatible SSPI declarations shared by FFI implementations.

#![allow(non_snake_case)]

mod functions;

use core::ffi::{c_char, c_void};

pub use functions::*;

pub type SecChar = c_char;
pub type LpStr = *const SecChar;
pub type SecWChar = u16;
pub type LpcWStr = *const SecWChar;
pub type SecurityStatus = u32;

/// [SECURITY_INTEGER](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-security_integer)
///
/// ```c
/// typedef struct _SECURITY_INTEGER {
///   unsigned long LowPart;
///   long          HighPart;
/// } SECURITY_INTEGER, *PSECURITY_INTEGER;
/// ```
#[repr(C)]
pub struct SecurityInteger {
    pub low_part: u32,
    pub high_part: i32,
}
pub type PTimeStamp = *mut SecurityInteger;

/// [SECURITY_STRING](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-security_string)
///
/// The SECURITY_STRING structure is used as the string interface for kernel operations and is a clone
/// of the [UNICODE_STRING](https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string)
/// structure. This is used for 32-bit mode.
///
/// ```c
/// typedef struct _SECURITY_STRING {
///   unsigned short Length;
///   unsigned short MaximumLength;
///   unsigned short *Buffer;
/// } SECURITY_STRING, *PSECURITY_STRING;
/// ```
#[repr(C)]
pub struct SecurityString {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}
pub type PSecurityString = *mut SecurityString;

/// [SecBuffer](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer)
///
/// ```c
/// typedef struct _SecBuffer {
///   unsigned long cbBuffer;
///   unsigned long BufferType;
///#if ...
///   char          *pvBuffer;
///#else
///   void SEC_FAR  *pvBuffer;
///#endif
/// } SecBuffer, *PSecBuffer;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecBuffer {
    pub cb_buffer: u32,
    pub buffer_type: u32,
    pub pv_buffer: *mut c_char,
}
pub type PSecBuffer = *mut SecBuffer;

/// [SecBufferDesc](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbufferdesc)
///
/// ```c
/// typedef struct _SecBufferDesc {
///   unsigned long ulVersion;
///   unsigned long cBuffers;
///   PSecBuffer    pBuffers;
/// } SecBufferDesc, *PSecBufferDesc;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecBufferDesc {
    pub ul_version: u32,
    pub c_buffers: u32,
    pub p_buffers: PSecBuffer,
}
pub type PSecBufferDesc = *mut SecBufferDesc;

/// [SecPkgContext_Sizes](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_sizes)
///
/// ```c
/// typedef struct _SecPkgContext_Sizes {
///   unsigned long cbMaxToken;
///   unsigned long cbMaxSignature;
///   unsigned long cbBlockSize;
///   unsigned long cbSecurityTrailer;
/// } SecPkgContext_Sizes, *PSecPkgContext_Sizes;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecPkgContextSizes {
    pub cb_max_token: u32,
    pub cb_max_signature: u32,
    pub cb_block_size: u32,
    pub cb_security_trailer: u32,
}

/// [SecPkgContext_StreamSizes](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_streamsizes)
///
/// ```c
/// typedef struct _SecPkgContext_StreamSizes {
///   unsigned long cbHeader;
///   unsigned long cbTrailer;
///   unsigned long cbMaximumMessage;
///   unsigned long cBuffers;
///   unsigned long cbBlockSize;
/// } SecPkgContext_StreamSizes, *PSecPkgContext_StreamSizes;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecPkgContextStreamSizes {
    pub cb_header: u32,
    pub cb_trailer: u32,
    pub cb_maximum_message: u32,
    pub c_buffers: u32,
    pub cb_block_size: u32,
}
pub type SecGetKeyFn = extern "system" fn(*mut c_void, *mut c_void, u32, *mut *mut c_void, *mut i32);

/// [SecPkgContext_Flags](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_flags)
///
/// ```c
/// typedef struct _SecPkgContext_Flags {
///   unsigned long Flags;
/// } SecPkgContext_Flags, *PSecPkgContext_Flags;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecPkgContextFlags {
    pub flags: u32,
}

/// [ALG_ID](https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id)
/// typedef unsigned int ALG_ID;
pub type AlgId = u32;

/// [SecPkgContext_ConnectionInfo](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_connectioninfo)
///
/// ```c
/// typedef struct _SecPkgContext_ConnectionInfo {
///   DWORD  dwProtocol;
///   ALG_ID aiCipher;
///   DWORD  dwCipherStrength;
///   ALG_ID aiHash;
///   DWORD  dwHashStrength;
///   ALG_ID aiExch;
///   DWORD  dwExchStrength;
/// } SecPkgContext_ConnectionInfo, *PSecPkgContext_ConnectionInfo;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecPkgContextConnectionInfo {
    pub dw_protocol: u32,
    pub ai_cipher: AlgId,
    pub dw_cipher_strength: u32,
    pub ai_hash: AlgId,
    pub dw_hash_strength: u32,
    pub ai_exch: AlgId,
    pub dw_exch_strength: u32,
}

/// [SecPkgContext_SessionKey](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_sessionkey)
///
/// ```c
/// typedef struct _SecPkgContext_SessionKey {
///   unsigned long SessionKeyLength;
///   unsigned char *SessionKey;
/// } SecPkgContext_SessionKey, *PSecPkgContext_SessionKey;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecPkgContextSessionKey {
    pub session_key_len: u32,
    pub session_key: *mut u8,
}

/// [CERT_TRUST_STATUS](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status)
///
/// ```c
/// typedef struct _CERT_TRUST_STATUS {
///   DWORD dwErrorStatus;
///   DWORD dwInfoStatus;
/// } CERT_TRUST_STATUS, *PCERT_TRUST_STATUS;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct CertTrustStatus {
    pub dw_error_status: u32,
    pub dw_info_status: u32,
}

/// [SecPkgContext_NamesA](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_namesa)
///
/// ```c
/// typedef struct _SecPkgContext_NamesA {
///   SEC_CHAR *sUserName;
/// } SecPkgContext_NamesA, *PSecPkgContext_NamesA;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecPkgContextNamesA {
    pub user_name: *mut SecChar,
}

/// [SecPkgContext_NamesW](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_namesw)
///
/// ```c
/// typedef struct _SecPkgContext_NamesW {
///   SEC_WCHAR *sUserName;
/// } SecPkgContextNamesW, *PSecPkgContextNamesW;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecPkgContextNamesW {
    pub user_name: *mut SecWChar,
}

pub const SECPKG_NEGOTIATION_COMPLETE: u32 = 0;
pub const SECPKG_NEGOTIATION_OPTIMISTIC: u32 = 1;
pub const SECPKG_NEGOTIATION_IN_PROGRESS: u32 = 2;
pub const SECPKG_ATTR_SIZES: u32 = 0;
pub const SECPKG_ATTR_NAMES: u32 = 1;
pub const SECPKG_ATTR_NEGOTIATION_INFO: u32 = 12;
pub const SECPKG_ATTR_STREAM_SIZES: u32 = 4;
pub const SECPKG_ATTR_REMOTE_CERT_CONTEXT: u32 = 0x53;
pub const SECPKG_ATTR_NEGOTIATION_PACKAGE: u32 = 0x80000081;
pub const SECPKG_ATTR_PACKAGE_INFO: u32 = 10;
pub const SECPKG_ATTR_SERVER_AUTH_FLAGS: u32 = 0x80000083;
pub const SECPKG_ATTR_CERT_TRUST_STATUS: u32 = 0x80000084;
pub const SECPKG_ATTR_CONNECTION_INFO: u32 = 0x5a;
pub const SECPKG_ATTR_SESSION_KEY: u32 = 9;
pub const SEC_WINNT_AUTH_IDENTITY_ANSI: u32 = 0x1;
pub const SEC_WINNT_AUTH_IDENTITY_UNICODE: u32 = 0x2;
pub const SEC_WINNT_AUTH_IDENTITY_VERSION: u32 = 0x200;
pub const SEC_WINNT_AUTH_IDENTITY_VERSION_2: u32 = 0x201;

/// [SecHandle](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sechandle)
///
/// ```c
/// typedef struct _SecHandle {
///   ULONG_PTR dwLower;
///   ULONG_PTR dwUpper;
/// } SecHandle, *PSecHandle;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecHandle {
    pub dw_lower: u64,
    pub dw_upper: u64,
}

pub type PCredHandle = *mut SecHandle;
pub type PCtxtHandle = *mut SecHandle;

/// [SecPkgInfoW](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkginfow)
///
/// ```c
/// typedef struct _SecPkgInfoW {
///   unsigned long  fCapabilities;
///   unsigned short wVersion;
///   unsigned short wRPCID;
///   unsigned long  cbMaxToken;
///   SEC_WCHAR      *Name;
///   SEC_WCHAR      *Comment;
/// } SecPkgInfoW, *PSecPkgInfoW;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecPkgInfoW {
    pub f_capabilities: u32,
    pub w_version: u16,
    pub w_rpc_id: u16,
    pub cb_max_token: u32,
    pub name: *mut SecWChar,
    pub comment: *mut SecWChar,
}

pub type PSecPkgInfoW = *mut SecPkgInfoW;

/// [SecPkgInfoA](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkginfoa)
///
/// ```c
/// typedef struct _SecPkgInfoA {
///   unsigned long  fCapabilities;
///   unsigned short wVersion;
///   unsigned short wRPCID;
///   unsigned long  cbMaxToken;
///   SEC_CHAR       *Name;
///   SEC_CHAR       *Comment;
/// } SecPkgInfoA, *PSecPkgInfoA;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecPkgInfoA {
    pub f_capabilities: u32,
    pub w_version: u16,
    pub w_rpc_id: u16,
    pub cb_max_token: u32,
    pub name: *mut SecChar,
    pub comment: *mut SecChar,
}

pub type PSecPkgInfoA = *mut SecPkgInfoA;

/// [SecPkgContext_NegotiationInfoW](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_negotiationinfow)
///
/// ```c
/// typedef struct _SecPkgContext_NegotiationInfoW {
///   PSecPkgInfoW  PackageInfo;
///   unsigned long NegotiationState;
/// } SecPkgContext_NegotiationInfoW, *PSecPkgContext_NegotiationInfoW;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecNegoInfoW {
    pub package_info: *mut SecPkgInfoW,
    pub nego_state: u32,
}

/// [SecPkgContext_NegotiationInfoA](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_negotiationinfoa)
///
/// ```c
/// typedef struct _SecPkgContext_NegotiationInfoA {
///   PSecPkgInfoA  PackageInfo;
///   unsigned long NegotiationState;
/// } SecPkgContext_NegotiationInfoA, *PSecPkgContext_NegotiationInfoA;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecNegoInfoA {
    pub package_info: *mut SecPkgInfoA,
    pub nego_state: u32,
}

/// [SecPkgCredentials_KdcProxySettingsW](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcredentials_kdcproxysettingsw)
///
/// ```c
/// typedef struct _SecPkgCredentials_KdcProxySettingsW {
///   ULONG  Version;
///   ULONG  Flags;
///   USHORT ProxyServerOffset;
///   USHORT ProxyServerLength;
///   USHORT ClientTlsCredOffset;
///   USHORT ClientTlsCredLength;
/// } SecPkgCredentials_KdcProxySettingsW, *PSecPkgCredentials_KdcProxySettingsW;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecPkgCredentialsKdcProxySettingsW {
    pub version: u32,
    pub flags: u32,
    pub proxy_server_offset: u16,
    pub proxy_server_length: u16,
    pub client_tls_cred_offset: u16,
    pub client_tls_cred_length: u16,
}

#[derive(Debug)]
#[repr(C)]
pub struct SecPkgCredentialsKdcUrlA {
    pub kdc_url: *mut SecChar,
}

#[derive(Debug)]
#[repr(C)]
pub struct SecPkgCredentialsKdcUrlW {
    pub kdc_url: *mut SecWChar,
}

/// [SEC_WINNT_AUTH_IDENTITY_W](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_winnt_auth_identity_w)
///
/// ```c
/// typedef struct _SEC_WINNT_AUTH_IDENTITY_W {
///   unsigned short *User;
///   unsigned long UserLength;
///   unsigned short *Domain;
///   unsigned long DomainLength;
///   unsigned short *Password;
///   unsigned long PasswordLength;
///   unsigned long Flags;
/// } SEC_WINNT_AUTH_IDENTITY_W, *PSEC_WINNT_AUTH_IDENTITY_W;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecWinntAuthIdentityW {
    pub user: *const u16,
    pub user_length: u32,
    pub domain: *const u16,
    pub domain_length: u32,
    pub password: *const u16,
    pub password_length: u32,
    pub flags: u32,
}

/// [SEC_WINNT_AUTH_IDENTITY_A](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_winnt_auth_identity_a)
///
/// ```c
/// typedef struct _SEC_WINNT_AUTH_IDENTITY_A {
///   unsigned char *User;
///   unsigned long UserLength;
///   unsigned char *Domain;
///   unsigned long DomainLength;
///   unsigned char *Password;
///   unsigned long PasswordLength;
///   unsigned long Flags;
/// } SEC_WINNT_AUTH_IDENTITY_A, *PSEC_WINNT_AUTH_IDENTITY_A;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecWinntAuthIdentityA {
    pub user: *const c_char,
    pub user_length: u32,
    pub domain: *const c_char,
    pub domain_length: u32,
    pub password: *const c_char,
    pub password_length: u32,
    pub flags: u32,
}

/// [SEC_WINNT_AUTH_IDENTITY_EXW](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_winnt_auth_identity_exw)
///
/// ```c
/// typedef struct _SEC_WINNT_AUTH_IDENTITY_EXW {
///   unsigned long  Version;
///   unsigned long  Length;
///   unsigned short *User;
///   unsigned long  UserLength;
///   unsigned short *Domain;
///   unsigned long  DomainLength;
///   unsigned short *Password;
///   unsigned long  PasswordLength;
///   unsigned long  Flags;
///   unsigned short *PackageList;
///   unsigned long  PackageListLength;
/// } SEC_WINNT_AUTH_IDENTITY_EXW, *PSEC_WINNT_AUTH_IDENTITY_EXW;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecWinntAuthIdentityExW {
    pub version: u32,
    pub length: u32,
    pub user: *const u16,
    pub user_length: u32,
    pub domain: *const u16,
    pub domain_length: u32,
    pub password: *const u16,
    pub password_length: u32,
    pub flags: u32,
    pub package_list: *const u16,
    pub package_list_length: u32,
}

/// [SEC_WINNT_AUTH_IDENTITY_EXA](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_winnt_auth_identity_exa)
///
/// ```c
/// typedef struct _SEC_WINNT_AUTH_IDENTITY_EXA {
///   unsigned long Version;
///   unsigned long Length;
///   unsigned char *User;
///   unsigned long UserLength;
///   unsigned char *Domain;
///   unsigned long DomainLength;
///   unsigned char *Password;
///   unsigned long PasswordLength;
///   unsigned long Flags;
///   unsigned char *PackageList;
///   unsigned long PackageListLength;
/// } SEC_WINNT_AUTH_IDENTITY_EXA, *PSEC_WINNT_AUTH_IDENTITY_EXA;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecWinntAuthIdentityExA {
    pub version: u32,
    pub length: u32,
    pub user: *const c_char,
    pub user_length: u32,
    pub domain: *const c_char,
    pub domain_length: u32,
    pub password: *const c_char,
    pub password_length: u32,
    pub flags: u32,
    pub package_list: *const c_char,
    pub package_list_length: u32,
}

/// [SEC_WINNT_AUTH_IDENTITY_EX2](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_winnt_auth_identity_ex2)
///
/// ```c
/// typedef struct _SEC_WINNT_AUTH_IDENTITY_EX2 {
///   unsigned long  Version;
///   unsigned short cbHeaderLength;
///   unsigned long  cbStructureLength;
///   unsigned long  UserOffset;
///   unsigned short UserLength;
///   unsigned long  DomainOffset;
///   unsigned short DomainLength;
///   unsigned long  PackedCredentialsOffset;
///   unsigned short PackedCredentialsLength;
///   unsigned long  Flags;
///   unsigned long  PackageListOffset;
///   unsigned short PackageListLength;
/// } SEC_WINNT_AUTH_IDENTITY_EX2, *PSEC_WINNT_AUTH_IDENTITY_EX2;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct SecWinntAuthIdentityEx2 {
    pub version: u32,
    pub cb_header_length: u16,
    pub cb_structure_length: u32,
    pub user_offset: u32,
    pub user_length: u16,
    pub domain_offset: u32,
    pub domain_length: u16,
    pub packed_credentials_offset: u32,
    pub packed_credentials_length: u16,
    pub flags: u32,
    pub package_list_offset: u32,
    pub package_list_length: u16,
}

/// [CREDSPP_SUBMIT_TYPE](https://learn.microsoft.com/en-us/windows/win32/api/credssp/ne-credssp-credspp_submit_type)
///
/// ```c
/// typedef enum _CREDSSP_SUBMIT_TYPE {
///   CredsspPasswordCreds = 2,
///   CredsspSchannelCreds = 4,
///   CredsspCertificateCreds = 13,
///   CredsspSubmitBufferBoth = 50,
///   CredsspSubmitBufferBothOld = 51,
///   CredsspCredEx = 100
/// } CREDSPP_SUBMIT_TYPE;
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub enum CredSspSubmitType {
    CredsspPasswordCreds = 2,
    CredsspSchannelCreds = 4,
    CredsspCertificateCreds = 13,
    CredsspSubmitBufferBoth = 50,
    CredsspSubmitBufferBothOld = 51,
    CredsspCredEx = 100,
}

/// [CREDSSP_CRED](https://learn.microsoft.com/en-us/windows/win32/api/credssp/ns-credssp-credssp_cred)
///
/// ```c
/// typedef struct _CREDSSP_CRED {
///   CREDSPP_SUBMIT_TYPE Type;
///   PVOID               pSchannelCred;
///   PVOID               pSpnegoCred;
/// } CREDSSP_CRED, *PCREDSSP_CRED;
/// ```
#[derive(Debug)]
#[repr(C)]
pub struct CredSspCred {
    pub submit_type: CredSspSubmitType,
    pub p_schannel_cred: *const c_void,
    pub p_spnego_cred: *const c_void,
}

pub type HCRYPTPROV = usize;
pub type HCRYPTKEY = usize;
