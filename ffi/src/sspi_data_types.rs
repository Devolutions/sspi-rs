use libc::{c_char, c_ushort, c_void};
use sspi::CertTrustStatus as SspiCertTrustStatus;

pub type SecChar = c_char;

pub type LpStr = *const SecChar;

pub type SecWChar = c_ushort;

pub type LpcWStr = *const SecWChar;

pub type SecurityStatus = u32;

#[repr(C)]
pub struct SecurityInteger {
    pub low_part: u32,
    pub high_part: i32,
}

pub type PTimeStamp = *mut SecurityInteger;

#[repr(C)]
pub struct SecurityString {
    pub length: c_ushort,
    pub maximum_length: c_ushort,
    pub buffer: *mut c_ushort,
}

pub type PSecurityString = *mut SecurityString;

#[repr(C)]
pub struct SecPkgContextSizes {
    pub cb_max_token: u32,
    pub cb_max_signature: u32,
    pub cb_block_size: u32,
    pub cb_security_trailer: u32,
}

/// [SecPkgContext_StreamSizes](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_streamsizes)
///
/// ```not_rust
/// typedef struct _SecPkgContext_StreamSizes {
///   unsigned long cbHeader;
///   unsigned long cbTrailer;
///   unsigned long cbMaximumMessage;
///   unsigned long cBuffers;
///   unsigned long cbBlockSize;
/// } SecPkgContext_StreamSizes, *PSecPkgContext_StreamSizes;
/// ```
#[repr(C)]
pub struct SecPkgContextStreamSizes {
    pub cb_header: u32,
    pub cb_trailer: u32,
    pub cb_maximum_message: u32,
    pub c_buffers: u32,
    pub cb_block_size: u32,
}

pub type SecGetKeyFn = extern "system" fn(*mut c_void, *mut c_void, u32, *mut *mut c_void, *mut i32);

/// [_SecPkgContext_Flags](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_flags)
///
/// ```not_rust
/// typedef struct _SecPkgContext_Flags {
///   unsigned long Flags;
/// } SecPkgContext_Flags, *PSecPkgContext_Flags;
/// ```
#[repr(C)]
pub struct SecPkgContextFlags {
    pub flags: u32,
}

/// [ALG_ID](https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id)
/// typedef unsigned int ALG_ID;
pub type AlgId = u32;

/// [_SecPkgContext_ConnectionInfo](https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_connectioninfo)
///
/// ```not_rust
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

/// [CERT_TRUST_STATUS](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status)
///
/// ```not_rust
/// typedef struct _CERT_TRUST_STATUS {
///   DWORD dwErrorStatus;
///   DWORD dwInfoStatus;
/// } CERT_TRUST_STATUS, *PCERT_TRUST_STATUS;
/// ```
#[repr(C)]
pub struct CertTrustStatus {
    pub dw_error_status: u32,
    pub dw_info_status: u32,
}

impl From<SspiCertTrustStatus> for CertTrustStatus {
    fn from(cert_trust_status: SspiCertTrustStatus) -> Self {
        Self {
            dw_error_status: cert_trust_status.error_status.bits(),
            dw_info_status: cert_trust_status.info_status.bits(),
        }
    }
}
