pub mod builders;
pub mod internal;
#[cfg(windows)]
pub mod winapi;

mod ntlm;

pub use self::{
    builders::{
        AcceptSecurityContextResult, AcquireCredentialsHandleResult,
        InitializeSecurityContextResult,
    },
    ntlm::{AuthIdentity, Ntlm},
};

use std::{error, fmt, io, result, str, string};

use bitflags::bitflags;
use num_derive::{FromPrimitive, ToPrimitive};

use self::{
    builders::{
        AcceptSecurityContext, AcquireCredentialsHandle, EmptyAcceptSecurityContext,
        EmptyAcquireCredentialsHandle, EmptyInitializeSecurityContext, FilledAcceptSecurityContext,
        FilledAcquireCredentialsHandle, FilledInitializeSecurityContext, InitializeSecurityContext,
    },
    internal::SspiImpl,
};

pub type Result<T> = result::Result<T, Error>;
pub type Luid = u64;

const PACKAGE_ID_NONE: u16 = 0xFFFF;

pub fn query_security_package_info(package_type: SecurityPackageType) -> Result<PackageInfo> {
    match package_type {
        SecurityPackageType::Ntlm => Ok(ntlm::PACKAGE_INFO.clone()),
        SecurityPackageType::Other(s) => Err(Error::new(
            ErrorKind::Unknown,
            format!("Queried info about unknown package: {:?}", s),
        )),
    }
}

pub fn enumerate_security_packages() -> Result<Vec<PackageInfo>> {
    Ok(vec![ntlm::PACKAGE_INFO.clone()])
}

pub trait Sspi
where
    Self: Sized + SspiImpl,
{
    fn acquire_credentials_handle(
        &mut self,
    ) -> EmptyAcquireCredentialsHandle<'_, Self, Self::CredentialsHandle, Self::AuthenticationData>
    {
        AcquireCredentialsHandle::new(self)
    }

    fn initialize_security_context(
        &mut self,
    ) -> EmptyInitializeSecurityContext<'_, Self, Self::CredentialsHandle> {
        InitializeSecurityContext::new(self)
    }

    fn accept_security_context(
        &mut self,
    ) -> EmptyAcceptSecurityContext<'_, Self, Self::CredentialsHandle> {
        AcceptSecurityContext::new(self)
    }

    fn complete_auth_token(&mut self, token: &mut [SecurityBuffer]) -> Result<SecurityStatus>;

    fn encrypt_message(
        &mut self,
        flags: EncryptionFlags,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> Result<SecurityStatus>;

    fn decrypt_message(
        &mut self,
        message: &mut [SecurityBuffer],
        sequence_number: u32,
    ) -> Result<DecryptionFlags>;

    fn query_context_sizes(&mut self) -> Result<ContextSizes>;
    fn query_context_names(&mut self) -> Result<ContextNames>;
    fn query_context_package_info(&mut self) -> Result<PackageInfo>;
    fn query_context_cert_trust_status(&mut self) -> Result<CertTrustStatus>;
}

pub trait SspiEx
where
    Self: Sized + SspiImpl,
{
    fn custom_set_auth_identity(&mut self, identity: Self::AuthenticationData);
}

bitflags! {
    pub struct EncryptionFlags: u32 {
        const WRAP_OOB_DATA = 0x4000_0000;
        const WRAP_NO_ENCRYPT = 0x8000_0001;
    }
}

bitflags! {
    pub struct DecryptionFlags: u32 {
        const SIGN_ONLY = 0x8000_0000;
        const WRAP_NO_ENCRYPT = 0x8000_0001;
    }
}

bitflags! {
    pub struct ClientRequestFlags: u32 {
        const DELEGATE = 0x1;
        const MUTUAL_AUTH = 0x2;
        const REPLAY_DETECT = 0x4;
        const SEQUENCE_DETECT = 0x8;
        const CONFIDENTIALITY = 0x10;
        const USE_SESSION_KEY = 0x20;
        const PROMPT_FOR_CREDS = 0x40;
        const USE_SUPPLIED_CREDS = 0x80;
        const ALLOCATE_MEMORY = 0x100;
        const USE_DCE_STYLE = 0x200;
        const DATAGRAM = 0x400;
        const CONNECTION = 0x800;
        const CALL_LEVEL = 0x1000;
        const FRAGMENT_SUPPLIED = 0x2000;
        const EXTENDED_ERROR = 0x4000;
        const STREAM = 0x8000;
        const INTEGRITY = 0x10_000;
        const IDENTIFY = 0x20_000;
        const NULL_SESSION = 0x40_000;
        const MANUAL_CRED_VALIDATION = 0x80_000;
        const RESERVED1 = 0x100_000;
        const FRAGMENT_TO_FIT = 0x200_000;
        const FORWARD_CREDENTIALS = 0x400_000;
        const NO_INTEGRITY = 0x800_000;
        const USE_HTTP_STYLE = 0x100_0000;
        const UNVERIFIED_TARGET_NAME = 0x2000_0000;
        const CONFIDENTIALITY_ONLY = 0x4000_0000;
    }
}

bitflags! {
    pub struct ServerRequestFlags: u32 {
        const DELEGATE = 0x1;
        const MUTUAL_AUTH = 0x2;
        const REPLAY_DETECT = 0x4;
        const SEQUENCE_DETECT = 0x8;
        const CONFIDENTIALITY = 0x10;
        const USE_SESSION_KEY = 0x20;
        const SESSION_TICKET = 0x40;
        const ALLOCATE_MEMORY = 0x100;
        const USE_DCE_STYLE = 0x200;
        const DATAGRAM = 0x400;
        const CONNECTION = 0x800;
        const CALL_LEVEL = 0x1000;
        const FRAGMENT_SUPPLIED = 0x2000;
        const EXTENDED_ERROR = 0x8000;
        const STREAM = 0x10_000;
        const INTEGRITY = 0x20_000;
        const LICENSING = 0x40_000;
        const IDENTIFY = 0x80_000;
        const ALLOW_NULL_SESSION = 0x100_000;
        const ALLOW_NON_USER_LOGONS = 0x200_000;
        const ALLOW_CONTEXT_REPLAY = 0x400_000;
        const FRAGMENT_TO_FIT = 0x80_0000;
        const NO_TOKEN = 0x100_0000;
        const PROXY_BINDINGS = 0x400_0000;
        const ALLOW_MISSING_BINDINGS = 0x1000_0000;
    }
}

bitflags! {
    pub struct ClientResponseFlags: u32 {
        const DELEGATE = 0x1;
        const MUTUAL_AUTH = 0x2;
        const REPLAY_DETECT = 0x4;
        const SEQUENCE_DETECT = 0x8;
        const CONFIDENTIALITY = 0x10;
        const USE_SESSION_KEY = 0x20;
        const USED_COLLECTED_CREDS = 0x40;
        const USED_SUPPLIED_CREDS = 0x80;
        const ALLOCATED_MEMORY = 0x100;
        const USED_DCE_STYLE = 0x200;
        const DATAGRAM = 0x400;
        const CONNECTION = 0x800;
        const INTERMEDIATE_RETURN = 0x1000;
        const CALL_LEVEL = 0x2000;
        const EXTENDED_ERROR = 0x4000;
        const STREAM = 0x8000;
        const INTEGRITY = 0x10_000;
        const IDENTIFY = 0x20_000;
        const NULL_SESSION = 0x40_000;
        const MANUAL_CRED_VALIDATION = 0x80_000;
        const RESERVED1 = 0x10_0000;
        const FRAGMENT_ONLY = 0x200_000;
        const FORWARD_CREDENTIALS = 0x400_000;
        const USED_HTTP_STYLE = 0x100_0000;
        const NO_ADDITIONAL_TOKEN = 0x200_0000;
        const REAUTHENTICATION = 0x800_0000;
        const CONFIDENTIALITY_ONLY = 0x4000_0000;
    }
}

bitflags! {
    pub struct ServerResponseFlags: u32 {
        const DELEGATE = 0x1;
        const MUTUAL_AUTH = 0x2;
        const REPLAY_DETECT = 0x4;
        const SEQUENCE_DETECT = 0x8;
        const CONFIDENTIALITY = 0x10;
        const USE_SESSION_KEY = 0x20;
        const SESSION_TICKET = 0x40;
        const ALLOCATED_MEMORY = 0x100;
        const USED_DCE_STYLE = 0x200;
        const DATAGRAM = 0x400;
        const CONNECTION = 0x800;
        const CALL_LEVEL = 0x2000;
        const THIRD_LEG_FAILED = 0x4000;
        const EXTENDED_ERROR = 0x8000;
        const STREAM = 0x10_000;
        const INTEGRITY = 0x20_000;
        const LICENSING = 0x40_000;
        const IDENTIFY = 0x80_000;
        const NULL_SESSION = 0x100_000;
        const ALLOW_NON_USER_LOGONS = 0x200_000;
        const ALLOW_CONTEXT_REPLAY = 0x400_000;
        const FRAGMENT_ONLY = 0x800_000;
        const NO_TOKEN = 0x100_0000;
        const NO_ADDITIONAL_TOKEN = 0x200_0000;
    }
}

#[derive(Debug, Copy, Clone, PartialEq, FromPrimitive, ToPrimitive)]
pub enum DataRepresentation {
    Network = 0,
    Native = 0x10,
}

#[derive(Debug, Clone)]
pub struct SecurityBuffer {
    pub buffer: Vec<u8>,
    pub buffer_type: SecurityBufferType,
}

impl SecurityBuffer {
    pub fn new(buffer: Vec<u8>, buffer_type: SecurityBufferType) -> Self {
        Self {
            buffer,
            buffer_type,
        }
    }

    pub fn find_buffer(
        buffers: &[SecurityBuffer],
        buffer_type: SecurityBufferType,
    ) -> Result<&SecurityBuffer> {
        buffers
            .iter()
            .find(|b| b.buffer_type == buffer_type)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    format!("No buffer was provided with type {:?}", buffer_type),
                )
            })
    }

    pub fn find_buffer_mut(
        buffers: &mut [SecurityBuffer],
        buffer_type: SecurityBufferType,
    ) -> Result<&mut SecurityBuffer> {
        buffers
            .iter_mut()
            .find(|b| b.buffer_type == buffer_type)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidToken,
                    format!("No buffer was provided with type {:?}", buffer_type),
                )
            })
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, FromPrimitive, ToPrimitive)]
pub enum SecurityBufferType {
    Empty = 0,
    Data = 1,
    Token = 2,
    TransportToPackageParameters = 3,
    Missing = 4,
    Extra = 5,
    StreamTrailer = 6,
    StreamHeader = 7,
    NegotiationInfo = 8,
    Padding = 9,
    Stream = 10,
    ObjectIdsList = 11,
    ObjectIdsListSignature = 12,
    Target = 13,
    ChannelBindings = 14,
    ChangePasswordResponse = 15,
    TargetHost = 16,
    Alert = 17,
    ApplicationProtocol = 18,
    AttributeMark = 0xF000_0000,
    ReadOnly = 0x8000_0000,
    ReadOnlyWithChecksum = 0x1000_0000,
}

#[derive(Debug, Copy, Clone, PartialEq, FromPrimitive, ToPrimitive)]
pub enum CredentialUse {
    Inbound = 1,
    Outbound = 2,
    Both = 3,
    Default = 4,
}

#[derive(Debug, Clone)]
pub enum SecurityPackageType {
    Ntlm,
    Other(String),
}

impl string::ToString for SecurityPackageType {
    fn to_string(&self) -> String {
        match self {
            SecurityPackageType::Ntlm => ntlm::PKG_NAME.to_string(),
            SecurityPackageType::Other(name) => name.clone(),
        }
    }
}

impl str::FromStr for SecurityPackageType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            ntlm::PKG_NAME => Ok(SecurityPackageType::Ntlm),
            s => Ok(SecurityPackageType::Other(s.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub capabilities: PackageCapabilities,
    pub rpc_id: u16,
    pub max_token_len: u32,
    pub name: SecurityPackageType,
    pub comment: String,
}

bitflags! {
    pub struct PackageCapabilities: u32 {
        const INTEGRITY = 0x1;
        const PRIVACY = 0x2;
        const TOKEN_ONLY = 0x4;
        const DATAGRAM = 0x8;
        const CONNECTION = 0x10;
        const MULTI_REQUIRED = 0x20;
        const CLIENT_ONLY = 0x40;
        const EXTENDED_ERROR = 0x80;
        const IMPERSONATION = 0x100;
        const ACCEPT_WIN32_NAME = 0x200;
        const STREAM = 0x400;
        const NEGOTIABLE = 0x800;
        const GSS_COMPATIBLE = 0x1000;
        const LOGON = 0x2000;
        const ASCII_BUFFERS = 0x4000;
        const FRAGMENT = 0x8000;
        const MUTUAL_AUTH = 0x1_0000;
        const DELEGATION = 0x2_0000;
        const READONLY_WITH_CHECKSUM = 0x4_0000;
        const RESTRICTED_TOKENS = 0x8_0000;
        const NEGO_EXTENDER = 0x10_0000;
        const NEGOTIABLE2 = 0x20_0000;
        const APP_CONTAINER_PASSTHROUGH = 0x40_0000;
        const APP_CONTAINER_CHECKS = 0x80_0000;
    }
}

#[derive(Debug, Clone)]
pub struct ContextSizes {
    pub max_token: u32,
    pub max_signature: u32,
    pub block: u32,
    pub security_trailer: u32,
}

#[derive(Debug, Clone)]
pub struct CertTrustStatus {
    pub error_status: CertTrustErrorStatus,
    pub info_status: CertTrustInfoStatus,
}

bitflags! {
    pub struct CertTrustErrorStatus: u32 {
        const NO_ERROR = 0x0;
        const IS_NOT_TIME_VALID = 0x1;
        const IS_NOT_TIME_NESTED = 0x2;
        const IS_REVOKED = 0x4;
        const IS_NOT_SIGNATURE_VALID = 0x8;
        const IS_NOT_VALID_FOR_USAGE = 0x10;
        const IS_UNTRUSTED_ROOT = 0x20;
        const REVOCATION_STATUS_UNKNOWN = 0x40;
        const IS_CYCLIC = 0x80;
        const INVALID_EXTENSION = 0x100;
        const INVALID_POLICY_CONSTRAINTS = 0x200;
        const INVALID_BASIC_CONSTRAINTS = 0x400;
        const INVALID_NAME_CONSTRAINTS = 0x800;
        const HAS_NOT_SUPPORTED_NAME_CONSTRAINT = 0x1000;
        const HAS_NOT_DEFINED_NAME_CONSTRAINT = 0x2000;
        const HAS_NOT_PERMITTED_NAME_CONSTRAINT = 0x4000;
        const HAS_EXCLUDED_NAME_CONSTRAINT = 0x8000;
        const IS_PARTIAL_CHAIN = 0x10_000;
        const CTL_IS_NOT_TIME_VALID = 0x20_000;
        const CTL_IS_NOT_SIGNATURE_VALID = 0x40_000;
        const CTL_IS_NOT_VALID_FOR_USAGE = 0x80_000;
        const IS_OFFLINE_REVOCATION = 0x100_0000;
        const NO_ISSUANCE_CHAIN_POLICY = 0x200_0000;
    }
}

bitflags! {
    pub struct CertTrustInfoStatus: u32 {
        const HAS_EXACT_MATCH_ISSUER = 0x1;
        const HAS_KEY_MATCH_ISSUER = 0x2;
        const HAS_NAME_MATCH_ISSUER = 0x4;
        const IS_SELF_SIGNED = 0x8;
        const AUTO_UPDATE_CA_REVOCATION = 0x10;
        const AUTO_UPDATE_END_REVOCATION = 0x20;
        const NO_OCSP_FAILOVER_TO_CRL = 0x40;
        const IS_KEY_ROLLOVER = 0x80;
        const HAS_PREFERRED_ISSUER = 0x100;
        const HAS_ISSUANCE_CHAIN_POLICY = 0x200;
        const HAS_VALID_NAME_CONSTRAINTS = 0x400;
        const IS_PEER_TRUSTED = 0x800;
        const HAS_CRL_VALIDITY_EXTENDED = 0x1_000;
        const IS_FROM_EXCLUSIVE_TRUST_STORE = 0x2_000;
        const IS_CA_TRUSTED = 0x4_000;
        const HAS_AUTO_UPDATE_WEAK_SIGNATURE = 0x8_000;
        const SSL_HANDSHAKE_OCSP = 0x40_000;
        const SSL_TIME_VALID_OCSP = 0x80_000;
        const SSL_RECONNECT_OCSP = 0x100_000;
        const IS_COMPLEX_CHAIN = 0x10_000;
        const HAS_ALLOW_WEAK_SIGNATURE = 0x20_000;
        const SSL_TIME_VALID = 0x100_0000;
        const NO_TIME_CHECK = 0x200_0000;
    }
}

#[derive(Debug, Clone)]
pub struct ContextNames {
    pub username: String,
    pub domain: Option<String>,
}

/// The kind of an SSPI related error. Enables to specify the error based on its type.
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, FromPrimitive, ToPrimitive)]
pub enum ErrorKind {
    Unknown = 0,
    InsufficientMemory = 0x8009_0300,
    InvalidHandle = 0x8009_0301,
    UnsupportedFunction = 0x8009_0302,
    TargetUnknown = 0x8009_0303,
    /// May correspond to any internal error (I/O error, server error, etc.).
    InternalError = 0x8009_0304,
    SecurityPackageNotFound = 0x8009_0305,
    NotOwned = 0x8009_0306,
    CannotInstall = 0x8009_0307,
    /// Used in cases when supplied data is missing or invalid.
    InvalidToken = 0x8009_0308,
    CannotPack = 0x8009_0309,
    OperationNotSupported = 0x8009_030A,
    NoImpersonation = 0x8009_030B,
    LogonDenied = 0x8009_030C,
    UnknownCredentials = 0x8009_030D,
    NoCredentials = 0x8009_030E,
    /// Used in contexts of supplying invalid credentials.
    MessageAltered = 0x8009_030F,
    /// Used when a required NTLM state does not correspond to the current.
    OutOfSequence = 0x8009_0310,
    NoAuthenticatingAuthority = 0x8009_0311,
    BadPackageId = 0x8009_0316,
    ContextExpired = 0x8009_0317,
    IncompleteMessage = 0x8009_0318,
    IncompleteCredentials = 0x8009_0320,
    BufferTooSmall = 0x8009_0321,
    WrongPrincipalName = 0x8009_0322,
    TimeSkew = 0x8009_0324,
    UntrustedRoot = 0x8009_0325,
    IllegalMessage = 0x8009_0326,
    CertificateUnknown = 0x8009_0327,
    CertificateExpired = 0x8009_0328,
    EncryptFailure = 0x8009_0329,
    DecryptFailure = 0x8009_0330,
    AlgorithmMismatch = 0x8009_0331,
    SecurityQosFailed = 0x8009_0332,
    UnfinishedContextDeleted = 0x8009_0333,
    NoTgtReply = 0x8009_0334,
    NoIpAddress = 0x8009_0335,
    WrongCredentialHandle = 0x8009_0336,
    CryptoSystemInvalid = 0x8009_0337,
    MaxReferralsExceeded = 0x8009_0338,
    MustBeKdc = 0x8009_0339,
    StrongCryptoNotSupported = 0x8009_033A,
    TooManyPrincipals = 0x8009_033B,
    NoPaData = 0x8009_033C,
    PkInitNameMismatch = 0x8009_033D,
    SmartCardLogonRequired = 0x8009_033E,
    ShutdownInProgress = 0x8009_033F,
    KdcInvalidRequest = 0x8009_0340,
    KdcUnknownEType = 0x8009_0341,
    KdcUnknownEType2 = 0x8009_0342,
    UnsupportedPreAuth = 0x8009_0343,
    DelegationRequired = 0x8009_0345,
    BadBindings = 0x8009_0346,
    MultipleAccounts = 0x8009_0347,
    NoKerdKey = 0x8009_0348,
    CertWrongUsage = 0x8009_0349,
    DowngradeDetected = 0x8009_0350,
    SmartCardCertificateRevoked = 0x8009_0351,
    IssuingCAUntrusted = 0x8009_0352,
    RevocationOffline = 0x8009_0353,
    PkInitClientFailure = 0x8009_0354,
    SmartCardCertExpired = 0x8009_0355,
    NoS4uProtSupport = 0x8009_0356,
    CrossRealmDelegationFailure = 0x8009_0357,
    RevocationOfflineKdc = 0x8009_0358,
    IssuingCaUntrustedKdc = 0x8009_0359,
    KdcCertExpired = 0x8009_035A,
    KdcCertRevoked = 0x8009_035B,
    InvalidParameter = 0x8009_035D,
    DelegationPolicy = 0x8009_035E,
    PolicyNtlmOnly = 0x8009_035F,
    NoContext = 0x8009_0361,
    Pku2uCertFailure = 0x8009_0362,
    MutualAuthFailed = 0x8009_0363,
    OnlyHttpsAllowed = 0x8009_0365,
    ApplicationProtocolMismatch = 0x8009_0367,
}

/// Holds the [`SspiErrorType`](enum.SspiErrorType.html) and the description of the error.
#[derive(Debug, Clone)]
pub struct Error {
    pub error_type: ErrorKind,
    pub description: String,
}

#[derive(Debug, Copy, Clone, PartialEq, FromPrimitive, ToPrimitive)]
pub enum SecurityStatus {
    Ok = 0,
    ContinueNeeded = 0x0009_0312,
    CompleteNeeded = 0x0009_0313,
    CompleteAndContinue = 0x0009_0314,
    LocalLogon = 0x0009_0315,
    ContextExpired = 0x0009_0317,
    IncompleteCredentials = 0x0009_0320,
    Renegotiate = 0x0009_0321,
    NoLsaContext = 0x0009_0323,
}

impl Error {
    /// Allows to fill a new error easily, supplying it with a coherent description.
    pub fn new(error_type: ErrorKind, error: String) -> Self {
        Self {
            error_type,
            description: error,
        }
    }
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::new(ErrorKind::InternalError, format!("IO error: {:?}", err))
    }
}

impl From<rand::Error> for Error {
    fn from(err: rand::Error) -> Self {
        Self::new(ErrorKind::InternalError, format!("Rand error: {:?}", err))
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::new(ErrorKind::InternalError, format!("UTF-8 error: {:?}", err))
    }
}

impl From<string::FromUtf16Error> for Error {
    fn from(err: string::FromUtf16Error) -> Self {
        Self::new(ErrorKind::InternalError, format!("UTF-16 error: {:?}", err))
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        io::Error::new(
            io::ErrorKind::Other,
            format!("{:?}: {}", err.error_type, err.description),
        )
    }
}
