use std::fmt::Debug;
use std::marker::PhantomData;

use chrono::NaiveDateTime;

use super::{Assigned, NotAssigned, ToAssign};
use crate::{CredentialUse, Luid, SspiPackage};

pub type EmptyAcquireCredentialsHandle<'a, C, A> = AcquireCredentialsHandle<'a, C, A, WithoutCredentialUse>;
pub type FilledAcquireCredentialsHandle<'a, C, A> = AcquireCredentialsHandle<'a, C, A, WithCredentialUse>;

/// Contains data returned by calling the `execute` method of
/// the `AcquireCredentialsHandleBuilder` structure. The builder is returned by calling
/// the `acquire_credentials_handle` method.
#[derive(Debug, Clone)]
pub struct AcquireCredentialsHandleResult<C> {
    pub credentials_handle: C,
    pub expiry: Option<NaiveDateTime>,
}

/// A builder to execute one of the SSPI functions. Returned by the `acquire_credentials_handle` method.
///
/// # Requirements for execution
///
/// These methods are required to be called before calling the `execute` method
/// * [`with_credential_use`](struct.AcquireCredentialsHandle.html#method.with_credential_use)
pub struct AcquireCredentialsHandle<'a, CredsHandle, AuthData, CredentialUseSet>
where
    CredentialUseSet: ToAssign,
{
    pub(crate) inner: Option<SspiPackage<'a, CredsHandle, AuthData>>,
    pub(crate) phantom_cred_handle: PhantomData<CredsHandle>,
    pub(crate) phantom_cred_use_set: PhantomData<CredentialUseSet>,

    pub credential_use: CredentialUse,

    pub principal_name: Option<&'a str>,
    pub logon_id: Option<Luid>,
    pub auth_data: Option<&'a AuthData>,
}

impl<'a, CredsHandle, AuthData, CredentialUseSet> Debug
    for AcquireCredentialsHandle<'a, CredsHandle, AuthData, CredentialUseSet>
where
    CredentialUseSet: ToAssign,
    AuthData: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcquireCredentialsHandle")
            .field("phantom_cred_handle", &self.phantom_cred_handle)
            .field("phantom_cred_use_set", &self.phantom_cred_use_set)
            .field("credential_use", &self.credential_use)
            .field("principal_name", &self.principal_name)
            .field("logon_id", &self.logon_id)
            .field("auth_data", &self.auth_data)
            .finish()
    }
}

impl<'a, CredsHandle, AuthData, CredentialUseSet> AcquireCredentialsHandle<'a, CredsHandle, AuthData, CredentialUseSet>
where
    CredentialUseSet: ToAssign,
{
    pub(crate) fn new(inner: SspiPackage<'a, CredsHandle, AuthData>) -> Self {
        Self {
            inner: Some(inner),
            phantom_cred_handle: PhantomData,
            phantom_cred_use_set: PhantomData,

            principal_name: None,
            credential_use: CredentialUse::Inbound,
            logon_id: None,
            auth_data: None,
        }
    }

    /// Specifies a flag that indicates how these credentials will be used.
    pub fn with_credential_use(
        self,
        credential_use: CredentialUse,
    ) -> AcquireCredentialsHandle<'a, CredsHandle, AuthData, WithCredentialUse> {
        AcquireCredentialsHandle {
            inner: self.inner,
            phantom_cred_handle: PhantomData,
            phantom_cred_use_set: PhantomData,

            principal_name: self.principal_name,
            credential_use,
            logon_id: self.logon_id,
            auth_data: self.auth_data,
        }
    }

    /// Specifies a string that specifies the name of the principal whose credentials the handle will reference.
    pub fn with_principal_name(self, principal_name: &'a str) -> Self {
        Self {
            principal_name: Some(principal_name),
            ..self
        }
    }

    /// Specifies a LUID that identifies the user. This parameter is provided for file-system processes such as network
    /// redirectors.
    pub fn with_logon_id(self, logon_id: Luid) -> Self {
        Self {
            logon_id: Some(logon_id),
            ..self
        }
    }

    /// Specifies a reference to the structure that specifies authentication data for both Schannel and Negotiate packages.
    pub fn with_auth_data(self, auth_data: &'a AuthData) -> Self {
        Self {
            auth_data: Some(auth_data),
            ..self
        }
    }
}

impl<'a, CredsHandle, AuthData> FilledAcquireCredentialsHandle<'a, CredsHandle, AuthData> {
    pub(crate) fn full_transform<NewCredsHandle, NewAuthData>(
        self,
        inner: SspiPackage<'a, NewCredsHandle, NewAuthData>,
        auth_data: Option<&'a NewAuthData>,
    ) -> FilledAcquireCredentialsHandle<'a, NewCredsHandle, NewAuthData> {
        AcquireCredentialsHandle {
            inner: Some(inner),
            phantom_cred_handle: PhantomData,
            phantom_cred_use_set: PhantomData,

            principal_name: self.principal_name,
            credential_use: self.credential_use,
            logon_id: self.logon_id,
            auth_data,
        }
    }
}

impl<'a, CredsHandle, AuthData> FilledAcquireCredentialsHandle<'a, CredsHandle, AuthData> {
    /// Executes the SSPI function that the builder represents.
    pub fn execute(mut self) -> crate::Result<AcquireCredentialsHandleResult<CredsHandle>> {
        let inner = self.inner.take().unwrap();
        inner.acquire_credentials_handle_impl(self)
    }

    pub(crate) fn transform(
        self,
        inner: SspiPackage<'a, CredsHandle, AuthData>,
    ) -> FilledAcquireCredentialsHandle<'a, CredsHandle, AuthData> {
        AcquireCredentialsHandle {
            inner: Some(inner),
            phantom_cred_handle: PhantomData,
            phantom_cred_use_set: PhantomData,

            principal_name: self.principal_name,
            credential_use: self.credential_use,
            logon_id: self.logon_id,
            auth_data: self.auth_data,
        }
    }
}

/// Simulates the presence of the `credential_use` value of the
/// `AcquireCredentialsHandle` builder.
#[derive(Debug)]
pub struct WithCredentialUse;
impl ToAssign for WithCredentialUse {}
impl Assigned for WithCredentialUse {}

/// Simulates the absence of the `credential_use` value of the
/// `AcquireCredentialsHandle` builder.
#[derive(Debug)]
pub struct WithoutCredentialUse;
impl ToAssign for WithoutCredentialUse {}
impl NotAssigned for WithoutCredentialUse {}
