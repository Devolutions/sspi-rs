use std::marker::PhantomData;

use chrono::NaiveDateTime;

use super::{Assigned, NotAssigned, ToAssign};
use crate::sspi::{self, internal::SspiImpl, CredentialUse, Luid};

pub type EmptyAcquireCredentialsHandle<'a, I, C, A> =
    AcquireCredentialsHandle<'a, I, C, A, WithoutCredentialUse>;
pub type FilledAcquireCredentialsHandle<'a, I, C, A> =
    AcquireCredentialsHandle<'a, I, C, A, WithCredentialUse>;

#[derive(Debug, Clone)]
pub struct AcquireCredentialsHandleResult<C> {
    pub credentials_handle: C,
    pub expiry: Option<NaiveDateTime>,
}

#[derive(Debug)]
pub struct AcquireCredentialsHandle<'a, Inner, CredsHandle, AuthData, CredentialUseSet>
where
    Inner: SspiImpl,
    CredentialUseSet: ToAssign,
{
    pub(crate) inner: Option<&'a mut Inner>,
    pub(crate) phantom_cred_handle: PhantomData<CredsHandle>,
    pub(crate) phantom_cred_use_set: PhantomData<CredentialUseSet>,

    pub credential_use: CredentialUse,

    pub principal_name: Option<&'a str>,
    pub logon_id: Option<Luid>,
    pub auth_data: Option<&'a AuthData>,
}

impl<'a, Inner, CredsHandle, AuthData, CredentialUseSet>
    AcquireCredentialsHandle<'a, Inner, CredsHandle, AuthData, CredentialUseSet>
where
    Inner: SspiImpl<CredentialsHandle = CredsHandle, AuthenticationData = AuthData>,
    CredentialUseSet: ToAssign,
{
    pub(crate) fn new(inner: &'a mut Inner) -> Self {
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

    pub fn with_credential_use(
        self,
        credential_use: CredentialUse,
    ) -> AcquireCredentialsHandle<'a, Inner, CredsHandle, AuthData, WithCredentialUse> {
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

    pub fn with_principal_name(self, principal_name: &'a str) -> Self {
        Self {
            principal_name: Some(principal_name),
            ..self
        }
    }

    pub fn with_logon_id(self, logon_id: Luid) -> Self {
        Self {
            logon_id: Some(logon_id),
            ..self
        }
    }

    pub fn with_auth_data(self, auth_data: &'a AuthData) -> Self {
        Self {
            auth_data: Some(auth_data),
            ..self
        }
    }
}

impl<'a, Inner, CredsHandle, AuthData>
    FilledAcquireCredentialsHandle<'a, Inner, CredsHandle, AuthData>
where
    Inner: SspiImpl<CredentialsHandle = CredsHandle, AuthenticationData = AuthData>,
{
    pub fn execute(mut self) -> sspi::Result<AcquireCredentialsHandleResult<CredsHandle>> {
        let inner = self.inner.take().unwrap();
        inner.acquire_credentials_handle_impl(self)
    }

    pub(crate) fn transform<Inner2>(
        self,
        inner: &'a mut Inner2,
    ) -> FilledAcquireCredentialsHandle<'a, Inner2, CredsHandle, AuthData>
    where
        Inner2: SspiImpl,
    {
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

#[derive(Debug)]
pub struct WithCredentialUse;
impl ToAssign for WithCredentialUse {}
impl Assigned for WithCredentialUse {}

#[derive(Debug)]
pub struct WithoutCredentialUse;
impl ToAssign for WithoutCredentialUse {}
impl NotAssigned for WithoutCredentialUse {}
