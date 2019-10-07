use std::marker::PhantomData;

use chrono::NaiveDateTime;

use super::{
    ToAssign, WithContextRequirements, WithCredentialsHandle, WithOutput,
    WithTargetDataRepresentation, WithoutContextRequirements, WithoutCredentialsHandle,
    WithoutOutput, WithoutTargetDataRepresentation,
};
use crate::sspi::{
    self, internal::SspiImpl, ClientRequestFlags, ClientResponseFlags, DataRepresentation,
    SecurityBuffer, SecurityStatus,
};

pub type EmptyInitializeSecurityContext<'a, I, C> = InitializeSecurityContext<
    'a,
    I,
    C,
    WithoutCredentialsHandle,
    WithoutContextRequirements,
    WithoutTargetDataRepresentation,
    WithoutOutput,
>;
pub type FilledInitializeSecurityContext<'a, I, C> = InitializeSecurityContext<
    'a,
    I,
    C,
    WithCredentialsHandle,
    WithContextRequirements,
    WithTargetDataRepresentation,
    WithOutput,
>;

#[derive(Debug, Clone)]
pub struct InitializeSecurityContextResult {
    pub status: SecurityStatus,
    pub flags: ClientResponseFlags,
    pub expiry: Option<NaiveDateTime>,
}

pub struct InitializeSecurityContext<
    'a,
    Inner,
    CredsHandle,
    CredsHandleSet,
    ContextRequirementsSet,
    TargetDataRepresentationSet,
    OutputSet,
> where
    Inner: SspiImpl,
    CredsHandleSet: ToAssign,
    ContextRequirementsSet: ToAssign,
    TargetDataRepresentationSet: ToAssign,
    OutputSet: ToAssign,
{
    inner: Option<&'a mut Inner>,
    phantom_creds_use_set: PhantomData<CredsHandleSet>,
    phantom_context_req_set: PhantomData<ContextRequirementsSet>,
    phantom_data_repr_set: PhantomData<TargetDataRepresentationSet>,
    phantom_output_set: PhantomData<OutputSet>,

    pub credentials_handle: Option<&'a mut CredsHandle>,
    pub context_requirements: ClientRequestFlags,
    pub target_data_representation: DataRepresentation,
    pub output: &'a mut [SecurityBuffer],

    pub target_name: Option<&'a str>,
    pub input: Option<&'a mut [SecurityBuffer]>,
}

impl<
        'a,
        Inner: SspiImpl,
        CredsHandle,
        CredsHandleSet: ToAssign,
        ContextRequirementsSet: ToAssign,
        TargetDataRepresentationSet: ToAssign,
        OutputSet: ToAssign,
    >
    InitializeSecurityContext<
        'a,
        Inner,
        CredsHandle,
        CredsHandleSet,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        OutputSet,
    >
{
    pub(crate) fn new(inner: &'a mut Inner) -> Self {
        Self {
            inner: Some(inner),
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: None,
            context_requirements: ClientRequestFlags::empty(),
            target_data_representation: DataRepresentation::Network,
            output: &mut [],

            target_name: None,
            input: None,
        }
    }

    pub fn with_credentials_handle(
        self,
        credentials_handle: &'a mut CredsHandle,
    ) -> InitializeSecurityContext<
        'a,
        Inner,
        CredsHandle,
        WithCredentialsHandle,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        OutputSet,
    > {
        InitializeSecurityContext {
            inner: self.inner,
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: Some(credentials_handle),
            context_requirements: self.context_requirements,
            target_data_representation: self.target_data_representation,
            output: self.output,

            target_name: self.target_name,
            input: self.input,
        }
    }

    pub fn with_context_requirements(
        self,
        context_requirements: ClientRequestFlags,
    ) -> InitializeSecurityContext<
        'a,
        Inner,
        CredsHandle,
        CredsHandleSet,
        WithContextRequirements,
        TargetDataRepresentationSet,
        OutputSet,
    > {
        InitializeSecurityContext {
            inner: self.inner,
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements,
            target_data_representation: self.target_data_representation,
            output: self.output,

            target_name: self.target_name,
            input: self.input,
        }
    }

    pub fn with_target_data_representation(
        self,
        target_data_representation: DataRepresentation,
    ) -> InitializeSecurityContext<
        'a,
        Inner,
        CredsHandle,
        CredsHandleSet,
        ContextRequirementsSet,
        WithTargetDataRepresentation,
        OutputSet,
    > {
        InitializeSecurityContext {
            inner: self.inner,
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements: self.context_requirements,
            target_data_representation,
            output: self.output,

            target_name: self.target_name,
            input: self.input,
        }
    }

    pub fn with_output(
        self,
        output: &'a mut [SecurityBuffer],
    ) -> InitializeSecurityContext<
        'a,
        Inner,
        CredsHandle,
        CredsHandleSet,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        WithOutput,
    > {
        InitializeSecurityContext {
            inner: self.inner,
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements: self.context_requirements,
            target_data_representation: self.target_data_representation,
            output,

            target_name: self.target_name,
            input: self.input,
        }
    }

    pub fn with_target_name(self, target_name: &'a str) -> Self {
        Self {
            target_name: Some(target_name),
            ..self
        }
    }

    pub fn with_input(self, input: &'a mut [SecurityBuffer]) -> Self {
        Self {
            input: Some(input),
            ..self
        }
    }
}

impl<'a, Inner: SspiImpl<CredentialsHandle = CredsHandle>, CredsHandle>
    FilledInitializeSecurityContext<'a, Inner, CredsHandle>
{
    pub fn execute(mut self) -> sspi::Result<InitializeSecurityContextResult> {
        let inner = self.inner.take().unwrap();

        inner.initialize_security_context_impl(self)
    }

    pub(crate) fn transform<Inner2>(
        self,
        inner: &'a mut Inner2,
    ) -> FilledInitializeSecurityContext<'a, Inner2, CredsHandle>
    where
        Inner2: SspiImpl,
    {
        InitializeSecurityContext {
            inner: Some(inner),
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements: self.context_requirements,
            target_data_representation: self.target_data_representation,
            output: self.output,

            target_name: self.target_name,
            input: self.input,
        }
    }
}
