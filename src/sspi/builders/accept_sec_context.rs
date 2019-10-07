use std::marker::PhantomData;

use chrono::NaiveDateTime;

use super::{
    ToAssign, WithContextRequirements, WithCredentialsHandle, WithOutput,
    WithTargetDataRepresentation, WithoutContextRequirements, WithoutCredentialsHandle,
    WithoutOutput, WithoutTargetDataRepresentation,
};
use crate::sspi::{
    self, internal::SspiImpl, DataRepresentation, SecurityBuffer, SecurityStatus,
    ServerRequestFlags, ServerResponseFlags,
};

pub type EmptyAcceptSecurityContext<'a, I, C> = AcceptSecurityContext<
    'a,
    I,
    C,
    WithoutCredentialsHandle,
    WithoutContextRequirements,
    WithoutTargetDataRepresentation,
    WithoutOutput,
>;
pub type FilledAcceptSecurityContext<'a, I, C> = AcceptSecurityContext<
    'a,
    I,
    C,
    WithCredentialsHandle,
    WithContextRequirements,
    WithTargetDataRepresentation,
    WithOutput,
>;

#[derive(Debug, Clone)]
pub struct AcceptSecurityContextResult {
    pub status: SecurityStatus,
    pub flags: ServerResponseFlags,
    pub expiry: Option<NaiveDateTime>,
}

#[derive(Debug)]
pub struct AcceptSecurityContext<
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
    pub context_requirements: ServerRequestFlags,
    pub target_data_representation: DataRepresentation,
    pub output: &'a mut [SecurityBuffer],

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
    AcceptSecurityContext<
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
            context_requirements: ServerRequestFlags::empty(),
            target_data_representation: DataRepresentation::Network,

            output: &mut [],
            input: None,
        }
    }

    pub fn with_credentials_handle(
        self,
        credentials_handle: &'a mut CredsHandle,
    ) -> AcceptSecurityContext<
        'a,
        Inner,
        CredsHandle,
        WithCredentialsHandle,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        OutputSet,
    > {
        AcceptSecurityContext {
            inner: self.inner,
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: Some(credentials_handle),
            context_requirements: self.context_requirements,
            target_data_representation: self.target_data_representation,
            output: self.output,

            input: self.input,
        }
    }

    pub fn with_context_requirements(
        self,
        context_requirements: ServerRequestFlags,
    ) -> AcceptSecurityContext<
        'a,
        Inner,
        CredsHandle,
        CredsHandleSet,
        WithContextRequirements,
        TargetDataRepresentationSet,
        OutputSet,
    > {
        AcceptSecurityContext {
            inner: self.inner,
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements,
            target_data_representation: self.target_data_representation,
            output: self.output,

            input: self.input,
        }
    }

    pub fn with_target_data_representation(
        self,
        target_data_representation: DataRepresentation,
    ) -> AcceptSecurityContext<
        'a,
        Inner,
        CredsHandle,
        CredsHandleSet,
        ContextRequirementsSet,
        WithTargetDataRepresentation,
        OutputSet,
    > {
        AcceptSecurityContext {
            inner: self.inner,
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements: self.context_requirements,
            target_data_representation,
            output: self.output,

            input: self.input,
        }
    }

    pub fn with_output(
        self,
        output: &'a mut [SecurityBuffer],
    ) -> AcceptSecurityContext<
        'a,
        Inner,
        CredsHandle,
        CredsHandleSet,
        ContextRequirementsSet,
        TargetDataRepresentationSet,
        WithOutput,
    > {
        AcceptSecurityContext {
            inner: self.inner,
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements: self.context_requirements,
            target_data_representation: self.target_data_representation,
            output,

            input: self.input,
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
    FilledAcceptSecurityContext<'a, Inner, CredsHandle>
{
    pub fn execute(mut self) -> sspi::Result<AcceptSecurityContextResult> {
        let inner = self.inner.take().unwrap();
        inner.accept_security_context_impl(self)
    }

    pub(crate) fn transform<Inner2>(
        self,
        inner: &'a mut Inner2,
    ) -> FilledAcceptSecurityContext<'a, Inner2, CredsHandle>
    where
        Inner2: SspiImpl,
    {
        AcceptSecurityContext {
            inner: Some(inner),
            phantom_creds_use_set: PhantomData,
            phantom_context_req_set: PhantomData,
            phantom_data_repr_set: PhantomData,
            phantom_output_set: PhantomData,

            credentials_handle: self.credentials_handle,
            context_requirements: self.context_requirements,
            target_data_representation: self.target_data_representation,

            output: self.output,
            input: self.input,
        }
    }
}
