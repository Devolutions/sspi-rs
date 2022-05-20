use std::marker::PhantomData;

use chrono::NaiveDateTime;

use super::{
    ToAssign, WithContextRequirements, WithCredentialsHandle, WithOutput, WithTargetDataRepresentation,
    WithoutContextRequirements, WithoutCredentialsHandle, WithoutOutput, WithoutTargetDataRepresentation,
};
use crate::sspi::internal::SspiImpl;
use crate::sspi::{self, ClientRequestFlags, ClientResponseFlags, DataRepresentation, SecurityBuffer, SecurityStatus};

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

/// Contains data returned by calling the `execute` method of
/// the `InitializeSecurityContextBuilder` structure. The builder is returned by calling
/// the `initialize_security_context` method.
#[derive(Debug, Clone)]
pub struct InitializeSecurityContextResult {
    pub status: SecurityStatus,
    pub flags: ClientResponseFlags,
    pub expiry: Option<NaiveDateTime>,
}

/// A builder to execute one of the SSPI functions. Returned by the `initialize_security_context` method.
///
/// # Requirements for execution
///
/// These methods are required to be called before calling the `execute` method
/// * [`with_credentials_handle`](struct.InitializeSecurityContext.html#method.with_credentials_handle)
/// * [`with_context_requirements`](struct.InitializeSecurityContext.html#method.with_context_requirements)
/// * [`with_target_data_representation`](struct.InitializeSecurityContext.html#method.with_target_data_representation)
/// * [`with_output`](struct.InitializeSecurityContext.html#method.with_output)
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

    /// Specifies a handle to the credentials returned by `acquire_credentials_handle`. This handle is used
    /// to build the security context. The builder requires at least `CredentialUse::Outbound` credentials.
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

    /// Specifies bit flags that indicate requests for the context. Not all packages can support all requirements.
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

    /// Specifies the data representation, such as byte ordering, on the target.
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

    /// Specifies a mutable reference to a buffer with `SecurityBuffer` that receives the output data.
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

    /// Specifies a mutable reference to a buffer with `SecurityBuffer` structures. Don't call this method on during
    /// the first execution of the builder. On the second execution, this parameter is a reference to the partially
    /// formed context returned during the first call.
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
    /// Executes the SSPI function that the builder represents.
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
